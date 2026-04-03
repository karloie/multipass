// Package proxy implements the authenticated Multipass reverse proxy.
package proxy

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/karloie/multipass/internal/audit"
	"github.com/karloie/multipass/internal/auth"
	"github.com/karloie/multipass/internal/authz"
	"github.com/karloie/multipass/internal/config"
	queryrewrite "github.com/karloie/multipass/internal/query"
)

// contextKey avoids context key collisions.
type contextKey string

const (
	userInfoKey    contextKey = "userInfo"
	permissionsKey contextKey = "permissions"
	namespaceKey   contextKey = "namespace"
	jwtTokenKey    contextKey = "jwtToken"
)

const (
	headerAuthorization = "Authorization"
	headerContentType   = "Content-Type"
	headerBearerPrefix  = "Bearer "

	queryParamNamespace = "namespace"

	namespaceRoutingModeRequest = "request"
	namespaceRoutingModeFixed   = "fixed"
	namespaceRoutingSourceQuery = "query"
	namespaceRoutingSourceBody  = "body"
	namespaceRoutingSourceBoth  = "both"

	defaultNamespace    = "default"
	auditWriteTimeout   = 2 * time.Second
	backendProbeTimeout = 2 * time.Second

	errMsgMissingAuth      = "Missing Authorization header"
	errMsgInvalidAuth      = "Invalid Authorization header format (expected 'Bearer <token>')"
	errMsgEmptyToken       = "Empty token"
	errMsgInvalidToken     = "Invalid token"
	errMsgBackendNotFound  = "Backend not found"
	errMsgAuthzFailed      = "Authorization check failed"
	errMsgAccessDenied     = "Access denied: no permission for namespace '%s'"
	errMsgNamespaceMissing = "Missing namespace routing parameter '%s'"
)

// Proxy handles requests and routes to backends.
type Proxy struct {
	config       *config.Config
	backends     map[string]*httputil.ReverseProxy
	router       *chi.Mux
	httpClient   *http.Client
	authProvider auth.Provider
	browserAuth  browserAuthenticator
	authz        authz.Evaluator
	auditStore   audit.Store
}

type readinessResult struct {
	Backend    string `json:"backend"`
	Endpoint   string `json:"endpoint"`
	StatusCode int    `json:"status_code,omitempty"`
	Error      string `json:"error,omitempty"`
}

type resolvedBackend struct {
	name        string
	config      config.BackendConfig
	stripPrefix bool
}

type hostMatchedBackend struct {
	resolved resolvedBackend
	prefix   string
}

// New creates a proxy handler.
func New(cfg *config.Config, authProvider auth.Provider, browserAuth browserAuthenticator, evaluator authz.Evaluator, auditStore audit.Store) (*Proxy, error) {
	p := &Proxy{
		config:       cfg,
		backends:     make(map[string]*httputil.ReverseProxy),
		router:       chi.NewRouter(),
		httpClient:   &http.Client{},
		authProvider: authProvider,
		browserAuth:  browserAuth,
		authz:        evaluator,
		auditStore:   auditStore,
	}

	for name, backend := range cfg.Backends {
		target, err := url.Parse(backend.Endpoint)
		if err != nil {
			return nil, fmt.Errorf("invalid backend URL %s: %w", name, err)
		}

		proxy := httputil.NewSingleHostReverseProxy(target)

		originalDirector := proxy.Director
		backendConfig := backend
		backendName := name
		proxy.Director = func(req *http.Request) {
			req.URL.Opaque = ""
			req.URL.RawPath = ""
			originalDirector(req)
			req.Host = req.URL.Host
			p.injectBackendHeaders(req, backendConfig, backendName)
		}

		p.backends[name] = proxy
		slog.Info("configured backend",
			slog.String("backend", name),
			slog.String("endpoint", backend.Endpoint),
			slog.String("type", backend.Type),
		)
	}

	p.setupRoutes()

	return p, nil
}

// setupRoutes configures the HTTP router.
func (p *Proxy) setupRoutes() {
	p.router.Use(middleware.Recoverer)
	p.router.Use(middleware.RequestID)
	p.router.Use(p.requestLogger)

	p.router.Use(p.authMiddleware)

	p.router.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})
	p.router.Get("/ready", p.handleReadiness)

	for name := range p.backends {
		backendName := name
		rootPattern := fmt.Sprintf("/%s", backendName)
		pattern := fmt.Sprintf("/%s/*", backendName)
		p.router.HandleFunc(rootPattern, func(w http.ResponseWriter, r *http.Request) {
			p.handleBackendRequest(w, r, resolvedBackend{name: backendName, config: p.config.Backends[backendName], stripPrefix: true})
		})
		p.router.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			p.handleBackendRequest(w, r, resolvedBackend{name: backendName, config: p.config.Backends[backendName], stripPrefix: true})
		})
	}

	p.router.Get("/", func(w http.ResponseWriter, r *http.Request) {
		if resolved, ok := p.resolveBackendRequest(r); ok {
			p.handleBackendRequest(w, r, resolved)
			return
		}

		w.Header().Set(headerContentType, "text/plain")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "Multipass Gateway\n")
		fmt.Fprintf(w, "\nAvailable backends:\n")
		for name, backend := range p.config.Backends {
			fmt.Fprintf(w, "  /%s -> %s\n", name, backend.Endpoint)
		}
	})

	p.router.NotFound(func(w http.ResponseWriter, r *http.Request) {
		if resolved, ok := p.resolveBackendRequest(r); ok {
			p.handleBackendRequest(w, r, resolved)
			return
		}

		http.NotFound(w, r)
	})
}

// authMiddleware validates authentication.
func (p *Proxy) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isProbePath(r.URL.Path) || strings.HasPrefix(r.URL.Path, "/auth/") {
			next.ServeHTTP(w, r)
			return
		}

		resolved, ok := p.resolveBackendRequest(r)
		if !ok {
			next.ServeHTTP(w, r)
			return
		}

		if resolved.config.Type == backendTypeWeb {
			p.authenticateBrowserRequest(w, r, next, resolved.name)
			return
		}

		p.authenticateAPIRequest(w, r, next)
	})
}

// handleBackendRequest proxies a request to a backend.
func (p *Proxy) handleBackendRequest(w http.ResponseWriter, r *http.Request, resolved resolvedBackend) {
	start := time.Now()

	proxy, ok := p.backends[resolved.name]
	if !ok {
		http.Error(w, errMsgBackendNotFound, http.StatusNotFound)
		return
	}

	userInfo, _ := r.Context().Value(userInfoKey).(*auth.UserInfo)

	namespace, err := resolveRequestNamespace(p.config.Authz, resolved.config, userInfo, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if p.config.Authz.Enabled && p.authz != nil && userInfo != nil {
		perms, err := p.authz.EvaluatePermissions(r.Context(), userInfo)
		if err != nil {
			slog.ErrorContext(r.Context(), "authorization evaluation failed",
				slog.String("user", userInfo.ID),
				slog.Any("error", err),
			)
			p.logAudit(r.Context(), userInfo, resolved.name, namespace, start, http.StatusInternalServerError, err.Error(), perms)
			http.Error(w, errMsgAuthzFailed, http.StatusInternalServerError)
			return
		}

		if !hasNamespaceAccess(perms.AllowedNamespaces, namespace) {
			slog.WarnContext(r.Context(), "access denied",
				slog.String("user", userInfo.ID),
				slog.String("namespace", namespace),
			)
			p.logAudit(r.Context(), userInfo, resolved.name, namespace, start, http.StatusForbidden, "access denied to namespace", perms)
			http.Error(w, fmt.Sprintf(errMsgAccessDenied, namespace), http.StatusForbidden)
			return
		}
		r = r.WithContext(context.WithValue(r.Context(), permissionsKey, perms))
	}

	r = r.WithContext(context.WithValue(r.Context(), namespaceKey, namespace))
	r, err = stripNamespaceRoutingQueryParam(r, resolved.config)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	r, err = rewriteBackendQuery(r, resolved, namespace)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if resolved.stripPrefix {
		prefix := "/" + resolved.name
		r.URL.Path = strings.TrimPrefix(r.URL.Path, prefix)
		if r.URL.Path == "" {
			r.URL.Path = "/"
		}
	}

	recorder := &responseRecorder{
		ResponseWriter: w,
		statusCode:     http.StatusOK,
	}

	proxy.ServeHTTP(recorder, r)

	if p.auditStore != nil && userInfo != nil {
		perms, _ := r.Context().Value(permissionsKey).(*authz.Permission)
		p.logAudit(r.Context(), userInfo, resolved.name, namespace, start, recorder.statusCode, "", perms)
	}
}
func rewriteBackendQuery(r *http.Request, resolved resolvedBackend, namespace string) (*http.Request, error) {
	if r == nil || !queryrewrite.HasRules(resolved.config.QueryRewrite) {
		return r, nil
	}

	route := r.URL.Path
	if resolved.stripPrefix {
		route = strings.TrimPrefix(route, "/"+resolved.name)
		if route == "" {
			route = "/"
		}
	}

	return queryrewrite.RewriteRequest(r, resolved.config.QueryRewrite, queryrewrite.Context{
		Backend:   resolved.name,
		Namespace: namespace,
		Host:      r.Host,
		Route:     route,
		Method:    r.Method,
	})
}

func resolveRequestNamespace(authzConfig config.AuthzConfig, backendConfig config.BackendConfig, userInfo *auth.UserInfo, r *http.Request) (string, error) {
	if backendConfig.NamespaceRouting != nil && backendConfig.NamespaceRouting.Mode != "" {
		switch backendConfig.NamespaceRouting.Mode {
		case namespaceRoutingModeFixed:
			return strings.TrimSpace(backendConfig.Namespace), nil
		case namespaceRoutingModeRequest:
			if r == nil {
				return "", fmt.Errorf(errMsgNamespaceMissing, backendConfig.NamespaceRouting.Parameter)
			}
			namespace, err := requestRoutingParameterValue(r, backendConfig.NamespaceRouting)
			if err != nil {
				return "", err
			}
			if namespace == "" {
				return "", fmt.Errorf(errMsgNamespaceMissing, backendConfig.NamespaceRouting.Parameter)
			}
			if segmentNamespace, ok := resolveDirectSegmentNamespace(strings.TrimSpace(backendConfig.Namespace), namespace); ok {
				return segmentNamespace, nil
			}
			if strings.TrimSpace(backendConfig.Namespace) != "" && authzConfig.NamespaceClassifier.HasRules() {
				return authzConfig.NamespaceClassifier.Classify(backendConfig.Namespace, namespace), nil
			}
			if authzConfig.NamespaceClassifier.HasRules() && authzConfig.ClusterResolver.HasMappings() {
				cluster := authzConfig.ClusterResolver.ResolveCluster(userInfo)
				if cluster == "" {
					return "", fmt.Errorf("unable to resolve cluster for request namespace routing")
				}
				if segmentNamespace, ok := resolveDirectSegmentNamespace(cluster, namespace); ok {
					return segmentNamespace, nil
				}
				return authzConfig.NamespaceClassifier.Classify(cluster, namespace), nil
			}
			if authzConfig.ClusterResolver.HasMappings() {
				cluster := authzConfig.ClusterResolver.ResolveCluster(userInfo)
				if cluster == "" {
					return "", fmt.Errorf("unable to resolve cluster for request namespace routing")
				}
				return cluster + "." + strings.ToLower(strings.TrimSpace(namespace)), nil
			}
			return namespace, nil
		}
	}
	if namespace := strings.TrimSpace(backendConfig.Namespace); namespace != "" {
		return resolveNamespaceAliases(authzConfig, namespace), nil
	}
	if r != nil {
		if namespace := strings.TrimSpace(r.URL.Query().Get(queryParamNamespace)); namespace != "" {
			return resolveNamespaceAliases(authzConfig, namespace), nil
		}
	}
	return defaultNamespace, nil
}

func resolveNamespaceAliases(authzConfig config.AuthzConfig, namespace string) string {
	localCluster := strings.TrimSpace(authzConfig.LocalCluster)
	if namespace == "" || localCluster == "" {
		return namespace
	}

	parts := strings.Split(namespace, "|")
	resolved := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		if trimmed == "local" {
			resolved = append(resolved, localCluster)
			continue
		}
		if strings.HasPrefix(trimmed, "local.") {
			resolved = append(resolved, localCluster+strings.TrimPrefix(trimmed, "local"))
			continue
		}
		resolved = append(resolved, trimmed)
	}

	return strings.Join(resolved, "|")
}

func resolveDirectSegmentNamespace(cluster, namespace string) (string, bool) {
	trimmedCluster := strings.TrimSpace(cluster)
	if trimmedCluster == "" {
		return "", false
	}

	switch strings.ToLower(strings.TrimSpace(namespace)) {
	case "dev", "ops":
		return trimmedCluster + "." + strings.ToLower(strings.TrimSpace(namespace)), true
	default:
		return "", false
	}
}

func stripNamespaceRoutingQueryParam(r *http.Request, backendConfig config.BackendConfig) (*http.Request, error) {
	if r == nil || backendConfig.NamespaceRouting == nil || backendConfig.NamespaceRouting.Mode != namespaceRoutingModeRequest {
		return r, nil
	}

	cloned := r.Clone(r.Context())
	cloned.URL = cloneURL(r.URL)
	if namespaceRoutingReadsQuery(backendConfig.NamespaceRouting) {
		query := cloned.URL.Query()
		query.Del(backendConfig.NamespaceRouting.Parameter)
		cloned.URL.RawQuery = query.Encode()
	}

	if !namespaceRoutingReadsBody(backendConfig.NamespaceRouting) || !hasFormURLEncodedBody(r) {
		return cloned, nil
	}

	bodyValues, err := readFormURLEncodedBodyValues(r)
	if err != nil {
		return nil, err
	}
	bodyValues.Del(backendConfig.NamespaceRouting.Parameter)
	rewrittenBody := bodyValues.Encode()
	cloned.Body = io.NopCloser(strings.NewReader(rewrittenBody))
	cloned.ContentLength = int64(len(rewrittenBody))
	cloned.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(rewrittenBody)), nil
	}
	cloned.PostForm = bodyValues
	cloned.Form = cloneFormValues(bodyValues)

	return cloned, nil
}

func requestRoutingParameterValue(r *http.Request, routing *config.NamespaceRoutingConfig) (string, error) {
	if r == nil {
		return "", nil
	}
	if namespaceRoutingReadsQuery(routing) {
		if value := strings.TrimSpace(r.URL.Query().Get(routing.Parameter)); value != "" {
			return value, nil
		}
	}
	if !namespaceRoutingReadsBody(routing) || !hasFormURLEncodedBody(r) {
		return "", nil
	}
	bodyValues, err := readFormURLEncodedBodyValues(r)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(bodyValues.Get(routing.Parameter)), nil
}

func namespaceRoutingReadsQuery(routing *config.NamespaceRoutingConfig) bool {
	return namespaceRoutingUsesSource(routing, namespaceRoutingSourceQuery)
}

func namespaceRoutingReadsBody(routing *config.NamespaceRoutingConfig) bool {
	return namespaceRoutingUsesSource(routing, namespaceRoutingSourceBody)
}

func namespaceRoutingUsesSource(routing *config.NamespaceRoutingConfig, source string) bool {
	switch normalizedNamespaceRoutingSource(routing) {
	case namespaceRoutingSourceBoth, source:
		return true
	default:
		return false
	}
}

func normalizedNamespaceRoutingSource(routing *config.NamespaceRoutingConfig) string {
	if routing == nil {
		return namespaceRoutingSourceBoth
	}
	source := strings.ToLower(strings.TrimSpace(routing.Source))
	if source == "" {
		return namespaceRoutingSourceBoth
	}
	return source
}

func hasFormURLEncodedBody(r *http.Request) bool {
	if r == nil {
		return false
	}
	switch r.Method {
	case http.MethodPost, http.MethodPut, http.MethodPatch:
	default:
		return false
	}
	contentType := strings.ToLower(strings.TrimSpace(r.Header.Get(headerContentType)))
	return strings.HasPrefix(contentType, "application/x-www-form-urlencoded")
}

func readFormURLEncodedBodyValues(r *http.Request) (url.Values, error) {
	if r == nil || r.Body == nil {
		return url.Values{}, nil
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	_ = r.Body.Close()
	r.Body = io.NopCloser(strings.NewReader(string(body)))
	if len(body) == 0 {
		return url.Values{}, nil
	}
	values, err := url.ParseQuery(string(body))
	if err != nil {
		return nil, err
	}
	return values, nil
}

func cloneFormValues(values url.Values) url.Values {
	if values == nil {
		return url.Values{}
	}
	cloned := make(url.Values, len(values))
	for key, items := range values {
		cloned[key] = append([]string(nil), items...)
	}
	return cloned
}

func cloneURL(source *url.URL) *url.URL {
	if source == nil {
		return &url.URL{}
	}
	cloned := *source
	return &cloned
}

// logAudit records an audit event.
func (p *Proxy) logAudit(ctx context.Context, userInfo *auth.UserInfo, backend, namespace string, start time.Time, statusCode int, errorMsg string, perms *authz.Permission) {
	if p.auditStore == nil || userInfo == nil {
		return
	}

	event := &audit.AuditEvent{
		Timestamp:  start,
		UserID:     userInfo.ID,
		Backend:    backend,
		Namespace:  namespace,
		StatusCode: statusCode,
		Error:      errorMsg,
	}

	if perms != nil {
		event.Groups = perms.Groups
		if len(perms.ElevatedRoles) > 0 {
			event.ElevatedAccessActive = true
			event.ElevatedRole = perms.ElevatedRoles[0].Role
		}
	}

	slog.InfoContext(ctx, "audit",
		slog.String("user", event.UserID),
		slog.String("backend", event.Backend),
		slog.String("namespace", event.Namespace),
		slog.Int("status", event.StatusCode),
		slog.Bool("elevated_access_active", event.ElevatedAccessActive),
		slog.String("elevated_role", emptyAuditValue(event.ElevatedRole)),
		slog.String("groups", formatAuditGroups(event.Groups)),
		slog.String("error", emptyAuditValue(event.Error)),
	)

	auditCtx, cancel := context.WithTimeout(context.Background(), auditWriteTimeout)
	defer cancel()

	if err := p.auditStore.Log(auditCtx, event); err != nil {
		slog.ErrorContext(ctx, "failed to persist audit event", slog.Any("error", err))
	}
}

func (p *Proxy) requestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		recorder := &responseRecorder{
			ResponseWriter: w,
			statusCode:     http.StatusOK,
		}

		next.ServeHTTP(recorder, r)

		attributes := []any{
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.String("query", r.URL.RawQuery),
			slog.Int("status", recorder.statusCode),
			slog.Duration("duration", time.Since(start)),
			slog.String("request_id", middleware.GetReqID(r.Context())),
			slog.String("remote_addr", r.RemoteAddr),
		}

		if isProbePath(r.URL.Path) {
			slog.DebugContext(r.Context(), "http_request", attributes...)
			return
		}

		slog.InfoContext(r.Context(), "http_request", attributes...)
	})
}

func (p *Proxy) handleReadiness(w http.ResponseWriter, r *http.Request) {
	results := p.probeBackends(r.Context())
	failed := make([]readinessResult, 0)
	for _, result := range results {
		if result.Error != "" {
			failed = append(failed, result)
		}
	}

	w.Header().Set(headerContentType, "application/json")
	if len(failed) > 0 {
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":          "not_ready",
			"failed_backends": failed,
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":   "ready",
		"backends": results,
	})
}

func (p *Proxy) probeBackends(ctx context.Context) []readinessResult {
	names := p.config.GetBackendNames()
	sort.Strings(names)

	results := make([]readinessResult, len(names))
	var wg sync.WaitGroup

	for i, name := range names {
		wg.Add(1)
		go func(index int, backendName string, backendConfig config.BackendConfig) {
			defer wg.Done()
			results[index] = p.probeBackend(ctx, backendName, backendConfig)
		}(i, name, p.config.Backends[name])
	}

	wg.Wait()
	return results
}

func (p *Proxy) probeBackend(ctx context.Context, name string, backendConfig config.BackendConfig) readinessResult {
	probeURL := backendConfig.Endpoint
	if backendConfig.ReadinessURL != "" {
		probeURL = backendConfig.ReadinessURL
	}

	result := readinessResult{
		Backend:  name,
		Endpoint: probeURL,
	}

	probeCtx, cancel := context.WithTimeout(ctx, backendProbeTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(probeCtx, http.MethodGet, probeURL, nil)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	req.Header.Set("User-Agent", "multipass-readiness")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))

	result.StatusCode = resp.StatusCode
	if resp.StatusCode >= http.StatusInternalServerError {
		result.Error = fmt.Sprintf("backend returned %d", resp.StatusCode)
	}

	return result
}

// responseRecorder captures the status code.
type responseRecorder struct {
	http.ResponseWriter
	statusCode int
}

func (r *responseRecorder) WriteHeader(statusCode int) {
	r.statusCode = statusCode
	r.ResponseWriter.WriteHeader(statusCode)
}

func (r *responseRecorder) Flush() {
	if flusher, ok := r.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (r *responseRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := r.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("underlying ResponseWriter does not support hijacking")
	}

	return hijacker.Hijack()
}

func (r *responseRecorder) Push(target string, opts *http.PushOptions) error {
	pusher, ok := r.ResponseWriter.(http.Pusher)
	if !ok {
		return http.ErrNotSupported
	}

	return pusher.Push(target, opts)
}

func (r *responseRecorder) Unwrap() http.ResponseWriter {
	return r.ResponseWriter
}

// hasNamespaceAccess checks if the allowed namespaces list contains the requested namespace
func hasNamespaceAccess(allowedNamespaces []string, namespace string) bool {
	requestedNamespaces := strings.Split(namespace, "|")
	allowed := make(map[string]struct{}, len(allowedNamespaces))
	for _, ns := range allowedNamespaces {
		trimmed := strings.TrimSpace(ns)
		if trimmed == "" {
			continue
		}
		if trimmed == "*" {
			return true
		}
		allowed[trimmed] = struct{}{}
	}

	matched := false
	for _, requested := range requestedNamespaces {
		trimmed := strings.TrimSpace(requested)
		if trimmed == "" {
			continue
		}
		matched = true
		if _, ok := allowed[trimmed]; !ok {
			return false
		}
	}

	return matched
}

// ServeHTTP implements http.Handler
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.router.ServeHTTP(w, r)
}

func (p *Proxy) resolveBackendRequest(r *http.Request) (resolvedBackend, bool) {
	if r == nil {
		return resolvedBackend{}, false
	}

	trimmedPath := strings.TrimPrefix(r.URL.Path, "/")
	if trimmedPath == "" {
		return p.resolveBackendByHost(r.Host, r.URL.Path)
	}

	backendName := trimmedPath
	if slash := strings.Index(trimmedPath, "/"); slash >= 0 {
		backendName = trimmedPath[:slash]
	}

	backendConfig, ok := p.config.Backends[backendName]
	if ok {
		return resolvedBackend{name: backendName, config: backendConfig, stripPrefix: true}, true
	}

	return p.resolveBackendByHost(r.Host, r.URL.Path)
}

func (p *Proxy) resolveBackendByHost(host, requestPath string) (resolvedBackend, bool) {
	normalizedHost := normalizeHost(host)
	if normalizedHost == "" {
		return resolvedBackend{}, false
	}

	var bestMatch hostMatchedBackend
	found := false

	for name, backendConfig := range p.config.Backends {
		if !strings.EqualFold(strings.TrimSpace(backendConfig.ExternalHost), normalizedHost) {
			continue
		}

		matchedPrefix, ok := matchExternalPathPrefix(requestPath, backendConfig.ExternalPathPrefixes)
		if !ok {
			continue
		}

		candidate := hostMatchedBackend{
			resolved: resolvedBackend{name: name, config: backendConfig, stripPrefix: false},
			prefix:   matchedPrefix,
		}

		if !found || len(candidate.prefix) > len(bestMatch.prefix) || (len(candidate.prefix) == len(bestMatch.prefix) && candidate.resolved.name < bestMatch.resolved.name) {
			bestMatch = candidate
			found = true
		}
	}

	if !found {
		return resolvedBackend{}, false
	}

	return bestMatch.resolved, true
}

func matchExternalPathPrefix(requestPath string, prefixes []string) (string, bool) {
	if len(prefixes) == 0 {
		return "", true
	}

	if requestPath == "" {
		requestPath = "/"
	}

	bestMatch := ""
	for _, prefix := range prefixes {
		trimmedPrefix := strings.TrimSpace(prefix)
		if trimmedPrefix == "" {
			continue
		}
		if requestPath != trimmedPrefix && !strings.HasPrefix(requestPath, trimmedPrefix+"/") {
			continue
		}
		if len(trimmedPrefix) > len(bestMatch) {
			bestMatch = trimmedPrefix
		}
	}

	if bestMatch == "" {
		return "", false
	}

	return bestMatch, true
}

func normalizeHost(host string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}

	if parsedHost, _, err := net.SplitHostPort(host); err == nil && parsedHost != "" {
		return parsedHost
	}

	return host
}

func formatAuditGroups(groups []string) string {
	if len(groups) == 0 {
		return "-"
	}

	sortedGroups := append([]string(nil), groups...)
	sort.Strings(sortedGroups)
	return strings.Join(sortedGroups, ",")
}

func emptyAuditValue(value string) string {
	if value == "" {
		return "-"
	}

	return value
}

func isProbePath(path string) bool {
	return path == "/health" || path == "/ready"
}
