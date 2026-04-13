// Package proxy implements the authenticated Multipass reverse proxy.
package proxy

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
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
	tenantKey      contextKey = "tenant"
	jwtTokenKey    contextKey = "jwtToken"
)

const (
	headerAuthorization = "Authorization"
	headerContentType   = "Content-Type"
	headerBearerPrefix  = "Bearer "

	defaultTeamParam    = "tm_team_id"
	defaultTeamHeader   = "X-Multipass-Team-ID"
	auditWriteTimeout   = 2 * time.Second
	backendProbeTimeout = 2 * time.Second

	errMsgMissingAuth      = "Missing Authorization header"
	errMsgInvalidAuth      = "Invalid Authorization header format (expected 'Bearer <token>')"
	errMsgEmptyToken       = "Empty token"
	errMsgInvalidToken     = "Invalid token"
	errMsgBackendNotFound  = "Backend not found"
	errMsgAuthzFailed      = "Authorization check failed"
	errMsgAccessDenied     = "Access denied: no permission for tenant '%s'"
	errMsgTenantMissing    = "Missing tenant routing parameter '%s'"
	errMsgTempoTraceHidden = "Trace not found"
)

var errTempoTraceSegmentMismatch = errors.New("tempo trace segment mismatch")

// Proxy handles requests and routes to backends.
type Proxy struct {
	config       *config.Config
	backends     map[string]*httputil.ReverseProxy
	router       *chi.Mux
	httpClient   *http.Client
	authProvider auth.Provider
	browserAuth  browserAuthenticator
	authz        authz.Evaluator
	teamPolicy   *authz.TeamPolicyEvaluator
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

	if cfg != nil && cfg.Authz.TeamAccess.Enabled {
		teamAccess := cfg.Authz.TeamAccess
		adminRoles := teamAccess.AdminRoles
		if len(adminRoles) == 0 {
			adminRoles = []string{"admin"}
		}
		devopsRoles := teamAccess.DevopsRoles
		if len(devopsRoles) == 0 {
			devopsRoles = []string{"devops"}
		}
		developerRoles := teamAccess.DeveloperRoles
		if len(developerRoles) == 0 {
			developerRoles = []string{"developer"}
		}

		p.teamPolicy = authz.NewTeamPolicyEvaluator(teamAccess.GroupToTeamID, authz.TeamPolicyConfig{
			AdminRoles:     adminRoles,
			DevopsRoles:    devopsRoles,
			DeveloperRoles: developerRoles,
			MappingVersion: teamAccess.MappingVersion,
		})
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
		proxy.ModifyResponse = func(resp *http.Response) error {
			return p.modifyBackendResponse(resp, backendName, backendConfig)
		}
		proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
			if errors.Is(err, errTempoTraceSegmentMismatch) {
				http.Error(w, errMsgTempoTraceHidden, http.StatusNotFound)
				return
			}
			http.Error(w, err.Error(), http.StatusBadGateway)
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

func (p *Proxy) modifyBackendResponse(resp *http.Response, backendName string, backendConfig config.BackendConfig) error {
	if resp == nil {
		return nil
	}
	if !shouldFilterTempoTraceResponse(backendName, backendConfig, resp) {
		return nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()

	var payload any
	if err := json.Unmarshal(body, &payload); err != nil {
		return err
	}

	segment := requiredTempoTraceSegment(backendConfig)
	if segment == "" {
		resp.Body = io.NopCloser(strings.NewReader(string(body)))
		resp.ContentLength = int64(len(body))
		resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(body)))
		return nil
	}
	if !jsonContainsSegment(payload, segment) {
		return errTempoTraceSegmentMismatch
	}

	resp.Body = io.NopCloser(strings.NewReader(string(body)))
	resp.ContentLength = int64(len(body))
	resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(body)))
	return nil
}

func shouldFilterTempoTraceResponse(backendName string, backendConfig config.BackendConfig, resp *http.Response) bool {
	if backendName == "" || resp == nil || resp.Request == nil {
		return false
	}
	if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(backendName)), "tempo-") && backendName != "tempo" {
		return false
	}
	if requiredTempoTraceSegment(backendConfig) == "" {
		return false
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return false
	}
	routePath := strings.TrimSpace(resp.Request.URL.Path)
	if routePath == "" {
		routePath = "/"
	}
	if !strings.HasPrefix(routePath, "/") {
		routePath = "/" + routePath
	}
	routePath = path.Clean(routePath)
	return strings.HasPrefix(routePath, "/api/traces/") || strings.HasPrefix(routePath, "/api/v2/traces/")
}

func requiredTempoTraceSegment(backendConfig config.BackendConfig) string {
	if backendConfig.QueryRewrite == nil {
		return ""
	}
	for _, rule := range backendConfig.QueryRewrite.Semantics {
		if strings.TrimSpace(strings.ToLower(rule.Language)) != "traceql" {
			continue
		}
		for _, requirement := range rule.Require {
			name := strings.TrimSpace(requirement.Name)
			if name == "resource.segment" || name == "segment" {
				return strings.TrimSpace(requirement.Value)
			}
		}
	}
	return ""
}

func jsonContainsSegment(value any, required string) bool {
	trimmedRequired := strings.TrimSpace(required)
	if trimmedRequired == "" {
		return true
	}

	switch typed := value.(type) {
	case map[string]any:
		if objectContainsSegment(typed, trimmedRequired) {
			return true
		}
		for _, nested := range typed {
			if jsonContainsSegment(nested, trimmedRequired) {
				return true
			}
		}
	case []any:
		for _, item := range typed {
			if jsonContainsSegment(item, trimmedRequired) {
				return true
			}
		}
	}

	return false
}

func objectContainsSegment(object map[string]any, required string) bool {
	for _, key := range []string{"segment", "resource.segment"} {
		if value, ok := object[key]; ok && jsonScalarEquals(value, required) {
			return true
		}
	}

	key, ok := object["key"].(string)
	if !ok {
		return false
	}
	if key != "segment" && key != "resource.segment" {
		return false
	}
	value, ok := object["value"]
	if !ok {
		return false
	}
	return jsonScalarEquals(value, required)
}

func jsonScalarEquals(value any, required string) bool {
	switch typed := value.(type) {
	case string:
		return typed == required
	case map[string]any:
		for _, key := range []string{"stringValue", "value", "text"} {
			if nested, ok := typed[key]; ok && jsonScalarEquals(nested, required) {
				return true
			}
		}
	case []any:
		for _, item := range typed {
			if jsonScalarEquals(item, required) {
				return true
			}
		}
	}
	return false
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

	tenant, err := resolveRequestTenant(p.config.Authz, resolved.config, userInfo, r)
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
			p.logAudit(r.Context(), userInfo, resolved.name, tenant, start, http.StatusInternalServerError, err.Error(), perms)
			http.Error(w, errMsgAuthzFailed, http.StatusInternalServerError)
			return
		}

		r = r.WithContext(context.WithValue(r.Context(), permissionsKey, perms))

		if p.teamPolicy != nil {
			teamDecision := p.teamPolicy.EvaluatePermission(perms)
			requestTeamID := resolveRequestTeamID(r, p.config.Authz.TeamAccess)
			if requestTeamID != "" {
				if !p.teamPolicy.CanAccessTeam(teamDecision, requestTeamID) {
					slog.WarnContext(r.Context(), "team access denied",
						slog.String("user", userInfo.ID),
						slog.String("team_id", requestTeamID),
						slog.String("reason", teamDecision.Reason),
					)
					p.logAudit(r.Context(), userInfo, resolved.name, tenant, start, http.StatusForbidden, "access denied to team", perms)
					http.Error(w, fmt.Sprintf("Access denied: no permission for team '%s'", requestTeamID), http.StatusForbidden)
					return
				}

				r = r.Clone(r.Context())
				r.Header.Set(defaultTeamHeader, requestTeamID)
			}
		}
	}

	r = r.WithContext(context.WithValue(r.Context(), tenantKey, tenant))
	r, err = stripTenantRoutingQueryParam(r, resolved.config)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	r, err = p.rewriteBackendQuery(r, resolved, tenant)
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
		p.logAudit(r.Context(), userInfo, resolved.name, tenant, start, recorder.statusCode, "", perms)
	}
}

func resolveRequestTeamID(r *http.Request, cfg config.TeamAccessConfig) string {
	if r == nil {
		return ""
	}

	queryParam := strings.TrimSpace(cfg.RequestParam)
	if queryParam == "" {
		queryParam = defaultTeamParam
	}
	if teamID := strings.TrimSpace(r.URL.Query().Get(queryParam)); teamID != "" {
		return strings.ToLower(teamID)
	}

	headerName := strings.TrimSpace(cfg.RequestHeader)
	if headerName == "" {
		headerName = defaultTeamHeader
	}
	if teamID := strings.TrimSpace(r.Header.Get(headerName)); teamID != "" {
		return strings.ToLower(teamID)
	}

	return ""
}

// buildSegmentFilteringConfig creates a queryRewrite config that injects segment labels
// to enforce segment-based access control. Returns the original config if segment is admin or if segment classification is not configured.
func buildSegmentFilteringConfig(p *Proxy, baseConfig *queryrewrite.RewriteConfig, segment string, cluster string) *queryrewrite.RewriteConfig {
	// Admin sees all segments - no filtering
	if segment == segmentAdmin {
		return baseConfig
	}

	// Only apply segment filtering if segment classification is configured
	if !p.config.Authz.SegmentClassifier.HasRules() {
		return baseConfig
	}

	// Dev and ops users get segment label injected
	segmentFilteringRules := []queryrewrite.SemanticRule{
		{
			Language: "promql",
			Params:   []string{"query"},
			Routes:   []string{"/api/v1/query", "/api/v1/query_range", "/api/v1/series"},
			Require: []queryrewrite.MatcherRequirement{
				{
					Name:     "segment",
					Operator: "=",
					Value:    segment,
				},
			},
		},
		{
			Language: "selector",
			Params:   []string{"match[]"},
			Routes:   []string{"/api/v1/series", "/api/v1/labels", "/api/v1/label/*"},
			Require: []queryrewrite.MatcherRequirement{
				{
					Name:     "segment",
					Operator: "=",
					Value:    segment,
				},
			},
		},
		{
			Language: "logql",
			Params:   []string{"query"},
			Routes:   []string{"/loki/api/v1/query", "/loki/api/v1/query_range", "/loki/api/v1/series"},
			Require: []queryrewrite.MatcherRequirement{
				{
					Name:     "segment",
					Operator: "=",
					Value:    segment,
				},
			},
		},
		{
			Language: "traceql",
			Params:   []string{"q"},
			Routes:   []string{"/api/search", "/api/traces/*"},
			Require: []queryrewrite.MatcherRequirement{
				{
					Name:     "resource.segment",
					Operator: "=",
					Value:    segment,
				},
			},
		},
	}

	// If no base config, use only segment filtering
	if baseConfig == nil {
		return &queryrewrite.RewriteConfig{
			Semantics: segmentFilteringRules,
		}
	}

	// Clone and augment base config
	augmented := &queryrewrite.RewriteConfig{
		Operations: append([]queryrewrite.RewriteOperation(nil), baseConfig.Operations...),
		Semantics:  append([]queryrewrite.SemanticRule(nil), baseConfig.Semantics...),
	}

	// Append segment filtering rules
	augmented.Semantics = append(augmented.Semantics, segmentFilteringRules...)

	return augmented
}

func (p *Proxy) rewriteBackendQuery(r *http.Request, resolved resolvedBackend, tenant string) (*http.Request, error) {
	// Determine segment for filtering (independent of tenant)
	segment := resolveSegment(r)

	// Determine cluster for segment classification
	cluster := ""
	if userInfo, ok := r.Context().Value(userInfoKey).(*auth.UserInfo); ok && userInfo != nil {
		cluster = p.config.Authz.ClusterResolver.ResolveCluster(userInfo)
	}

	// Build config with segment filtering
	// Segment filtering is for query rewriting (namespace matchers)
	// Tenant is for multi-tenant backend isolation (X-Scope-OrgID)
	// These are completely independent concepts
	effectiveConfig := buildSegmentFilteringConfig(p, resolved.config.QueryRewrite, segment, cluster)

	if r == nil || !queryrewrite.HasRules(effectiveConfig) {
		return r, nil
	}

	route := r.URL.Path
	if resolved.stripPrefix {
		route = strings.TrimPrefix(route, "/"+resolved.name)
		if route == "" {
			route = "/"
		}
	}

	return queryrewrite.RewriteRequest(r, effectiveConfig, queryrewrite.Context{
		Backend: resolved.name,
		Tenant:  tenant,
		Host:    r.Host,
		Route:   route,
		Method:  r.Method,
		Segment: segment,
	})
}

func resolveRequestTenant(authzConfig config.AuthzConfig, backendConfig config.BackendConfig, userInfo *auth.UserInfo, r *http.Request) (string, error) {
	// Request-based tenant routing
	if backendConfig.TenantRouting != nil && backendConfig.TenantRouting.Mode == "request" {
		param := backendConfig.TenantRouting.Parameter
		if param == "" {
			param = "tenant"
		}

		source := backendConfig.TenantRouting.Source
		if source == "" {
			source = "query"
		}

		var rawTenant string
		switch source {
		case "query":
			rawTenant = r.URL.Query().Get(param)
		case "body":
			if r.PostForm != nil {
				rawTenant = r.PostForm.Get(param)
			}
		case "both":
			rawTenant = r.URL.Query().Get(param)
			if rawTenant == "" && r.PostForm != nil {
				rawTenant = r.PostForm.Get(param)
			}
		}

		rawTenant = strings.TrimSpace(rawTenant)
		if rawTenant != "" {
			return rawTenant, nil
		}
	}

	// Fixed tenant takes precedence
	if tenant := strings.TrimSpace(backendConfig.Tenant); tenant != "" {
		return tenant, nil
	}

	// No tenant configured - use default
	return "default", nil
}

func stripTenantRoutingQueryParam(r *http.Request, backendConfig config.BackendConfig) (*http.Request, error) {
	// Only strip if using request-based routing
	if backendConfig.TenantRouting == nil || backendConfig.TenantRouting.Mode != "request" {
		return r, nil
	}

	param := backendConfig.TenantRouting.Parameter
	if param == "" {
		param = "tenant"
	}

	source := backendConfig.TenantRouting.Source
	if source == "" {
		source = "query"
	}

	// Strip from query if needed
	if source == "query" || source == "both" {
		query := r.URL.Query()
		if query.Has(param) {
			query.Del(param)
			cloned := r.Clone(r.Context())
			cloned.URL = &url.URL{}
			*cloned.URL = *r.URL
			cloned.URL.RawQuery = query.Encode()
			return cloned, nil
		}
	}

	return r, nil
}

// logAudit records an audit event.
func (p *Proxy) logAudit(ctx context.Context, userInfo *auth.UserInfo, backend, tenant string, start time.Time, statusCode int, errorMsg string, perms *authz.Permission) {
	if p.auditStore == nil || userInfo == nil {
		return
	}

	event := &audit.AuditEvent{
		Timestamp:  start,
		UserID:     userInfo.ID,
		Backend:    backend,
		Tenant:     tenant,
		StatusCode: statusCode,
		Error:      errorMsg,
	}

	if perms != nil {
		event.Groups = perms.ExternalGroups
		if len(perms.ElevatedRoles) > 0 {
			event.ElevatedAccessActive = true
			event.ElevatedRole = perms.ElevatedRoles[0].Role
		}
	}

	slog.InfoContext(ctx, "audit",
		slog.String("user", event.UserID),
		slog.String("backend", event.Backend),
		slog.String("tenant", event.Tenant),
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
