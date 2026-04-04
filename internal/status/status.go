package status

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/karloie/multipass/internal/auth"
	"github.com/karloie/multipass/internal/authz"
	"github.com/karloie/multipass/internal/config"
)

const probeTimeout = 5 * time.Second

type oidcProbeResult struct {
	Configured     bool   `json:"configured"`
	ActiveProvider bool   `json:"active_provider"`
	IssuerURL      string `json:"issuer_url,omitempty"`
	DiscoveryURL   string `json:"discovery_url,omitempty"`
	Reachable      bool   `json:"reachable"`
	StatusCode     int    `json:"status_code,omitempty"`
	Error          string `json:"error,omitempty"`
}

type response struct {
	Mode        string       `json:"mode"`
	Auth        authStatus   `json:"auth"`
	Authz       authzStatus  `json:"authz"`
	CurrentUser currentUser  `json:"current_user"`
	Checks      checksStatus `json:"checks"`
	Issues      []string     `json:"issues"`
	GeneratedAt string       `json:"generated_at"`
}

type authStatus struct {
	Provider string `json:"provider"`
}

type authzStatus struct {
	Enabled  bool   `json:"enabled"`
	Provider string `json:"provider,omitempty"`
}

type checksStatus struct {
	OIDC oidcProbeResult `json:"oidc"`
}

type currentUser struct {
	Authenticated        bool     `json:"authenticated"`
	ID                   string   `json:"id,omitempty"`
	Username             string   `json:"username,omitempty"`
	PrincipalID          string   `json:"principal_id,omitempty"`
	TenantID             string   `json:"tenant_id,omitempty"`
	Email                string   `json:"email,omitempty"`
	Name                 string   `json:"name,omitempty"`
	ExternalGroups       []string `json:"external_groups,omitempty"`
	InternalRoles        []string `json:"internal_roles,omitempty"`
	RawAllowedNamespaces []string `json:"raw_allowed_namespaces,omitempty"`
	AllowedNamespaces    []string `json:"allowed_namespaces,omitempty"`
	ElevatedRoles        []string `json:"elevated_roles,omitempty"`
	PermissionsError     string   `json:"permissions_error,omitempty"`
}

type browserAuthenticator interface {
	AuthenticateRequest(r *http.Request) (*auth.UserInfo, bool)
}

type Handler struct {
	config         *config.Config
	httpClient     *http.Client
	browserAuth    browserAuthenticator
	authzEvaluator authz.Evaluator
}

func Enabled(cfg *config.Config) bool {
	return cfg != nil
}

func NewHandler(cfg *config.Config, browserAuth browserAuthenticator, evaluator authz.Evaluator) http.Handler {
	return &Handler{
		config:         cfg,
		browserAuth:    browserAuth,
		authzEvaluator: evaluator,
		httpClient: &http.Client{
			Timeout: probeTimeout,
		},
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	status := h.collect(r)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(status)
}

func (h *Handler) collect(r *http.Request) response {
	ctx := context.Background()
	if r != nil {
		ctx = r.Context()
	}

	result := response{
		Mode: statusMode(h.config),
		Auth: authStatus{
			Provider: h.config.Auth.Provider,
		},
		Authz: authzStatus{
			Enabled:  h.config.Authz.Enabled,
			Provider: h.config.Authz.Provider,
		},
		CurrentUser: h.currentUserStatus(r),
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
	}

	result.Checks.OIDC = h.probeOIDC(ctx)
	result.Issues = collectIssues(result)

	return result
}

func (h *Handler) currentUserStatus(r *http.Request) currentUser {
	result := currentUser{}
	if h.browserAuth == nil || r == nil {
		return result
	}

	userInfo, ok := h.browserAuth.AuthenticateRequest(r)
	if !ok || userInfo == nil {
		return result
	}

	result.Authenticated = true
	result.ID = userInfo.ID
	result.Username = userInfo.Username
	result.PrincipalID = userInfo.PrincipalID
	result.TenantID = userInfo.TenantID
	result.Email = userInfo.Email
	result.Name = userInfo.Name

	if h.authzEvaluator != nil && h.config.Authz.Enabled {
		permission, err := h.authzEvaluator.EvaluatePermissions(r.Context(), userInfo)
		if err != nil {
			result.PermissionsError = err.Error()
		} else if permission != nil {
			result.ExternalGroups = append([]string(nil), permission.ExternalGroups...)
			result.InternalRoles = append([]string(nil), permission.InternalRoles...)
			result.RawAllowedNamespaces = append([]string(nil), permission.AllowedNamespaces...)
			result.AllowedNamespaces = displayAllowedNamespaces(h.config, userInfo, permission.AllowedNamespaces)
			result.ElevatedRoles = elevatedRoleNames(permission.ElevatedRoles)
		}
	}

	return result
}

func statusMode(cfg *config.Config) string {
	if cfg == nil {
		return "unknown"
	}

	return "live"
}

func (h *Handler) probeOIDC(ctx context.Context) oidcProbeResult {
	issuerURL := strings.TrimSpace(h.config.Auth.OIDC.IssuerURL)
	result := oidcProbeResult{
		Configured:     hasOIDCConfig(h.config),
		ActiveProvider: strings.EqualFold(strings.TrimSpace(h.config.Auth.Provider), "oidc"),
		IssuerURL:      issuerURL,
	}

	if issuerURL == "" {
		return result
	}

	discoveryURL := strings.TrimRight(issuerURL, "/") + "/.well-known/openid-configuration"
	result.DiscoveryURL = discoveryURL

	probeCtx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(probeCtx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		result.Error = err.Error()
		return result
	}

	resp, err := h.httpClient.Do(req)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer resp.Body.Close()

	result.StatusCode = resp.StatusCode
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		result.Error = fmt.Sprintf("unexpected status %d", resp.StatusCode)
		return result
	}

	var discovery struct {
		Issuer string `json:"issuer"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&discovery); err != nil {
		result.Error = fmt.Sprintf("invalid discovery document: %v", err)
		return result
	}
	if strings.TrimSpace(discovery.Issuer) == "" {
		result.Error = "discovery document missing issuer"
		return result
	}

	result.Reachable = true
	return result
}

func hasOIDCConfig(cfg *config.Config) bool {
	if cfg == nil {
		return false
	}

	oidcCfg := cfg.Auth.OIDC
	return strings.TrimSpace(oidcCfg.IssuerURL) != "" || strings.TrimSpace(oidcCfg.ClientID) != "" || strings.TrimSpace(oidcCfg.RedirectURL) != ""
}

func displayAllowedNamespaces(cfg *config.Config, userInfo *auth.UserInfo, allowedNamespaces []string) []string {
	if len(allowedNamespaces) == 0 {
		return nil
	}

	if cfg == nil {
		return append([]string(nil), allowedNamespaces...)
	}

	resolvedClusters := statusResolvedClusters(cfg, userInfo)
	backendClusters := statusRequestRoutedBackendClusters(cfg)
	visibleNamespaces := make(map[string]struct{}, len(allowedNamespaces))

	for _, namespace := range allowedNamespaces {
		trimmedNamespace := strings.TrimSpace(namespace)
		if trimmedNamespace == "" {
			continue
		}

		if trimmedNamespace == "*" || isDerivedNamespace(trimmedNamespace, resolvedClusters, backendClusters, cfg.Authz.NamespaceClassifier) {
			visibleNamespaces[trimmedNamespace] = struct{}{}
			continue
		}

		derivedNamespaces := deriveVisibleNamespaces(cfg, trimmedNamespace, resolvedClusters, backendClusters)
		if len(derivedNamespaces) == 0 {
			visibleNamespaces[trimmedNamespace] = struct{}{}
			continue
		}

		for _, derivedNamespace := range derivedNamespaces {
			visibleNamespaces[derivedNamespace] = struct{}{}
		}
	}

	if len(visibleNamespaces) == 0 {
		return nil
	}

	result := make([]string, 0, len(visibleNamespaces))
	for namespace := range visibleNamespaces {
		result = append(result, namespace)
	}
	sort.Strings(result)

	return result
}

func deriveVisibleNamespaces(cfg *config.Config, namespace string, resolvedClusters, backendClusters []string) []string {
	authzConfig := cfg.Authz
	if authzConfig.NamespaceClassifier.HasRules() {
		derivedNamespaces := make([]string, 0, len(resolvedClusters)+len(backendClusters)+1)
		for _, cluster := range backendClusters {
			derivedNamespaces = append(derivedNamespaces, authzConfig.NamespaceClassifier.Classify(cluster, namespace))
		}
		for _, cluster := range resolvedClusters {
			derivedNamespaces = append(derivedNamespaces, authzConfig.NamespaceClassifier.Classify(cluster, namespace))
		}
		if len(derivedNamespaces) == 0 {
			derivedNamespaces = append(derivedNamespaces, authzConfig.NamespaceClassifier.Classify("", namespace))
		}
		return derivedNamespaces
	}

	if len(resolvedClusters) == 0 {
		return nil
	}

	normalizedNamespace := strings.ToLower(strings.TrimSpace(namespace))
	if normalizedNamespace == "" {
		return nil
	}

	derivedNamespaces := make([]string, 0, len(resolvedClusters))
	for _, cluster := range resolvedClusters {
		derivedNamespaces = append(derivedNamespaces, cluster+"."+normalizedNamespace)
	}

	return derivedNamespaces
}

func statusResolvedClusters(cfg *config.Config, userInfo *auth.UserInfo) []string {
	if cfg == nil || !cfg.Authz.ClusterResolver.HasMappings() {
		return nil
	}

	cluster := strings.TrimSpace(cfg.Authz.ClusterResolver.ResolveCluster(userInfo))
	if cluster == "" {
		return nil
	}

	return []string{cluster}
}

func statusRequestRoutedBackendClusters(cfg *config.Config) []string {
	if cfg == nil || !cfg.Authz.NamespaceClassifier.HasRules() {
		return nil
	}

	clusters := make(map[string]struct{})
	for _, backend := range cfg.Backends {
		if backend.NamespaceRouting == nil || !strings.EqualFold(strings.TrimSpace(backend.NamespaceRouting.Mode), "request") {
			continue
		}

		cluster := strings.TrimSpace(backend.Namespace)
		if cluster == "" {
			continue
		}

		clusters[cluster] = struct{}{}
	}

	if len(clusters) == 0 {
		return nil
	}

	result := make([]string, 0, len(clusters))
	for cluster := range clusters {
		result = append(result, cluster)
	}
	sort.Strings(result)

	return result
}

func isDerivedNamespace(namespace string, resolvedClusters, backendClusters []string, classifier config.NamespaceClassifierConfig) bool {
	for _, cluster := range resolvedClusters {
		if strings.HasPrefix(namespace, cluster+".") {
			return true
		}
	}
	for _, cluster := range backendClusters {
		if strings.HasPrefix(namespace, cluster+".") {
			return true
		}
	}

	if len(resolvedClusters) == 0 && len(backendClusters) == 0 && classifier.HasRules() {
		defaultSegment := strings.TrimSpace(classifier.DefaultSegment)
		if defaultSegment == "" {
			defaultSegment = "dev"
		}
		return namespace == "ops" || namespace == defaultSegment
	}

	return false
}

func elevatedRoleNames(roles []authz.ElevatedRole) []string {
	if len(roles) == 0 {
		return nil
	}

	names := make([]string, 0, len(roles))
	for _, role := range roles {
		if strings.TrimSpace(role.Role) == "" {
			continue
		}
		names = append(names, role.Role)
	}

	if len(names) == 0 {
		return nil
	}

	return names
}

func collectIssues(status response) []string {
	issues := make([]string, 0, 2)

	if status.Checks.OIDC.Configured && !status.Checks.OIDC.Reachable {
		issues = append(issues, "oidc discovery probe failed")
	}

	if status.CurrentUser.PermissionsError != "" {
		issues = append(issues, "current user permission evaluation failed")
	}

	return issues
}
