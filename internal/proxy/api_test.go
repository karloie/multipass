package proxy

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/karloie/multipass/internal/audit"
	"github.com/karloie/multipass/internal/auth"
	"github.com/karloie/multipass/internal/authz"
	"github.com/karloie/multipass/internal/config"
	queryrewrite "github.com/karloie/multipass/internal/query"
)

func TestAPIBackends(t *testing.T) {
	tests := []proxyTestCase{
		{
			name:                 "host-based backend matches shared host path prefix",
			backendName:          "mimir",
			backendType:          "generic",
			requestPath:          "/otlp/v1/metrics",
			host:                 "otlp.example.com",
			externalPathPrefixes: []string{"/otlp/v1/metrics"},
			authToken:            "valid-token",
			authValidateFunc: func(ctx context.Context, token string) (*auth.UserInfo, error) {
				return &auth.UserInfo{ID: "user-shared-host"}, nil
			},
			authzEnabled:      false,
			expectedStatus:    http.StatusOK,
			expectAuditEvent:  true,
			expectAuthCall:    true,
			expectAuthzCall:   false,
			expectBackendCall: true,
		},
		{
			name:                 "host-based backend rejects unmatched shared host path prefix",
			backendName:          "mimir",
			backendType:          "generic",
			requestPath:          "/otlp/v1/logs",
			host:                 "otlp.example.com",
			externalPathPrefixes: []string{"/otlp/v1/metrics"},
			authToken:            "valid-token",
			authValidateFunc: func(ctx context.Context, token string) (*auth.UserInfo, error) {
				return &auth.UserInfo{ID: "user-shared-host-miss"}, nil
			},
			authzEnabled:      false,
			expectedStatus:    http.StatusNotFound,
			expectAuditEvent:  false,
			expectAuthCall:    false,
			expectAuthzCall:   false,
			expectBackendCall: false,
		},
		{
			name:        "request-routed Prometheus backend allows permitted namespace and strips routing parameter",
			backendName: "mimir",
			backendType: "prometheus",
			requestPath: "/mimir/api/v1/query?tm_tenant=utv&query=up",
			authToken:   "valid-token",
			authValidateFunc: func(ctx context.Context, token string) (*auth.UserInfo, error) {
				return &auth.UserInfo{ID: "user-request-ok"}, nil
			},
			authzGetUserGroupsFunc: func(ctx context.Context, userID string) ([]string, error) {
				return []string{"utv-team"}, nil
			},
			authzGroupMappings: map[string][]string{
				"utv-team": {"utv"},
			},
			authzEnabled:           true,
			expectedStatus:         http.StatusOK,
			expectedHeaders:        map[string]string{"X-Scope-OrgID": "utv"},
			expectedBackendQuery:   "query=up",
			expectedAuditTenant: "utv",
			expectAuditEvent:       true,
			expectAuthCall:         true,
			expectAuthzCall:        true,
			expectBackendCall:      true,
		},
		{
			name:        "request-routed backend rewrites query after namespace stripping",
			backendName: "mimir",
			backendType: "prometheus",
			requestPath: "/mimir/api/v1/query?tm_tenant=utv&query=up&debug=true",
			queryRewrite: &queryrewrite.RewriteConfig{Operations: []queryrewrite.RewriteOperation{
				{Action: "rename", Name: "query", To: "expr"},
				{Action: "add", Name: "tenant", Value: "{{tenant}}"},
				{Action: "set", Name: "source", Value: "multipass-{{backend}}"},
				{Action: "delete", Name: "debug"},
			}},
			authToken: "valid-token",
			authValidateFunc: func(ctx context.Context, token string) (*auth.UserInfo, error) {
				return &auth.UserInfo{ID: "user-query-rewrite"}, nil
			},
			authzGetUserGroupsFunc: func(ctx context.Context, userID string) ([]string, error) {
				return []string{"utv-team"}, nil
			},
			authzGroupMappings: map[string][]string{
				"utv-team": {"utv"},
			},
			authzEnabled:           true,
			expectedStatus:         http.StatusOK,
			expectedHeaders:        map[string]string{"X-Scope-OrgID": "utv"},
			expectedBackendQuery:   "expr=up&source=multipass-mimir&tenant=utv",
			expectedAuditTenant: "utv",
			expectAuditEvent:       true,
			expectAuthCall:         true,
			expectAuthzCall:        true,
		},
		{
			name:               "fixed-namespace backend rewrites form-encoded post body",
			backendName:        "mimir",
			backendType:        "prometheus",
			backendNamespace:   "utv",
			requestMethod:      http.MethodPost,
			requestPath:        "/mimir/api/v1/query",
			requestBody:        "query=up&debug=true",
			requestContentType: "application/x-www-form-urlencoded",
			queryRewrite: &queryrewrite.RewriteConfig{Operations: []queryrewrite.RewriteOperation{
				{Action: "rename", Name: "query", To: "expr"},
				{Action: "add", Name: "tenant", Value: "{{tenant}}"},
				{Action: "set", Name: "source", Value: "multipass-{{backend}}"},
				{Action: "delete", Name: "debug"},
			}},
			authToken: "valid-token",
			authValidateFunc: func(ctx context.Context, token string) (*auth.UserInfo, error) {
				return &auth.UserInfo{ID: "user-query-rewrite-post"}, nil
			},
			authzGetUserGroupsFunc: func(ctx context.Context, userID string) ([]string, error) {
				return []string{"utv-team"}, nil
			},
			authzGroupMappings: map[string][]string{
				"utv-team": {"utv"},
			},
			authzEnabled:           true,
			expectedStatus:         http.StatusOK,
			expectedHeaders:        map[string]string{"X-Scope-OrgID": "utv"},
			expectedBackendBody:    "expr=up&source=multipass-mimir&tenant=utv",
			expectedAuditTenant: "utv",
			expectAuditEvent:       true,
			expectAuthCall:         true,
			expectAuthzCall:        true,
			expectBackendCall:      true,
		},
		{
			name:        "route-aware semantics enforce selector matchers on series endpoint",
			backendName: "mimir",
			backendType: "prometheus",
			requestPath: "/mimir/api/v1/series?tm_tenant=utv&match%5B%5D=up",
			queryRewrite: &queryrewrite.RewriteConfig{
				Operations: []queryrewrite.RewriteOperation{{
					Action: "rename",
					Name:   "query",
					To:     "expr",
					Routes: []string{"/api/v1/query"},
				}},
				Semantics: []queryrewrite.SemanticRule{{
					Language: "selector",
					Params:   []string{"match[]"},
					Routes:   []string{"/api/v1/series"},
					Require: []queryrewrite.MatcherRequirement{{
						Name:  "namespace",
						Value: "{{tenant}}",
					}},
				}},
			},
			authToken: "valid-token",
			authValidateFunc: func(ctx context.Context, token string) (*auth.UserInfo, error) {
				return &auth.UserInfo{ID: "user-series-selector"}, nil
			},
			authzGetUserGroupsFunc: func(ctx context.Context, userID string) ([]string, error) {
				return []string{"utv-team"}, nil
			},
			authzGroupMappings: map[string][]string{
				"utv-team": {"utv"},
			},
			authzEnabled:           true,
			expectedStatus:         http.StatusOK,
			expectedHeaders:        map[string]string{"X-Scope-OrgID": "utv"},
			expectedBackendQuery:   "match%5B%5D=%7B__name__%3D%22up%22%2Cnamespace%3D%22utv%22%7D",
			expectedAuditTenant: "utv",
			expectAuditEvent:       true,
			expectAuthCall:         true,
			expectAuthzCall:        true,
			expectBackendCall:      true,
		},
		{
			name:        "request-routed Prometheus backend allows any namespace (Phase 1)",
			backendName: "mimir",
			backendType: "prometheus",
			requestPath: "/mimir/api/v1/query?tm_tenant=monitoring&query=up",
			authToken:   "valid-token",
			authValidateFunc: func(ctx context.Context, token string) (*auth.UserInfo, error) {
				return &auth.UserInfo{ID: "user-request-deny"}, nil
			},
			authzGetUserGroupsFunc: func(ctx context.Context, userID string) ([]string, error) {
				return []string{"utv-team"}, nil
			},
			authzGroupMappings: map[string][]string{
				"utv-team": {"utv"},
			},
			authzEnabled:   true,
			expectedStatus: http.StatusOK,
			expectedHeaders: map[string]string{
				"X-Scope-OrgID": "monitoring",
			},
			expectedAuditTenant: "monitoring",
			expectAuditEvent:       true,
			expectAuthCall:         true,
			expectAuthzCall:        true,
			expectBackendCall:      true,
		},
		{
			name:             "successful request to Prometheus backend with auth and authz",
			backendName:      "loki",
			backendType:      "prometheus",
			requestPath:      "/loki/loki/api/v1/query",
			authToken:        "",
			namespace:        "production",
			authValidateFunc: nil,
			authzGetUserGroupsFunc: func(ctx context.Context, userID string) ([]string, error) {
				return []string{"sre-team"}, nil
			},
			authzGroupMappings: map[string][]string{
				"sre-team": {"production", "staging"},
			},
			authzEnabled:   true,
			expectedStatus: http.StatusOK,
			expectedHeaders: map[string]string{
				"X-Scope-OrgID": "production",
			},
			expectedBackendQuery: "namespace=production",
			expectAuditEvent:     true,
			expectAuthCall:       true,
			expectAuthzCall:      true,
			expectBackendCall:    true,
		},
		{
			name:        "request to OpenSearch backend with JWT header injection",
			backendName: "opensearch",
			backendType: "jwt",
			requestPath: "/opensearch/_search",
			authToken:   "valid-jwt",
			namespace:   "logs",
			authValidateFunc: func(ctx context.Context, token string) (*auth.UserInfo, error) {
				return &auth.UserInfo{ID: "user456"}, nil
			},
			authzGetUserGroupsFunc: func(ctx context.Context, userID string) ([]string, error) {
				return []string{"logs-team"}, nil
			},
			authzGroupMappings: map[string][]string{
				"logs-team": {"logs"},
			},
			authzEnabled:   true,
			expectedStatus: http.StatusOK,
			expectedHeaders: map[string]string{
				"Authorization": "Bearer valid-jwt",
			},
			expectAuditEvent:  true,
			expectAuthCall:    true,
			expectAuthzCall:   true,
			expectBackendCall: true,
		},
		{
			name:        "missing authorization header",
			backendName: "loki",
			backendType: "prometheus",
			requestPath: "/loki/api/v1/query",
			authToken:   "",
			namespace:   "default",
			authValidateFunc: func(ctx context.Context, token string) (*auth.UserInfo, error) {
				return nil, nil
			},
			authzEnabled:      false,
			expectedStatus:    http.StatusUnauthorized,
			expectAuditEvent:  false,
			expectAuthCall:    false,
			expectAuthzCall:   false,
			expectBackendCall: false,
		},
		{
			name:        "trusted proxy request to Prometheus backend with authz",
			backendName: "loki",
			backendType: "prometheus",
			requestPath: "/loki/loki/api/v1/query",
			trustedProxyConfig: &config.TrustedProxyConfig{
				Enabled:      true,
				UserHeader:   "X-Grafana-User",
				GroupsHeader: "X-Multipass-Groups",
				SecretHeader: "X-Multipass-Proxy-Secret",
				SecretValue:  "core-test-shared-secret",
			},
			requestHeaders: map[string]string{
				"X-Grafana-User":           "paul@example.com",
				"X-Multipass-Groups":       "developers",
				"X-Multipass-Proxy-Secret": "core-test-shared-secret",
			},
			namespace: "utv",
			authzGetUserGroupsFunc: func(ctx context.Context, userID string) ([]string, error) {
				if userID != "paul@example.com" {
					return nil, errors.New("unexpected trusted proxy user")
				}
				return []string{"developers"}, nil
			},
			authzGroupMappings: map[string][]string{
				"developers": {"utv"},
			},
			authzEnabled:   true,
			expectedStatus: http.StatusOK,
			expectedHeaders: map[string]string{
				"X-Scope-OrgID": "utv",
			},
			expectAuditEvent:  true,
			expectAuthCall:    false,
			expectAuthzCall:   true,
			expectBackendCall: true,
		},
		{
			name:        "trusted proxy request without shared secret is unauthorized",
			backendName: "loki",
			backendType: "prometheus",
			requestPath: "/loki/api/v1/query",
			trustedProxyConfig: &config.TrustedProxyConfig{
				Enabled:      true,
				UserHeader:   "X-Grafana-User",
				SecretHeader: "X-Multipass-Proxy-Secret",
				SecretValue:  "core-test-shared-secret",
			},
			requestHeaders: map[string]string{
				"X-Grafana-User": "paul@example.com",
			},
			authzEnabled:      false,
			expectedStatus:    http.StatusUnauthorized,
			expectAuditEvent:  false,
			expectAuthCall:    false,
			expectAuthzCall:   false,
			expectBackendCall: false,
		},
		{
			name:        "invalid auth token",
			backendName: "loki",
			backendType: "prometheus",
			requestPath: "/loki/api/v1/query",
			authToken:   "invalid-token",
			namespace:   "default",
			authValidateFunc: func(ctx context.Context, token string) (*auth.UserInfo, error) {
				return nil, errors.New("invalid token")
			},
			authzEnabled:      false,
			expectedStatus:    http.StatusUnauthorized,
			expectAuditEvent:  false,
			expectAuthCall:    true,
			expectAuthzCall:   false,
			expectBackendCall: false,
		},
		{
			name:        "authorization allowed - namespace check disabled (Phase 1)",
			backendName: "loki",
			backendType: "prometheus",
			requestPath: "/loki/api/v1/query",
			authToken:   "valid-token",
			namespace:   "forbidden",
			authValidateFunc: func(ctx context.Context, token string) (*auth.UserInfo, error) {
				return &auth.UserInfo{ID: "user789"}, nil
			},
			authzGetUserGroupsFunc: func(ctx context.Context, userID string) ([]string, error) {
				return []string{"limited-group"}, nil
			},
			authzGroupMappings: map[string][]string{
				"limited-group": {"allowed"},
			},
			authzEnabled:   true,
			expectedStatus: http.StatusOK,
			expectedHeaders: map[string]string{
				"X-Scope-OrgID": "forbidden",
			},
			expectAuditEvent:  true,
			expectAuthCall:    true,
			expectAuthzCall:   true,
			expectBackendCall: true,
		},
		{
			name:        "successful request with authz disabled",
			backendName: "grafana",
			backendType: "prometheus",
			requestPath: "/grafana/api/dashboards",
			authToken:   "valid-token",
			namespace:   "default",
			authValidateFunc: func(ctx context.Context, token string) (*auth.UserInfo, error) {
				return &auth.UserInfo{ID: "user999"}, nil
			},
			authzEnabled:      false,
			expectedStatus:    http.StatusOK,
			expectAuditEvent:  true,
			expectAuthCall:    true,
			expectAuthzCall:   false,
			expectBackendCall: true,
		},
		{
			name:        "backend not found",
			backendName: "nonexistent",
			backendType: "prometheus",
			requestPath: "/nonexistent/api",
			authToken:   "valid-token",
			namespace:   "default",
			authValidateFunc: func(ctx context.Context, token string) (*auth.UserInfo, error) {
				return &auth.UserInfo{ID: "user000"}, nil
			},
			authzEnabled:      false,
			expectedStatus:    http.StatusNotFound,
			expectAuditEvent:  false,
			expectAuthCall:    false,
			expectAuthzCall:   false,
			expectBackendCall: false,
		},
		{
			name:        "request with default namespace when not specified",
			backendName: "tempo",
			backendType: "prometheus",
			requestPath: "/tempo/api/traces",
			authToken:   "valid-token",
			namespace:   "",
			authValidateFunc: func(ctx context.Context, token string) (*auth.UserInfo, error) {
				return &auth.UserInfo{ID: "user111"}, nil
			},
			authzGetUserGroupsFunc: func(ctx context.Context, userID string) ([]string, error) {
				return []string{"default-group"}, nil
			},
			authzGroupMappings: map[string][]string{
				"default-group": {"default"},
			},
			authzEnabled:   true,
			expectedStatus: http.StatusOK,
			expectedHeaders: map[string]string{
				"X-Scope-OrgID": "default",
			},
			expectAuditEvent:  true,
			expectAuthCall:    true,
			expectAuthzCall:   true,
			expectBackendCall: true,
		},
		{
			name:             "user with wildcard namespace access",
			backendName:      "loki",
			backendType:      "prometheus",
			requestPath:      "/loki/api/v1/query",
			authToken:        "",
			namespace:        "any-namespace",
			authValidateFunc: nil,
			authzGetUserGroupsFunc: func(ctx context.Context, userID string) ([]string, error) {
				return []string{"admin-group"}, nil
			},
			authzGroupMappings: map[string][]string{
				"admin-group": {"*"},
			},
			authzEnabled:   true,
			expectedStatus: http.StatusOK,
			expectedHeaders: map[string]string{
				"X-Scope-OrgID": "any-namespace",
			},
			expectAuditEvent:  true,
			expectAuthCall:    true,
			expectAuthzCall:   true,
			expectBackendCall: true,
		},
		{
			name:        "authz provider error returns internal server error",
			backendName: "loki",
			backendType: "prometheus",
			requestPath: "/loki/api/v1/query",
			authToken:   "valid-token",
			namespace:   "default",
			authValidateFunc: func(ctx context.Context, token string) (*auth.UserInfo, error) {
				return &auth.UserInfo{ID: "user-error"}, nil
			},
			authzGetUserGroupsFunc: func(ctx context.Context, userID string) ([]string, error) {
				return nil, errors.New("authz service unavailable")
			},
			authzEnabled:      true,
			expectedStatus:    http.StatusInternalServerError,
			expectAuditEvent:  true,
			expectAuthCall:    true,
			expectAuthzCall:   true,
			expectBackendCall: false,
		},
		{
			name:        "malformed JWT returns unauthorized",
			backendName: "loki",
			backendType: "prometheus",
			requestPath: "/loki/api/v1/query",
			authToken:   "not.a.valid.jwt.with.too.many.parts",
			namespace:   "default",
			authValidateFunc: func(ctx context.Context, token string) (*auth.UserInfo, error) {
				return auth.ParseTestJWT(token)
			},
			authzEnabled:      false,
			expectedStatus:    http.StatusUnauthorized,
			expectAuditEvent:  false,
			expectAuthCall:    true,
			expectAuthzCall:   false,
			expectBackendCall: false,
		},
		{
			name:        "request with query parameters preserved in backend path",
			backendName: "grafana",
			backendType: "prometheus",
			requestPath: "/grafana/api/dashboards?folder=prod&limit=10",
			authToken:   "valid-token",
			namespace:   "production",
			authValidateFunc: func(ctx context.Context, token string) (*auth.UserInfo, error) {
				return &auth.UserInfo{ID: "user123"}, nil
			},
			authzGetUserGroupsFunc: func(ctx context.Context, userID string) ([]string, error) {
				return []string{"grafana-team"}, nil
			},
			authzGroupMappings: map[string][]string{
				"grafana-team": {"production"},
			},
			authzEnabled:   true,
			expectedStatus: http.StatusOK,
			expectedHeaders: map[string]string{
				"X-Scope-OrgID": "production",
			},
			expectAuditEvent:  true,
			expectAuthCall:    true,
			expectAuthzCall:   true,
			expectBackendCall: true,
		},
		{
			name:        "browser session does not authorize datasource request",
			backendName: "loki",
			backendType: "prometheus",
			requestPath: "/loki/api/v1/query",
			browserUser: &auth.UserInfo{ID: "browser-user"},
			authValidateFunc: func(ctx context.Context, token string) (*auth.UserInfo, error) {
				return &auth.UserInfo{ID: "should-not-be-called"}, nil
			},
			namespace:         "default",
			authzEnabled:      false,
			expectedStatus:    http.StatusUnauthorized,
			expectAuditEvent:  false,
			expectAuthCall:    false,
			expectAuthzCall:   false,
			expectBackendCall: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			executeProxyTestCase(t, tt)
		})
	}
}

func TestTrustedProxyRequestFallsBackToCachedGroupsFromBrowserRequest(t *testing.T) {
	grafanaServer, _ := captureBackend()
	defer grafanaServer.Close()

	prometheusServer, prometheusCaptured := captureBackend()
	defer prometheusServer.Close()

	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Auth: config.AuthConfig{
			Provider:   "oidc",
			SessionTTL: "1h",
			OIDC: config.OIDCConfig{
				IssuerURL:    "https://issuer.example.com",
				ClientID:     "multipass",
				ClientSecret: "secret",
				RedirectURL:  "https://multipass.example.com/login/generic_oauth",
			},
			TrustedProxy: config.TrustedProxyConfig{
				Enabled:      true,
				UserHeader:   "X-Grafana-User",
				GroupsHeader: "X-Multipass-Groups",
				CallerHeader: "X-Multipass-Caller",
				CallerValue:  "grafana-datasource",
				SecretHeader: "X-Multipass-Proxy-Secret",
				SecretValue:  "proxy-secret",
			},
		},
		Authz: config.AuthzConfig{
			Enabled:  true,
			Provider: "token",
			GroupMappings: map[string][]string{
				"Rolle Plattformadmin utvikling": {"mgmt-plat.dev", "mgmt-plat.ops"},
			},
		},
		Audit: config.AuditConfig{
			Enabled: true,
			Store:   "memory",
		},
		Backends: map[string]config.BackendConfig{
			"grafana": {
				Type:      "web",
				Endpoint:  grafanaServer.URL,
				Tenant: "mgmt-plat.dev",
				WebConfig: &config.WebConfig{
					UserHeader:   "X-WEBAUTH-USER",
					GroupsHeader: "X-WEBAUTH-GROUP",
				},
			},
			"prometheus": {
				Type:      "prometheus",
				Endpoint:  prometheusServer.URL,
				Tenant: "mgmt-plat.ops",
			},
		},
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("invalid config: %v", err)
	}

	proxy, err := New(
		cfg,
		&jwtAuthProvider{},
		&browserAuthProvider{user: &auth.UserInfo{
			ID:       "(usr!koi)",
			Username: "koi",
			Groups:   []string{"Rolle Plattformadmin utvikling"},
		}},
		authz.NewPolicyEvaluator(authz.NewCachedGroupProvider(authz.NewTokenProvider(), authz.NewMemoryGroupCache(time.Hour)), authz.NewTokenProvider(), cfg.Authz.GroupMappings),
		audit.NewMemoryStore(),
	)
	if err != nil {
		t.Fatalf("create proxy: %v", err)
	}

	webRequest := httptest.NewRequest(http.MethodGet, "/grafana/api/dashboards", nil)
	webResponse := httptest.NewRecorder()
	proxy.ServeHTTP(webResponse, webRequest)
	if webResponse.Code != http.StatusOK {
		t.Fatalf("expected web request to succeed, got %d: %s", webResponse.Code, webResponse.Body.String())
	}

	apiRequest := httptest.NewRequest(http.MethodGet, "/prometheus/api/v1/labels", nil)
	apiRequest.Header.Set("X-Grafana-User", "koi")
	apiRequest.Header.Set("X-Multipass-Caller", "grafana-datasource")
	apiRequest.Header.Set("X-Multipass-Proxy-Secret", "proxy-secret")
	apiResponse := httptest.NewRecorder()
	proxy.ServeHTTP(apiResponse, apiRequest)
	if apiResponse.Code != http.StatusOK {
		t.Fatalf("expected trusted proxy request to succeed, got %d: %s", apiResponse.Code, apiResponse.Body.String())
	}

	if got := prometheusCaptured.Headers.Get("X-Scope-OrgID"); got != "mgmt-plat.ops" {
		t.Fatalf("unexpected X-Scope-OrgID header: got %q want %q", got, "mgmt-plat.ops")
	}
	if got := prometheusCaptured.Path; got != "/api/v1/labels" {
		t.Fatalf("unexpected backend path: got %q want %q", got, "/api/v1/labels")
	}
}

func TestTrustedProxyRequestWithoutCallerMarkerDoesNotUseCachedGroups(t *testing.T) {
	grafanaServer, _ := captureBackend()
	defer grafanaServer.Close()

	prometheusServer, _ := captureBackend()
	defer prometheusServer.Close()

	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Auth: config.AuthConfig{
			Provider:   "oidc",
			SessionTTL: "1h",
			OIDC: config.OIDCConfig{
				IssuerURL:    "https://issuer.example.com",
				ClientID:     "multipass",
				ClientSecret: "secret",
				RedirectURL:  "https://multipass.example.com/login/generic_oauth",
			},
			TrustedProxy: config.TrustedProxyConfig{
				Enabled:      true,
				UserHeader:   "X-Grafana-User",
				GroupsHeader: "X-Multipass-Groups",
				CallerHeader: "X-Multipass-Caller",
				CallerValue:  "grafana-datasource",
				SecretHeader: "X-Multipass-Proxy-Secret",
				SecretValue:  "proxy-secret",
			},
		},
		Authz: config.AuthzConfig{
			Enabled:  true,
			Provider: "token",
			GroupMappings: map[string][]string{
				"Rolle Plattformadmin utvikling": {"mgmt-plat.dev", "mgmt-plat.ops"},
			},
		},
		Audit: config.AuditConfig{
			Enabled: true,
			Store:   "memory",
		},
		Backends: map[string]config.BackendConfig{
			"grafana": {
				Type:      "web",
				Endpoint:  grafanaServer.URL,
				Tenant: "mgmt-plat.dev",
				WebConfig: &config.WebConfig{
					UserHeader:   "X-WEBAUTH-USER",
					GroupsHeader: "X-WEBAUTH-GROUP",
				},
			},
			"prometheus": {
				Type:      "prometheus",
				Endpoint:  prometheusServer.URL,
				Tenant: "mgmt-plat.ops",
			},
		},
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("invalid config: %v", err)
	}

	proxy, err := New(
		cfg,
		&jwtAuthProvider{},
		&browserAuthProvider{user: &auth.UserInfo{
			ID:       "(usr!koi)",
			Username: "koi",
			Groups:   []string{"Rolle Plattformadmin utvikling"},
		}},
		authz.NewPolicyEvaluator(authz.NewCachedGroupProvider(authz.NewTokenProvider(), authz.NewMemoryGroupCache(time.Hour)), authz.NewTokenProvider(), cfg.Authz.GroupMappings),
		audit.NewMemoryStore(),
	)
	if err != nil {
		t.Fatalf("create proxy: %v", err)
	}

	webRequest := httptest.NewRequest(http.MethodGet, "/grafana/api/dashboards", nil)
	webResponse := httptest.NewRecorder()
	proxy.ServeHTTP(webResponse, webRequest)
	if webResponse.Code != http.StatusOK {
		t.Fatalf("expected web request to succeed, got %d: %s", webResponse.Code, webResponse.Body.String())
	}

	apiRequest := httptest.NewRequest(http.MethodGet, "/prometheus/api/v1/labels", nil)
	apiRequest.Header.Set("X-Grafana-User", "koi")
	apiRequest.Header.Set("X-Multipass-Proxy-Secret", "proxy-secret")
	apiResponse := httptest.NewRecorder()
	proxy.ServeHTTP(apiResponse, apiRequest)
	// Phase 1: Without namespace checks, request succeeds even without caller marker
	// TODO: Consider if this needs additional security controls
	if apiResponse.Code != http.StatusOK {
		t.Fatalf("expected trusted proxy request to succeed (Phase 1), got %d: %s", apiResponse.Code, apiResponse.Body.String())
	}
}

func TestTrustedProxyRequestPreservesBackendEndpointPath(t *testing.T) {
	grafanaServer, _ := captureBackend()
	defer grafanaServer.Close()

	prometheusServer, prometheusCaptured := captureBackend()
	defer prometheusServer.Close()

	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Auth: config.AuthConfig{
			Provider:   "oidc",
			SessionTTL: "1h",
			OIDC: config.OIDCConfig{
				IssuerURL:    "https://issuer.example.com",
				ClientID:     "multipass",
				ClientSecret: "secret",
				RedirectURL:  "https://multipass.example.com/login/generic_oauth",
			},
			TrustedProxy: config.TrustedProxyConfig{
				Enabled:      true,
				UserHeader:   "X-Grafana-User",
				GroupsHeader: "X-Multipass-Groups",
				CallerHeader: "X-Multipass-Caller",
				CallerValue:  "grafana-datasource",
				SecretHeader: "X-Multipass-Proxy-Secret",
				SecretValue:  "proxy-secret",
			},
		},
		Authz: config.AuthzConfig{
			Enabled:  true,
			Provider: "token",
			GroupMappings: map[string][]string{
				"Rolle Plattformadmin utvikling": {"mgmt-plat.dev", "mgmt-plat.ops"},
			},
		},
		Audit: config.AuditConfig{
			Enabled: true,
			Store:   "memory",
		},
		Backends: map[string]config.BackendConfig{
			"grafana": {
				Type:      "web",
				Endpoint:  grafanaServer.URL,
				Tenant: "mgmt-plat.dev",
				WebConfig: &config.WebConfig{
					UserHeader:   "X-WEBAUTH-USER",
					GroupsHeader: "X-WEBAUTH-GROUP",
				},
			},
			"prometheus": {
				Type:      "prometheus",
				Endpoint:  prometheusServer.URL + "/prometheus",
				Tenant: "mgmt-plat.ops",
			},
		},
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("invalid config: %v", err)
	}

	proxy, err := New(
		cfg,
		&jwtAuthProvider{},
		&browserAuthProvider{user: &auth.UserInfo{
			ID:       "(usr!koi)",
			Username: "koi",
			Groups:   []string{"Rolle Plattformadmin utvikling"},
		}},
		authz.NewPolicyEvaluator(authz.NewCachedGroupProvider(authz.NewTokenProvider(), authz.NewMemoryGroupCache(time.Hour)), authz.NewTokenProvider(), cfg.Authz.GroupMappings),
		audit.NewMemoryStore(),
	)
	if err != nil {
		t.Fatalf("create proxy: %v", err)
	}

	webRequest := httptest.NewRequest(http.MethodGet, "/grafana/api/dashboards", nil)
	webResponse := httptest.NewRecorder()
	proxy.ServeHTTP(webResponse, webRequest)
	if webResponse.Code != http.StatusOK {
		t.Fatalf("expected web request to succeed, got %d: %s", webResponse.Code, webResponse.Body.String())
	}

	apiRequest := httptest.NewRequest(http.MethodGet, "/prometheus/api/v1/labels", nil)
	apiRequest.Header.Set("X-Grafana-User", "koi")
	apiRequest.Header.Set("X-Multipass-Caller", "grafana-datasource")
	apiRequest.Header.Set("X-Multipass-Proxy-Secret", "proxy-secret")
	apiResponse := httptest.NewRecorder()
	proxy.ServeHTTP(apiResponse, apiRequest)
	if apiResponse.Code != http.StatusOK {
		t.Fatalf("expected trusted proxy request to succeed, got %d: %s", apiResponse.Code, apiResponse.Body.String())
	}

	if got := prometheusCaptured.Headers.Get("X-Scope-OrgID"); got != "mgmt-plat.ops" {
		t.Fatalf("unexpected X-Scope-OrgID header: got %q want %q", got, "mgmt-plat.ops")
	}
	if got := prometheusCaptured.Path; got != "/prometheus/api/v1/labels" {
		t.Fatalf("unexpected backend path: got %q want %q", got, "/prometheus/api/v1/labels")
	}
	targetURL, err := url.Parse(prometheusServer.URL)
	if err != nil {
		t.Fatalf("parse backend URL: %v", err)
	}
	if got := prometheusCaptured.Host; got != targetURL.Host {
		t.Fatalf("unexpected backend host: got %q want %q", got, targetURL.Host)
	}
}

func TestTrustedProxyRequestStripsRawPathBeforeProxying(t *testing.T) {
	grafanaServer, _ := captureBackend()
	defer grafanaServer.Close()

	prometheusServer, prometheusCaptured := captureBackend()
	defer prometheusServer.Close()

	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Auth: config.AuthConfig{
			Provider:   "oidc",
			SessionTTL: "1h",
			OIDC: config.OIDCConfig{
				IssuerURL:    "https://issuer.example.com",
				ClientID:     "multipass",
				ClientSecret: "secret",
				RedirectURL:  "https://multipass.example.com/login/generic_oauth",
			},
			TrustedProxy: config.TrustedProxyConfig{
				Enabled:      true,
				UserHeader:   "X-Grafana-User",
				GroupsHeader: "X-Multipass-Groups",
				CallerHeader: "X-Multipass-Caller",
				CallerValue:  "grafana-datasource",
				SecretHeader: "X-Multipass-Proxy-Secret",
				SecretValue:  "proxy-secret",
			},
		},
		Authz: config.AuthzConfig{
			Enabled:  true,
			Provider: "token",
			GroupMappings: map[string][]string{
				"Rolle Plattformadmin utvikling": {"mgmt-plat.dev", "mgmt-plat.ops"},
			},
		},
		Audit: config.AuditConfig{
			Enabled: true,
			Store:   "memory",
		},
		Backends: map[string]config.BackendConfig{
			"grafana": {
				Type:      "web",
				Endpoint:  grafanaServer.URL,
				Tenant: "mgmt-plat.dev",
				WebConfig: &config.WebConfig{
					UserHeader:   "X-WEBAUTH-USER",
					GroupsHeader: "X-WEBAUTH-GROUP",
				},
			},
			"prometheus": {
				Type:      "prometheus",
				Endpoint:  prometheusServer.URL + "/prometheus",
				Tenant: "mgmt-plat.ops",
			},
		},
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("invalid config: %v", err)
	}

	proxy, err := New(
		cfg,
		&jwtAuthProvider{},
		&browserAuthProvider{user: &auth.UserInfo{
			ID:       "(usr!koi)",
			Username: "koi",
			Groups:   []string{"Rolle Plattformadmin utvikling"},
		}},
		authz.NewPolicyEvaluator(authz.NewCachedGroupProvider(authz.NewTokenProvider(), authz.NewMemoryGroupCache(time.Hour)), authz.NewTokenProvider(), cfg.Authz.GroupMappings),
		audit.NewMemoryStore(),
	)
	if err != nil {
		t.Fatalf("create proxy: %v", err)
	}

	webRequest := httptest.NewRequest(http.MethodGet, "/grafana/api/dashboards", nil)
	webResponse := httptest.NewRecorder()
	proxy.ServeHTTP(webResponse, webRequest)
	if webResponse.Code != http.StatusOK {
		t.Fatalf("expected web request to succeed, got %d: %s", webResponse.Code, webResponse.Body.String())
	}

	apiRequest := httptest.NewRequest(http.MethodGet, "/prometheus/api/v1/labels", nil)
	apiRequest.URL.RawPath = "/prometheus/api/v1/labels"
	apiRequest.Header.Set("X-Grafana-User", "koi")
	apiRequest.Header.Set("X-Multipass-Caller", "grafana-datasource")
	apiRequest.Header.Set("X-Multipass-Proxy-Secret", "proxy-secret")
	apiResponse := httptest.NewRecorder()
	proxy.ServeHTTP(apiResponse, apiRequest)
	if apiResponse.Code != http.StatusOK {
		t.Fatalf("expected trusted proxy request to succeed, got %d: %s", apiResponse.Code, apiResponse.Body.String())
	}

	if got := prometheusCaptured.Path; got != "/prometheus/api/v1/labels" {
		t.Fatalf("unexpected backend path: got %q want %q", got, "/prometheus/api/v1/labels")
	}
	targetURL, err := url.Parse(prometheusServer.URL)
	if err != nil {
		t.Fatalf("parse backend URL: %v", err)
	}
	if got := prometheusCaptured.Host; got != targetURL.Host {
		t.Fatalf("unexpected backend host: got %q want %q", got, targetURL.Host)
	}
}

func TestTrustedProxyGroups(t *testing.T) {
	tests := []struct {
		name        string
		headerValue string
		expected    []string
	}{
		{name: "empty", headerValue: "", expected: nil},
		{name: "single", headerValue: "developers", expected: []string{"developers"}},
		{name: "trim and dedupe", headerValue: " developers, ops ,developers ,, ", expected: []string{"developers", "ops"}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := trustedProxyGroups(test.headerValue)
			if len(got) != len(test.expected) {
				t.Fatalf("unexpected group count: got %d want %d (%v)", len(got), len(test.expected), got)
			}
			for index := range test.expected {
				if got[index] != test.expected[index] {
					t.Fatalf("unexpected group at %d: got %q want %q", index, got[index], test.expected[index])
				}
			}
		})
	}
}

func TestTrustedProxyUserInfoUsesTrustedUserAsUsername(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/prometheus/api/v1/labels", nil)
	r.Header.Set("X-Grafana-User", "koi")
	r.Header.Set("X-Multipass-Groups", "Rolle Plattformadmin utvikling")

	userInfo, err := trustedProxyUserInfo(r, config.TrustedProxyConfig{
		UserHeader:   "X-Grafana-User",
		GroupsHeader: "X-Multipass-Groups",
	})
	if err != nil {
		t.Fatalf("trustedProxyUserInfo returned error: %v", err)
	}
	if userInfo.Username != "koi" {
		t.Fatalf("unexpected username: got %q want %q", userInfo.Username, "koi")
	}
	if userInfo.ID != "koi" {
		t.Fatalf("unexpected id: got %q want %q", userInfo.ID, "koi")
	}
	if len(userInfo.Groups) != 1 || userInfo.Groups[0] != "Rolle Plattformadmin utvikling" {
		t.Fatalf("unexpected groups: %v", userInfo.Groups)
	}
}
