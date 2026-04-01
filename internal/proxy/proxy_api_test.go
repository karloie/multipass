package proxy

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/karloie/multipass/internal/auth"
	"github.com/karloie/multipass/internal/config"
)

func TestProxy_ApiBackends(t *testing.T) {
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
			requestPath: "/mimir/api/v1/query?tm_namespace=utv&query=up",
			backendNamespaceRouting: &config.NamespaceRoutingConfig{
				Mode:      "request",
				Parameter: "tm_namespace",
			},
			authToken: "valid-token",
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
			expectedAuditNamespace: "utv",
			expectAuditEvent:       true,
			expectAuthCall:         true,
			expectAuthzCall:        true,
			expectBackendCall:      true,
		},
		{
			name:             "request-routed Prometheus backend classifies raw namespace into cluster scope",
			backendName:      "mimir",
			backendType:      "prometheus",
			backendNamespace: "core-test",
			requestPath:      "/mimir/api/v1/query?tm_namespace=argocd&query=up",
			backendNamespaceRouting: &config.NamespaceRoutingConfig{
				Mode:      "request",
				Parameter: "tm_namespace",
			},
			authzNamespaceClassifier: &config.NamespaceClassifierConfig{
				DefaultSegment: "dev",
				OpsExact:       []string{"argocd"},
			},
			authToken: "valid-token",
			authValidateFunc: func(ctx context.Context, token string) (*auth.UserInfo, error) {
				return &auth.UserInfo{ID: "user-request-classified"}, nil
			},
			authzGetUserGroupsFunc: func(ctx context.Context, userID string) ([]string, error) {
				return []string{"platform-ops"}, nil
			},
			authzGroupMappings: map[string][]string{
				"platform-ops": {"core-test.ops"},
			},
			authzEnabled:           true,
			expectedStatus:         http.StatusOK,
			expectedHeaders:        map[string]string{"X-Scope-OrgID": "core-test.ops"},
			expectedBackendQuery:   "query=up",
			expectedAuditNamespace: "core-test.ops",
			expectAuditEvent:       true,
			expectAuthCall:         true,
			expectAuthzCall:        true,
			expectBackendCall:      true,
		},
		{
			name:        "request-routed Prometheus backend denies forbidden namespace",
			backendName: "mimir",
			backendType: "prometheus",
			requestPath: "/mimir/api/v1/query?tm_namespace=monitoring&query=up",
			backendNamespaceRouting: &config.NamespaceRoutingConfig{
				Mode:      "request",
				Parameter: "tm_namespace",
			},
			authToken: "valid-token",
			authValidateFunc: func(ctx context.Context, token string) (*auth.UserInfo, error) {
				return &auth.UserInfo{ID: "user-request-deny"}, nil
			},
			authzGetUserGroupsFunc: func(ctx context.Context, userID string) ([]string, error) {
				return []string{"utv-team"}, nil
			},
			authzGroupMappings: map[string][]string{
				"utv-team": {"utv"},
			},
			authzEnabled:           true,
			expectedStatus:         http.StatusForbidden,
			expectedAuditNamespace: "monitoring",
			expectAuditEvent:       true,
			expectAuthCall:         true,
			expectAuthzCall:        true,
			expectBackendCall:      false,
		},
		{
			name:        "request-routed Prometheus backend requires namespace parameter",
			backendName: "mimir",
			backendType: "prometheus",
			requestPath: "/mimir/api/v1/query?query=up",
			backendNamespaceRouting: &config.NamespaceRoutingConfig{
				Mode:      "request",
				Parameter: "tm_namespace",
			},
			authToken: "valid-token",
			authValidateFunc: func(ctx context.Context, token string) (*auth.UserInfo, error) {
				return &auth.UserInfo{ID: "user-request-missing"}, nil
			},
			authzEnabled:      true,
			expectedStatus:    http.StatusBadRequest,
			expectAuditEvent:  false,
			expectAuthCall:    true,
			expectAuthzCall:   false,
			expectBackendCall: false,
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
			name:        "authorization denied - namespace not allowed",
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
			authzEnabled:      true,
			expectedStatus:    http.StatusForbidden,
			expectAuditEvent:  true,
			expectAuthCall:    true,
			expectAuthzCall:   true,
			expectBackendCall: false,
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
