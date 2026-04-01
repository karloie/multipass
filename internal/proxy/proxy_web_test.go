package proxy

import (
	"context"
	"net/http"
	"testing"

	"github.com/karloie/multipass/internal/auth"
	"github.com/karloie/multipass/internal/config"
)

func TestProxy_WebBackends(t *testing.T) {
	tests := []proxyTestCase{
		{
			name:        "web backend with user identity headers",
			backendName: "grafana",
			backendType: "web",
			requestPath: "/grafana/api/dashboards",
			browserUser: &auth.UserInfo{
				ID:       "user123",
				Username: "test-user",
				Email:    "user@example.com",
				Name:     "Test User",
			},
			namespace:    "default",
			authzEnabled: false,
			webConfig: &config.WebConfig{
				UserHeader:  "X-WEBAUTH-USER",
				EmailHeader: "X-WEBAUTH-EMAIL",
				NameHeader:  "X-WEBAUTH-NAME",
			},
			expectedStatus: http.StatusOK,
			expectedHeaders: map[string]string{
				"X-WEBAUTH-USER":  "test-user",
				"X-WEBAUTH-EMAIL": "user@example.com",
				"X-WEBAUTH-NAME":  "Test User",
			},
			expectAuditEvent:    true,
			expectAuthCall:      false,
			expectAuthzCall:     false,
			expectBackendCall:   true,
			expectedBackendPath: "/api/dashboards",
		},
		{
			name:         "web backend with partial user info (no email/name)",
			backendName:  "kibana",
			backendType:  "web",
			requestPath:  "/kibana/app/dashboards",
			browserUser:  &auth.UserInfo{ID: "user456"},
			namespace:    "default",
			authzEnabled: false,
			webConfig: &config.WebConfig{
				UserHeader:  "X-Proxy-User",
				EmailHeader: "X-Proxy-Email",
				NameHeader:  "X-Proxy-Name",
			},
			expectedStatus: http.StatusOK,
			expectedHeaders: map[string]string{
				"X-Proxy-User": "user456",
				// Email and Name headers should not be set
			},
			expectAuditEvent:    true,
			expectAuthCall:      false,
			expectAuthzCall:     false,
			expectBackendCall:   true,
			expectedBackendPath: "/app/dashboards",
		},
		{
			name:        "web backend without web config (no headers injected)",
			backendName: "custom-ui",
			backendType: "web",
			requestPath: "/custom-ui/api",
			browserUser: &auth.UserInfo{
				ID:    "user789",
				Email: "test@example.com",
			},
			namespace:       "default",
			authzEnabled:    false,
			webConfig:       nil, // No web config
			expectedStatus:  http.StatusOK,
			expectedHeaders: map[string]string{
				// No user headers should be set
			},
			expectAuditEvent:    true,
			expectAuthCall:      false,
			expectAuthzCall:     false,
			expectBackendCall:   true,
			expectedBackendPath: "/api",
		},
		{
			name:        "web backend with JWT groups and derived role when authz disabled",
			backendName: "grafana-role-from-jwt",
			backendType: "web",
			requestPath: "/grafana-role-from-jwt/",
			browserUser: &auth.UserInfo{
				ID:       "user-role-from-jwt",
				Username: "editor-user",
				Email:    "editor@example.com",
				Groups:   []string{"App-Grafana-Editors"},
			},
			authzEnabled: false,
			webConfig: &config.WebConfig{
				UserHeader:   "X-WEBAUTH-USER",
				GroupsHeader: "X-WEBAUTH-GROUP",
				RoleHeader:   "X-WEBAUTH-ROLE",
				RoleMappings: map[string]string{
					"App-Grafana-Admins":  "GrafanaAdmin",
					"App-Grafana-Editors": "Editor",
				},
			},
			expectedStatus: http.StatusOK,
			expectedHeaders: map[string]string{
				"X-WEBAUTH-USER":  "editor-user",
				"X-WEBAUTH-GROUP": "App-Grafana-Editors",
				"X-WEBAUTH-ROLE":  "Editor",
			},
			expectAuditEvent:    true,
			expectAuthCall:      false,
			expectAuthzCall:     false,
			expectBackendCall:   true,
			expectedBackendPath: "/",
		},
		{
			name:        "web backend with groups header and authz enabled",
			backendName: "grafana-groups",
			backendType: "web",
			requestPath: "/grafana-groups/api/dashboards",
			browserUser: &auth.UserInfo{
				ID:       "user-with-groups",
				Username: "admin-user",
				Email:    "admin@example.com",
				Name:     "Admin User",
			},
			namespace: "production",
			authzGetUserGroupsFunc: func(ctx context.Context, userID string) ([]string, error) {
				return []string{"team-platform", "team-sre", "admins"}, nil
			},
			authzGroupMappings: map[string][]string{
				"team-platform": {"dev", "test", "production"},
				"team-sre":      {"production"},
				"admins":        {"*"},
			},
			authzEnabled: true,
			webConfig: &config.WebConfig{
				UserHeader:   "X-WEBAUTH-USER",
				EmailHeader:  "X-WEBAUTH-EMAIL",
				NameHeader:   "X-WEBAUTH-NAME",
				GroupsHeader: "X-WEBAUTH-GROUP",
				RoleHeader:   "X-WEBAUTH-ROLE",
				RoleMappings: map[string]string{
					"admins":        "GrafanaAdmin",
					"team-platform": "Editor",
				},
			},
			expectedStatus: http.StatusOK,
			expectedHeaders: map[string]string{
				"X-WEBAUTH-USER":  "admin-user",
				"X-WEBAUTH-EMAIL": "admin@example.com",
				"X-WEBAUTH-NAME":  "Admin User",
				"X-WEBAUTH-GROUP": "team-platform,team-sre,admins",
				"X-WEBAUTH-ROLE":  "GrafanaAdmin",
			},
			expectAuditEvent:    true,
			expectAuthCall:      false,
			expectAuthzCall:     true,
			expectBackendCall:   true,
			expectedBackendPath: "/api/dashboards",
		},
		{
			name:        "web backend with groups header but authz disabled (no groups)",
			backendName: "grafana-no-authz",
			backendType: "web",
			requestPath: "/grafana-no-authz/api/dashboards",
			browserUser: &auth.UserInfo{
				ID:    "user-no-authz",
				Email: "user@example.com",
			},
			namespace:    "default",
			authzEnabled: false,
			webConfig: &config.WebConfig{
				UserHeader:   "X-WEBAUTH-USER",
				GroupsHeader: "X-WEBAUTH-GROUP",
				RoleHeader:   "X-WEBAUTH-ROLE",
				RoleMappings: map[string]string{
					"App-Grafana-Editors": "Editor",
				},
			},
			expectedStatus: http.StatusOK,
			expectedHeaders: map[string]string{
				"X-WEBAUTH-USER": "user-no-authz",
				// X-WEBAUTH-GROUP should NOT be set (authz disabled, no permissions in context)
			},
			expectAuditEvent:    true,
			expectAuthCall:      false,
			expectAuthzCall:     false,
			expectBackendCall:   true,
			expectedBackendPath: "/api/dashboards",
		},
		{
			name:              "web backend redirects to login when browser session missing",
			backendName:       "grafana-login",
			backendType:       "web",
			requestPath:       "/grafana-login/",
			namespace:         "",
			authzEnabled:      false,
			expectedStatus:    http.StatusFound,
			expectedLocation:  "/login?return_to=/grafana-login/",
			expectAuditEvent:  false,
			expectAuthCall:    false,
			expectAuthzCall:   false,
			expectBackendCall: false,
		},
		{
			name:        "host-based web backend serves root path without backend prefix",
			backendName: "grafana-host",
			backendType: "web",
			requestPath: "/",
			host:        "lgtm.example.com",
			browserUser: &auth.UserInfo{
				ID:       "user123",
				Username: "host-user",
				Email:    "user@example.com",
			},
			webConfig: &config.WebConfig{
				UserHeader:  "X-WEBAUTH-USER",
				EmailHeader: "X-WEBAUTH-EMAIL",
			},
			expectedStatus: http.StatusOK,
			expectedHeaders: map[string]string{
				"X-WEBAUTH-USER":  "host-user",
				"X-WEBAUTH-EMAIL": "user@example.com",
			},
			expectAuditEvent:    true,
			expectAuthCall:      false,
			expectAuthzCall:     false,
			expectBackendCall:   true,
			expectedBackendPath: "/",
		},
		{
			name:              "host-based web backend redirects to login with original external path",
			backendName:       "opensearch-host",
			backendType:       "web",
			requestPath:       "/app/home",
			host:              "opensearch.example.com",
			expectedStatus:    http.StatusFound,
			expectedLocation:  "/login?return_to=/app/home",
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
