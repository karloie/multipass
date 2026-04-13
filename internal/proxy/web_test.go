package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/karloie/multipass/internal/auth"
	"github.com/karloie/multipass/internal/authz"
)

func TestResolveWebRoleInputsIncludesExternalGroupsWhenInternalRolesPresent(t *testing.T) {
	user := &auth.UserInfo{Groups: []string{"App-Grafana-Editors", "Rolle Utvikler"}}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(context.WithValue(req.Context(), permissionsKey, &authz.Permission{
		InternalRoles:  []string{"dev", "devops"},
		ExternalGroups: []string{"App-Grafana-Editors", "Rolle Utvikler"},
	}))

	inputs := resolveWebRoleInputs(req, user)
	role := resolveMappedRole(inputs, map[string]string{
		"App-Grafana-Editors": "Editor",
	})

	if role != "Editor" {
		t.Fatalf("expected Editor role from external App-Grafana-* group, got %q (inputs=%v)", role, inputs)
	}
}

func TestWebBackends(t *testing.T) {
	tests := []proxyTestCase{
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
