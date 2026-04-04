package status

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/karloie/multipass/internal/auth"
	"github.com/karloie/multipass/internal/authz"
	"github.com/karloie/multipass/internal/config"
)

type fakeBrowserAuthenticator struct {
	user *auth.UserInfo
}

func (f fakeBrowserAuthenticator) AuthenticateRequest(_ *http.Request) (*auth.UserInfo, bool) {
	if f.user == nil {
		return nil, false
	}
	return f.user, true
}

type fakePermissionEvaluator struct {
	permission *authz.Permission
	err        error
}

func (f fakePermissionEvaluator) EvaluatePermissions(_ context.Context, _ *auth.UserInfo) (*authz.Permission, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.permission, nil
}

func (f fakePermissionEvaluator) CanAccessNamespace(_ context.Context, _ *auth.UserInfo, _ string) (bool, error) {
	return false, nil
}

func TestEnabled(t *testing.T) {
	if !Enabled(&config.Config{Auth: config.AuthConfig{Provider: "oidc"}}) {
		t.Fatal("expected status endpoint to be enabled when config is present")
	}
	if Enabled(nil) {
		t.Fatal("expected status endpoint to be disabled for nil config")
	}
}

func TestHandlerReportsConfiguredProviders(t *testing.T) {
	discoveryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/issuer/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"issuer":"` + discoveryServerURL(r) + `"}`))
	}))
	defer discoveryServer.Close()

	cfg := &config.Config{
		Auth: config.AuthConfig{
			Provider: "oidc",
			OIDC: config.OIDCConfig{
				IssuerURL: strings.TrimRight(discoveryServer.URL, "/") + "/issuer",
				ClientID:  "multipass",
			},
		},
		Authz: config.AuthzConfig{
			Enabled:  true,
			Provider: "token",
		},
	}

	handler := &Handler{
		config:      cfg,
		httpClient:  discoveryServer.Client(),
		browserAuth: fakeBrowserAuthenticator{},
	}

	req := httptest.NewRequest(http.MethodGet, "/status", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rr.Code)
	}

	var got response
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if got.Mode != "live" {
		t.Fatalf("expected live mode, got %q", got.Mode)
	}
	if got.Auth.Provider != "oidc" {
		t.Fatalf("expected oidc auth provider, got %q", got.Auth.Provider)
	}
	if !got.Checks.OIDC.Reachable {
		t.Fatalf("expected oidc discovery to be reachable, got %+v", got.Checks.OIDC)
	}
	if len(got.Issues) != 0 {
		t.Fatalf("expected no issues, got %v", got.Issues)
	}
	if got.CurrentUser.Authenticated {
		t.Fatalf("expected no authenticated current user, got %+v", got.CurrentUser)
	}
}

func TestHandlerReportsOIDCProbeFailure(t *testing.T) {
	cfg := &config.Config{
		Auth: config.AuthConfig{
			Provider: "oidc",
			OIDC: config.OIDCConfig{
				IssuerURL: "http://127.0.0.1:1/issuer",
			},
		},
		Authz: config.AuthzConfig{
			Enabled:  true,
			Provider: "token",
		},
	}

	handler := &Handler{
		config:      cfg,
		httpClient:  &http.Client{},
		browserAuth: fakeBrowserAuthenticator{},
	}

	req := httptest.NewRequest(http.MethodGet, "/status", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	var got response
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if got.Checks.OIDC.Reachable {
		t.Fatalf("expected oidc probe failure, got %+v", got.Checks.OIDC)
	}
	if len(got.Issues) != 1 {
		t.Fatalf("expected 1 issue, got %v", got.Issues)
	}
}

func TestHandlerReportsCurrentUserGroups(t *testing.T) {
	cfg := &config.Config{
		Auth: config.AuthConfig{Provider: "oidc"},
		Authz: config.AuthzConfig{
			Enabled:  true,
			Provider: "token",
		},
	}

	handler := &Handler{
		config: cfg,
		browserAuth: fakeBrowserAuthenticator{user: &auth.UserInfo{
			ID:          "karl@example.com",
			Username:    "karl",
			PrincipalID: "25d840f5-6852-4f88-8d8c-d7e7a192c3ab",
			TenantID:    "2c82ac4f-a070-4e0a-8bff-c303ffd6fe79",
			Email:       "karl@example.com",
			Name:        "Karl Example",
		}},
		authzEvaluator: fakePermissionEvaluator{permission: &authz.Permission{
			ExternalGroups:    []string{"Rolle Utvikler", "Rolle Plattformadmin utvikling"},
			InternalRoles:     []string{"dev", "admin"},
			AllowedNamespaces: []string{"default", "monitoring"},
			ElevatedRoles:     []authz.ElevatedRole{{Role: "Reader"}},
		}},
		httpClient: &http.Client{},
	}

	req := httptest.NewRequest(http.MethodGet, "/status", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	var got response
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if !got.CurrentUser.Authenticated {
		t.Fatalf("expected current user to be authenticated, got %+v", got.CurrentUser)
	}
	if got.CurrentUser.ID != "karl@example.com" {
		t.Fatalf("unexpected current user id %q", got.CurrentUser.ID)
	}
	if got.CurrentUser.Username != "karl" {
		t.Fatalf("unexpected current user username %q", got.CurrentUser.Username)
	}
	if !reflect.DeepEqual(got.CurrentUser.ExternalGroups, []string{"Rolle Utvikler", "Rolle Plattformadmin utvikling"}) {
		t.Fatalf("expected external groups, got %+v", got.CurrentUser.ExternalGroups)
	}
	if !reflect.DeepEqual(got.CurrentUser.InternalRoles, []string{"dev", "admin"}) {
		t.Fatalf("expected internal roles, got %+v", got.CurrentUser.InternalRoles)
	}
	if !reflect.DeepEqual(got.CurrentUser.RawAllowedNamespaces, []string{"default", "monitoring"}) {
		t.Fatalf("expected raw namespaces, got %+v", got.CurrentUser.RawAllowedNamespaces)
	}
	if len(got.CurrentUser.AllowedNamespaces) != 2 {
		t.Fatalf("expected 2 namespaces, got %+v", got.CurrentUser.AllowedNamespaces)
	}
	if len(got.CurrentUser.ElevatedRoles) != 1 || got.CurrentUser.ElevatedRoles[0] != "Reader" {
		t.Fatalf("expected current user roles, got %+v", got.CurrentUser.ElevatedRoles)
	}
	if got.CurrentUser.PermissionsError != "" {
		t.Fatalf("expected no permission error, got %q", got.CurrentUser.PermissionsError)
	}
}

func TestHandlerReportsDerivedAllowedNamespaces(t *testing.T) {
	cfg := &config.Config{
		Auth: config.AuthConfig{Provider: "oidc"},
		Authz: config.AuthzConfig{
			Enabled:  true,
			Provider: "token",
			ClusterResolver: config.ClusterResolverConfig{
				Source: "user",
				Mappings: map[string]string{
					"otel-collector-core-test": "core-test",
				},
			},
			NamespaceClassifier: config.NamespaceClassifierConfig{
				DefaultSegment: "dev",
				OpsExact:       []string{"argocd"},
			},
		},
	}

	handler := &Handler{
		config: cfg,
		browserAuth: fakeBrowserAuthenticator{user: &auth.UserInfo{
			ID: "otel-collector-core-test",
		}},
		authzEvaluator: fakePermissionEvaluator{permission: &authz.Permission{
			AllowedNamespaces: []string{"argocd", "team-a"},
		}},
		httpClient: &http.Client{},
	}

	got := executeStatusRequest(t, handler)
	wantRawNamespaces := []string{"argocd", "team-a"}
	wantNamespaces := []string{"core-test.dev", "core-test.ops"}
	if !reflect.DeepEqual(got.CurrentUser.RawAllowedNamespaces, wantRawNamespaces) {
		t.Fatalf("unexpected raw namespaces: got %+v want %+v", got.CurrentUser.RawAllowedNamespaces, wantRawNamespaces)
	}
	if !reflect.DeepEqual(got.CurrentUser.AllowedNamespaces, wantNamespaces) {
		t.Fatalf("unexpected derived namespaces: got %+v want %+v", got.CurrentUser.AllowedNamespaces, wantNamespaces)
	}
}

func TestHandlerKeepsDerivedAllowedNamespacesStable(t *testing.T) {
	cfg := &config.Config{
		Auth: config.AuthConfig{Provider: "oidc"},
		Authz: config.AuthzConfig{
			Enabled:  true,
			Provider: "token",
			ClusterResolver: config.ClusterResolverConfig{
				Source: "user",
				Mappings: map[string]string{
					"otel-collector-core-test": "core-test",
				},
			},
			NamespaceClassifier: config.NamespaceClassifierConfig{
				DefaultSegment: "dev",
				OpsExact:       []string{"argocd"},
			},
		},
	}

	handler := &Handler{
		config: cfg,
		browserAuth: fakeBrowserAuthenticator{user: &auth.UserInfo{
			ID: "otel-collector-core-test",
		}},
		authzEvaluator: fakePermissionEvaluator{permission: &authz.Permission{
			AllowedNamespaces: []string{"core-test.ops"},
		}},
		httpClient: &http.Client{},
	}

	got := executeStatusRequest(t, handler)
	wantRawNamespaces := []string{"core-test.ops"}
	wantNamespaces := []string{"core-test.ops"}
	if !reflect.DeepEqual(got.CurrentUser.RawAllowedNamespaces, wantRawNamespaces) {
		t.Fatalf("unexpected raw namespaces: got %+v want %+v", got.CurrentUser.RawAllowedNamespaces, wantRawNamespaces)
	}
	if !reflect.DeepEqual(got.CurrentUser.AllowedNamespaces, wantNamespaces) {
		t.Fatalf("unexpected stable namespaces: got %+v want %+v", got.CurrentUser.AllowedNamespaces, wantNamespaces)
	}
}

func TestHandlerDerivesAllowedNamespacesFromBackendCluster(t *testing.T) {
	cfg := &config.Config{
		Auth: config.AuthConfig{Provider: "oidc"},
		Authz: config.AuthzConfig{
			Enabled:  true,
			Provider: "token",
			NamespaceClassifier: config.NamespaceClassifierConfig{
				DefaultSegment: "dev",
				OpsExact:       []string{"monitoring"},
			},
		},
		Backends: map[string]config.BackendConfig{
			"mimir-core-test": {
				Namespace: "core-test",
				NamespaceRouting: &config.NamespaceRoutingConfig{
					Mode:      "request",
					Parameter: "tm_namespace",
				},
			},
			"mimir-tool-test": {
				Namespace: "tool-test",
				NamespaceRouting: &config.NamespaceRoutingConfig{
					Mode:      "request",
					Parameter: "tm_namespace",
				},
			},
		},
	}

	handler := &Handler{
		config: cfg,
		browserAuth: fakeBrowserAuthenticator{user: &auth.UserInfo{
			ID: "karl@example.com",
		}},
		authzEvaluator: fakePermissionEvaluator{permission: &authz.Permission{
			AllowedNamespaces: []string{"monitoring"},
		}},
		httpClient: &http.Client{},
	}

	got := executeStatusRequest(t, handler)
	wantRawNamespaces := []string{"monitoring"}
	wantNamespaces := []string{"core-test.ops", "tool-test.ops"}
	if !reflect.DeepEqual(got.CurrentUser.RawAllowedNamespaces, wantRawNamespaces) {
		t.Fatalf("unexpected raw namespaces: got %+v want %+v", got.CurrentUser.RawAllowedNamespaces, wantRawNamespaces)
	}
	if !reflect.DeepEqual(got.CurrentUser.AllowedNamespaces, wantNamespaces) {
		t.Fatalf("unexpected backend-derived namespaces: got %+v want %+v", got.CurrentUser.AllowedNamespaces, wantNamespaces)
	}
}

func executeStatusRequest(t *testing.T, handler *Handler) response {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, "/status", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rr.Code)
	}

	var got response
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	return got
}

func discoveryServerURL(r *http.Request) string {
	return "http://" + r.Host + "/issuer"
}
