package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/karloie/multipass/internal/audit"
	"github.com/karloie/multipass/internal/auth"
	"github.com/karloie/multipass/internal/authz"
	"github.com/karloie/multipass/internal/config"
	queryrewrite "github.com/karloie/multipass/internal/query"
)

const testRequestRoutingParameter = "tm_namespace"

func requestNamespaceRouting(source string) *config.NamespaceRoutingConfig {
	routing := &config.NamespaceRoutingConfig{
		Mode:      namespaceRoutingModeRequest,
		Parameter: testRequestRoutingParameter,
	}
	if source != "" {
		routing.Source = source
	}
	return routing
}

// createTestJWT creates a simple unsigned JWT for testing.
// This exercises real JWT parsing code without requiring signature verification.
func createTestJWT(userID string) string {
	header := map[string]interface{}{
		"alg": "none",
		"typ": "JWT",
	}
	headerJSON, _ := json.Marshal(header)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)

	payload := map[string]interface{}{
		"sub": userID,
		"aud": "test-client",
		"iss": "https://test-issuer.example.com",
		"exp": 9999999999,
	}
	payloadJSON, _ := json.Marshal(payload)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	return fmt.Sprintf("%s.%s.", headerB64, payloadB64)
}

type jwtAuthProvider struct {
	validateFunc func(ctx context.Context, token string) (*auth.UserInfo, error)
}

type browserAuthProvider struct {
	user     *auth.UserInfo
	loginURL string
}

func (b *browserAuthProvider) AuthenticateRequest(r *http.Request) (*auth.UserInfo, bool) {
	if b == nil || b.user == nil {
		return nil, false
	}
	return b.user, true
}

func (b *browserAuthProvider) LoginURL(returnTo string) string {
	base := "/login"
	if b != nil && b.loginURL != "" {
		base = b.loginURL
	}
	return base + "?return_to=" + returnTo
}

func (j *jwtAuthProvider) ValidateToken(ctx context.Context, token string) (*auth.UserInfo, error) {
	if j.validateFunc != nil {
		return j.validateFunc(ctx, token)
	}
	return auth.ParseTestJWT(token)
}

func (j *jwtAuthProvider) ExchangeCode(ctx context.Context, code string) (*auth.UserInfo, error) {
	return nil, fmt.Errorf("not implemented in test")
}

func (j *jwtAuthProvider) GetAuthURL(state string) string {
	return "/login?state=" + state
}

func (j *jwtAuthProvider) GetLogoutURL() string {
	return "/logout"
}

type mockAuthzProvider struct {
	getUserGroupsFunc          func(ctx context.Context, userInfo *auth.UserInfo) ([]string, error)
	getActiveElevatedRolesFunc func(ctx context.Context, userInfo *auth.UserInfo) ([]authz.ElevatedRole, error)
}

func (m *mockAuthzProvider) GetUserGroups(ctx context.Context, userInfo *auth.UserInfo) ([]string, error) {
	if m.getUserGroupsFunc != nil {
		return m.getUserGroupsFunc(ctx, userInfo)
	}
	return []string{"default-group"}, nil
}

func (m *mockAuthzProvider) GetActiveElevatedRoles(ctx context.Context, userInfo *auth.UserInfo) ([]authz.ElevatedRole, error) {
	if m.getActiveElevatedRolesFunc != nil {
		return m.getActiveElevatedRolesFunc(ctx, userInfo)
	}
	return []authz.ElevatedRole{}, nil
}

type capturedRequest struct {
	Method   string
	Path     string
	RawQuery string
	Body     string
	Headers  http.Header
}

type hijackableResponseWriter struct {
	http.ResponseWriter
	hijackCalled bool
	flushCalled  bool
}

func (w *hijackableResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	w.hijackCalled = true
	serverConn, clientConn := net.Pipe()
	_ = clientConn.Close()
	return serverConn, bufio.NewReadWriter(bufio.NewReader(strings.NewReader("")), bufio.NewWriter(serverConn)), nil
}

func (w *hijackableResponseWriter) Flush() {
	w.flushCalled = true
}

type proxyTestCase struct {
	name                     string
	backendName              string
	backendType              string
	backendNamespace         string
	externalPathPrefixes     []string
	trustedProxyConfig       *config.TrustedProxyConfig
	queryRewrite             *queryrewrite.RewriteConfig
	requestMethod            string
	requestBody              string
	requestContentType       string
	requestPath              string
	host                     string
	authToken                string
	browserUser              *auth.UserInfo
	namespace                string
	requestHeaders           map[string]string
	backendNamespaceRouting  *config.NamespaceRoutingConfig
	authzNamespaceClassifier *config.NamespaceClassifierConfig
	authzClusterResolver     *config.ClusterResolverConfig
	authValidateFunc         func(ctx context.Context, token string) (*auth.UserInfo, error)
	authzGetUserGroupsFunc   func(ctx context.Context, userID string) ([]string, error)
	authzGroupMappings       map[string][]string
	authzEnabled             bool
	webConfig                *config.WebConfig
	expectedStatus           int
	expectedLocation         string
	expectedHeaders          map[string]string
	expectAuditEvent         bool
	expectAuthCall           bool
	expectAuthzCall          bool
	expectBackendCall        bool
	expectedBackendPath      string
	expectedBackendQuery     string
	expectedBackendBody      string
	expectedAuditNamespace   string
}

func captureBackend() (*httptest.Server, *capturedRequest) {
	captured := &capturedRequest{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured.Method = r.Method
		captured.Path = r.URL.Path
		captured.RawQuery = r.URL.RawQuery
		body, _ := io.ReadAll(r.Body)
		captured.Body = string(body)
		captured.Headers = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	return server, captured
}

func TestResponseRecorderSupportsOptionalInterfaces(t *testing.T) {
	base := httptest.NewRecorder()
	wrapped := &hijackableResponseWriter{ResponseWriter: base}
	recorder := &responseRecorder{ResponseWriter: wrapped, statusCode: http.StatusOK}

	if _, _, err := recorder.Hijack(); err != nil {
		t.Fatalf("Hijack returned error: %v", err)
	}
	if !wrapped.hijackCalled {
		t.Fatalf("expected Hijack to be forwarded to the underlying ResponseWriter")
	}

	recorder.Flush()
	if !wrapped.flushCalled {
		t.Fatalf("expected Flush to be forwarded to the underlying ResponseWriter")
	}

	if recorder.Unwrap() != wrapped {
		t.Fatalf("expected Unwrap to return the underlying ResponseWriter")
	}
}

func executeProxyTestCase(t *testing.T, tt proxyTestCase) {
	t.Helper()

	testToken := tt.authToken
	if tt.authValidateFunc == nil && testToken == "" && tt.trustedProxyConfig == nil {
		testToken = createTestJWT("user123")
	}

	var backendServer *httptest.Server
	var captured *capturedRequest
	if tt.backendName != "nonexistent" {
		backendServer, captured = captureBackend()
		defer backendServer.Close()
	}

	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Auth: config.AuthConfig{
			Provider: "oidc",
			OIDC: config.OIDCConfig{
				IssuerURL:    "https://issuer.example.com",
				ClientID:     "multipass",
				ClientSecret: "secret",
				RedirectURL:  "https://multipass.example.com/login/generic_oauth",
			},
		},
		Authz: config.AuthzConfig{
			Enabled:  tt.authzEnabled,
			Provider: "token",
		},
		Audit: config.AuditConfig{
			Enabled: true,
			Store:   "memory",
		},
		Backends: map[string]config.BackendConfig{
			"dummy": {
				Type:     "prometheus",
				Endpoint: "http://dummy",
			},
		},
	}
	if tt.trustedProxyConfig != nil {
		cfg.Auth.TrustedProxy = *tt.trustedProxyConfig
	}
	if tt.authzNamespaceClassifier != nil {
		cfg.Authz.NamespaceClassifier = *tt.authzNamespaceClassifier
	}
	if tt.authzClusterResolver != nil {
		cfg.Authz.ClusterResolver = *tt.authzClusterResolver
	}

	if tt.backendName != "nonexistent" {
		cfg.Backends[tt.backendName] = config.BackendConfig{
			Type:                 tt.backendType,
			Endpoint:             backendServer.URL,
			Namespace:            tt.backendNamespace,
			NamespaceRouting:     tt.backendNamespaceRouting,
			QueryRewrite:         tt.queryRewrite,
			ExternalHost:         tt.host,
			ExternalPathPrefixes: tt.externalPathPrefixes,
			WebConfig:            tt.webConfig,
		}
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Invalid config: %v", err)
	}

	authCalled := false
	authProvider := &jwtAuthProvider{}
	if tt.authValidateFunc != nil {
		authProvider.validateFunc = func(ctx context.Context, token string) (*auth.UserInfo, error) {
			authCalled = true
			return tt.authValidateFunc(ctx, token)
		}
	} else {
		authProvider.validateFunc = func(ctx context.Context, token string) (*auth.UserInfo, error) {
			authCalled = true
			return auth.ParseTestJWT(token)
		}
	}

	authzCalled := false
	var authzEvaluator authz.Evaluator
	if tt.authzEnabled {
		groupMappings := tt.authzGroupMappings
		if groupMappings == nil {
			groupMappings = map[string][]string{
				"default-group": {"default"},
			}
		}
		authzProvider := &mockAuthzProvider{
			getUserGroupsFunc: func(ctx context.Context, userInfo *auth.UserInfo) ([]string, error) {
				authzCalled = true
				if tt.authzGetUserGroupsFunc != nil {
					return tt.authzGetUserGroupsFunc(ctx, userInfo.ID)
				}
				return []string{"default-group"}, nil
			},
		}
		authzEvaluator = authz.NewPolicyEvaluator(authzProvider, groupMappings)
	}

	auditStore := audit.NewMemoryStore()
	browserAuth := &browserAuthProvider{user: tt.browserUser}

	proxy, err := New(cfg, authProvider, browserAuth, authzEvaluator, auditStore)
	if err != nil {
		t.Fatalf("Failed to create proxy: %v", err)
	}

	requestMethod := tt.requestMethod
	if requestMethod == "" {
		requestMethod = http.MethodGet
	}
	var requestBody io.Reader
	if tt.requestBody != "" {
		requestBody = strings.NewReader(tt.requestBody)
	}
	req := httptest.NewRequest(requestMethod, tt.requestPath, requestBody)
	if tt.host != "" {
		req.Host = tt.host
	}
	if tt.requestContentType != "" {
		req.Header.Set("Content-Type", tt.requestContentType)
	}
	if testToken != "" {
		req.Header.Set("Authorization", "Bearer "+testToken)
	}
	for headerName, headerValue := range tt.requestHeaders {
		req.Header.Set(headerName, headerValue)
	}
	if tt.namespace != "" {
		q := req.URL.Query()
		q.Set("namespace", tt.namespace)
		req.URL.RawQuery = q.Encode()
	}

	rr := httptest.NewRecorder()
	proxy.ServeHTTP(rr, req)

	time.Sleep(50 * time.Millisecond)

	if rr.Code != tt.expectedStatus {
		t.Errorf("Expected status %d, got %d. Body: %s", tt.expectedStatus, rr.Code, rr.Body.String())
	}

	if tt.expectedLocation != "" {
		if location := rr.Header().Get("Location"); location != tt.expectedLocation {
			t.Errorf("Expected redirect location %s, got %s", tt.expectedLocation, location)
		}
	}

	if authCalled != tt.expectAuthCall {
		t.Errorf("Expected auth call: %v, got: %v", tt.expectAuthCall, authCalled)
	}

	if tt.authzEnabled && authzCalled != tt.expectAuthzCall {
		t.Errorf("Expected authz call: %v, got: %v", tt.expectAuthzCall, authzCalled)
	}

	if tt.expectBackendCall {
		if captured == nil {
			t.Fatal("Expected backend call but captured request is nil")
		}

		for headerName, expectedValue := range tt.expectedHeaders {
			actualValue := captured.Headers.Get(headerName)
			if actualValue != expectedValue {
				t.Errorf("Expected header %s=%s, got %s", headerName, expectedValue, actualValue)
			}
		}

		expectedBackendPath := tt.expectedBackendPath
		if expectedBackendPath == "" {
			expectedBackendPath = deriveExpectedBackendPath(tt)
		}
		if captured.Path != expectedBackendPath {
			t.Errorf("Expected backend path %s, got %s", expectedBackendPath, captured.Path)
		}
		if tt.expectedBackendQuery != "" && captured.RawQuery != tt.expectedBackendQuery {
			t.Errorf("Expected backend query %q, got %q", tt.expectedBackendQuery, captured.RawQuery)
		}
		if tt.expectedBackendBody != "" && captured.Body != tt.expectedBackendBody {
			t.Errorf("Expected backend body %q, got %q", tt.expectedBackendBody, captured.Body)
		}
	}

	if tt.expectAuditEvent {
		events, err := auditStore.Query(context.Background(), audit.AuditFilters{})
		if err != nil {
			t.Errorf("Failed to query audit events: %v", err)
		} else if len(events) == 0 {
			t.Error("Expected audit event to be logged, but none found")
		} else {
			event := events[0]
			if event.Backend != tt.backendName {
				t.Errorf("Expected audit backend=%s, got %s", tt.backendName, event.Backend)
			}
			expectedNs := tt.expectedAuditNamespace
			if expectedNs == "" {
				expectedNs = tt.backendNamespace
			}
			if expectedNs == "" {
				expectedNs = tt.namespace
				if expectedNs == "" {
					expectedNs = "default"
				}
			}
			if event.Namespace != expectedNs {
				t.Errorf("Expected audit namespace=%s, got %s", expectedNs, event.Namespace)
			}
		}
	} else {
		events, err := auditStore.Query(context.Background(), audit.AuditFilters{})
		if err != nil {
			t.Errorf("Failed to query audit events: %v", err)
		} else if len(events) > 0 {
			t.Errorf("Expected no audit event, but got %d events", len(events))
		}
	}
}

func deriveExpectedBackendPath(tt proxyTestCase) string {
	parsedURL, err := url.Parse(tt.requestPath)
	if err != nil {
		return tt.requestPath
	}

	if tt.host != "" {
		if parsedURL.Path == "" {
			return "/"
		}
		return parsedURL.Path
	}

	prefix := "/" + tt.backendName
	if strings.HasPrefix(parsedURL.Path, prefix) {
		trimmedPath := strings.TrimPrefix(parsedURL.Path, prefix)
		if trimmedPath == "" {
			return "/"
		}
		return trimmedPath
	}

	if parsedURL.Path == "" {
		return "/"
	}

	return parsedURL.Path
}

func TestHealthEndpoint(t *testing.T) {
	backendServer, _ := captureBackend()
	defer backendServer.Close()

	cfg := &config.Config{
		Server: config.ServerConfig{Port: 8080},
		Auth:   config.AuthConfig{Provider: "oidc", OIDC: config.OIDCConfig{IssuerURL: "https://issuer.example.com", ClientID: "multipass", ClientSecret: "secret", RedirectURL: "https://multipass.example.com/login/generic_oauth"}},
		Backends: map[string]config.BackendConfig{
			"grafana": {
				Type:     "web",
				Endpoint: backendServer.URL,
			},
		},
	}

	proxy, err := New(cfg, &jwtAuthProvider{}, &browserAuthProvider{}, nil, audit.NewMemoryStore())
	if err != nil {
		t.Fatalf("Failed to create proxy: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rr := httptest.NewRecorder()

	proxy.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Expected status %d, got %d", http.StatusOK, rr.Code)
	}
	if body := strings.TrimSpace(rr.Body.String()); body != "OK" {
		t.Fatalf("Expected body OK, got %q", body)
	}
}

func TestRequestLoggerProbePathUsesDebugLevel(t *testing.T) {
	proxy, err := New(&config.Config{
		Server: config.ServerConfig{Port: 8080},
		Auth: config.AuthConfig{
			Provider: "oidc",
			OIDC: config.OIDCConfig{
				IssuerURL:    "https://issuer.example.com",
				ClientID:     "multipass",
				ClientSecret: "secret",
				RedirectURL:  "https://multipass.example.com/login/generic_oauth",
			},
		},
		Backends: map[string]config.BackendConfig{},
	}, &jwtAuthProvider{}, &browserAuthProvider{}, nil, audit.NewMemoryStore())
	if err != nil {
		t.Fatalf("Failed to create proxy: %v", err)
	}

	t.Run("health logs are suppressed at info", func(t *testing.T) {
		output := captureDefaultLogs(t, slog.LevelInfo, func() {
			req := httptest.NewRequest(http.MethodGet, "/health", nil)
			rr := httptest.NewRecorder()
			proxy.requestLogger(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})).ServeHTTP(rr, req)
		})

		if strings.Contains(output, "\"path\":\"/health\"") {
			t.Fatalf("expected /health request log to be suppressed at info level, got %q", output)
		}
	})

	t.Run("health logs are emitted at debug", func(t *testing.T) {
		output := captureDefaultLogs(t, slog.LevelDebug, func() {
			req := httptest.NewRequest(http.MethodGet, "/health", nil)
			rr := httptest.NewRecorder()
			proxy.requestLogger(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})).ServeHTTP(rr, req)
		})

		if !strings.Contains(output, "\"path\":\"/health\"") {
			t.Fatalf("expected /health request log at debug level, got %q", output)
		}
	})

	t.Run("normal requests stay at info", func(t *testing.T) {
		output := captureDefaultLogs(t, slog.LevelInfo, func() {
			req := httptest.NewRequest(http.MethodGet, "/grafana/api/health", nil)
			rr := httptest.NewRecorder()
			proxy.requestLogger(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})).ServeHTTP(rr, req)
		})

		if !strings.Contains(output, "\"path\":\"/grafana/api/health\"") {
			t.Fatalf("expected normal request log at info level, got %q", output)
		}
	})
}

func captureDefaultLogs(t *testing.T, level slog.Level, run func()) string {
	t.Helper()

	var buffer bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buffer, &slog.HandlerOptions{Level: level}))
	original := slog.Default()
	slog.SetDefault(logger)
	t.Cleanup(func() {
		slog.SetDefault(original)
	})

	run()
	return buffer.String()
}

func TestFixedBackendNamespaceOverridesRequestNamespace(t *testing.T) {
	executeProxyTestCase(t, proxyTestCase{
		name:                "fixed backend namespace wins over query parameter",
		backendName:         "mimir",
		backendType:         "prometheus",
		backendNamespace:    "monitoring",
		requestPath:         "/mimir/api/v1/query",
		namespace:           "prod",
		authzEnabled:        true,
		authzGroupMappings:  map[string][]string{"default-group": {"monitoring"}},
		expectedStatus:      http.StatusOK,
		expectedHeaders:     map[string]string{"X-Scope-OrgID": "monitoring"},
		expectAuditEvent:    true,
		expectAuthCall:      true,
		expectAuthzCall:     true,
		expectBackendCall:   true,
		expectedBackendPath: "/api/v1/query",
	})
}

func TestReadinessEndpoint(t *testing.T) {
	t.Run("ready when all backends respond", func(t *testing.T) {
		backendServer, _ := captureBackend()
		defer backendServer.Close()

		cfg := &config.Config{
			Server: config.ServerConfig{Port: 8080},
			Auth:   config.AuthConfig{Provider: "oidc", OIDC: config.OIDCConfig{IssuerURL: "https://issuer.example.com", ClientID: "multipass", ClientSecret: "secret", RedirectURL: "https://multipass.example.com/login/generic_oauth"}},
			Backends: map[string]config.BackendConfig{
				"grafana": {
					Type:     "web",
					Endpoint: backendServer.URL,
				},
			},
		}

		proxy, err := New(cfg, &jwtAuthProvider{}, &browserAuthProvider{}, nil, audit.NewMemoryStore())
		if err != nil {
			t.Fatalf("Failed to create proxy: %v", err)
		}

		req := httptest.NewRequest(http.MethodGet, "/ready", nil)
		rr := httptest.NewRecorder()

		proxy.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("Expected status %d, got %d. Body: %s", http.StatusOK, rr.Code, rr.Body.String())
		}
		if !strings.Contains(rr.Body.String(), `"status":"ready"`) {
			t.Fatalf("Expected ready response body, got %s", rr.Body.String())
		}
	})

	t.Run("uses readiness url override when configured", func(t *testing.T) {
		probeHits := 0
		readinessServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			probeHits++
			w.WriteHeader(http.StatusOK)
		}))
		defer readinessServer.Close()

		backendServer, _ := captureBackend()
		endpoint := backendServer.URL
		backendServer.Close()

		cfg := &config.Config{
			Server: config.ServerConfig{Port: 8080},
			Auth:   config.AuthConfig{Provider: "oidc", OIDC: config.OIDCConfig{IssuerURL: "https://issuer.example.com", ClientID: "multipass", ClientSecret: "secret", RedirectURL: "https://multipass.example.com/login/generic_oauth"}},
			Backends: map[string]config.BackendConfig{
				"otel": {
					Type:         "web",
					Endpoint:     endpoint,
					ReadinessURL: readinessServer.URL,
				},
			},
		}

		proxy, err := New(cfg, &jwtAuthProvider{}, &browserAuthProvider{}, nil, audit.NewMemoryStore())
		if err != nil {
			t.Fatalf("Failed to create proxy: %v", err)
		}

		req := httptest.NewRequest(http.MethodGet, "/ready", nil)
		rr := httptest.NewRecorder()

		proxy.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("Expected status %d, got %d. Body: %s", http.StatusOK, rr.Code, rr.Body.String())
		}
		if probeHits != 1 {
			t.Fatalf("Expected readiness override to be probed once, got %d", probeHits)
		}
		if !strings.Contains(rr.Body.String(), readinessServer.URL) {
			t.Fatalf("Expected readiness response to contain override URL, got %s", rr.Body.String())
		}
	})

	t.Run("not ready when backend is unreachable", func(t *testing.T) {
		backendServer, _ := captureBackend()
		endpoint := backendServer.URL
		backendServer.Close()

		cfg := &config.Config{
			Server: config.ServerConfig{Port: 8080},
			Auth:   config.AuthConfig{Provider: "oidc", OIDC: config.OIDCConfig{IssuerURL: "https://issuer.example.com", ClientID: "multipass", ClientSecret: "secret", RedirectURL: "https://multipass.example.com/login/generic_oauth"}},
			Backends: map[string]config.BackendConfig{
				"opensearch": {
					Type:     "jwt",
					Endpoint: endpoint,
				},
			},
		}

		proxy, err := New(cfg, &jwtAuthProvider{}, &browserAuthProvider{}, nil, audit.NewMemoryStore())
		if err != nil {
			t.Fatalf("Failed to create proxy: %v", err)
		}

		req := httptest.NewRequest(http.MethodGet, "/ready", nil)
		rr := httptest.NewRecorder()

		proxy.ServeHTTP(rr, req)

		if rr.Code != http.StatusServiceUnavailable {
			t.Fatalf("Expected status %d, got %d. Body: %s", http.StatusServiceUnavailable, rr.Code, rr.Body.String())
		}
		if !strings.Contains(rr.Body.String(), `"status":"not_ready"`) {
			t.Fatalf("Expected not_ready response body, got %s", rr.Body.String())
		}
	})
}
