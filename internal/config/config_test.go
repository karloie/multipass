package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/karloie/multipass/internal/auth"
	queryrewrite "github.com/karloie/multipass/internal/query"
)

func newTestConfig(backend BackendConfig) *Config {
	return &Config{
		Server: ServerConfig{Port: 8080},
		Auth:   AuthConfig{Provider: "oidc", OIDC: OIDCConfig{IssuerURL: "https://issuer", ClientID: "client", ClientSecret: "secret", RedirectURL: "https://example.com/login/generic_oauth"}},
		Backends: map[string]BackendConfig{
			"test": backend,
		},
	}
}

func newBackendWithQueryRewrite(rewrite *queryrewrite.RewriteConfig) BackendConfig {
	return BackendConfig{
		Type:         "generic",
		Endpoint:     "http://example",
		QueryRewrite: rewrite,
	}
}

func TestLoadExpandsEnvironmentVariables(t *testing.T) {
	t.Setenv("MULTIPASS_OIDC_CLIENT_SECRET", "oidc-secret")
	t.Setenv("MULTIPASS_TRUSTED_PROXY_SECRET", "proxy-secret")

	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	content := []byte("server:\n" +
		"  port: 8080\n" +
		"auth:\n" +
		"  provider: oidc\n" +
		"  sessionTTL: 24h\n" +
		"  sessionStore:\n" +
		"    store: memory\n" +
		"  trustedProxy:\n" +
		"    enabled: true\n" +
		"    userHeader: X-Grafana-User\n" +
		"    callerHeader: X-Multipass-Caller\n" +
		"    callerValue: grafana-datasource\n" +
		"    secretHeader: X-Multipass-Proxy-Secret\n" +
		"    secretValue: ${MULTIPASS_TRUSTED_PROXY_SECRET}\n" +
		"  oidc:\n" +
		"    providerName: forgerock\n" +
		"    issuerUrl: https://example.com\n" +
		"    clientId: multipass\n" +
		"    clientSecret: ${MULTIPASS_OIDC_CLIENT_SECRET}\n" +
		"    redirectUrl: https://example.com/login/generic_oauth\n" +
		"    scopes:\n" +
		"      - openid\n" +
		"authz:\n" +
		"  enabled: false\n" +
		"  provider: token\n" +
		"audit:\n" +
		"  enabled: false\n" +
		"  store: memory\n" +
		"backends:\n" +
		"  lgtm:\n" +
		"    type: web\n" +
		"    endpoint: http://example\n")
	if err := os.WriteFile(configPath, content, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	if cfg.Auth.OIDC.ClientSecret != "oidc-secret" {
		t.Fatalf("expected expanded oidc client secret, got %q", cfg.Auth.OIDC.ClientSecret)
	}
	if cfg.Auth.TrustedProxy.SecretValue != "proxy-secret" {
		t.Fatalf("expected expanded trusted proxy secret, got %q", cfg.Auth.TrustedProxy.SecretValue)
	}
	if cfg.Auth.TrustedProxy.CallerHeader != "X-Multipass-Caller" {
		t.Fatalf("expected trusted proxy caller header, got %q", cfg.Auth.TrustedProxy.CallerHeader)
	}
	if cfg.Auth.TrustedProxy.CallerValue != "grafana-datasource" {
		t.Fatalf("expected trusted proxy caller value, got %q", cfg.Auth.TrustedProxy.CallerValue)
	}
}

func TestOIDCConfigPathsDefaultsToGrafanaShape(t *testing.T) {
	paths := OIDCConfig{}.Paths()

	if paths.LoginPath != DefaultOIDCLoginPath {
		t.Fatalf("expected default login path %q, got %q", DefaultOIDCLoginPath, paths.LoginPath)
	}
	if paths.CallbackPath != DefaultOIDCCallbackPath {
		t.Fatalf("expected default callback path %q, got %q", DefaultOIDCCallbackPath, paths.CallbackPath)
	}
	if paths.LogoutPath != DefaultOIDCLogoutPath {
		t.Fatalf("expected default logout path %q, got %q", DefaultOIDCLogoutPath, paths.LogoutPath)
	}
}

func TestOIDCConfigCanOverridePaths(t *testing.T) {
	paths := OIDCConfig{
		LoginPath:    "/auth/login",
		CallbackPath: "/auth/callback",
		LogoutPath:   "/auth/logout",
	}.Paths()

	if paths.LoginPath != "/auth/login" || paths.CallbackPath != "/auth/callback" || paths.LogoutPath != "/auth/logout" {
		t.Fatalf("expected custom auth paths, got %+v", paths)
	}
}

func TestOIDCConfigDerivesPostLogoutRedirectURL(t *testing.T) {
	cfg := OIDCConfig{RedirectURL: "https://monitor.plat.los.spk.no/login/generic_oauth"}

	if got := cfg.EffectivePostLogoutRedirectURL(); got != "https://monitor.plat.los.spk.no/login" {
		t.Fatalf("expected derived post logout redirect URL, got %q", got)
	}
}

func TestConfigValidateNamespaceRouting(t *testing.T) {
	tests := []struct {
		name    string
		backend BackendConfig
		authz   AuthzConfig
		wantErr bool
	}{
		{
			name: "request routing requires parameter",
			backend: BackendConfig{
				Type:     "prometheus",
				Endpoint: "http://example",
				NamespaceRouting: &NamespaceRoutingConfig{
					Mode: "request",
				},
			},
			wantErr: true,
		},
		{
			name: "request routing namespace prefix requires classifier",
			backend: BackendConfig{
				Type:      "prometheus",
				Endpoint:  "http://example",
				Namespace: "core-test",
				NamespaceRouting: &NamespaceRoutingConfig{
					Mode:      "request",
					Parameter: "tm_namespace",
				},
			},
			wantErr: true,
		},
		{
			name: "request routing allows cluster prefix with classifier",
			backend: BackendConfig{
				Type:      "prometheus",
				Endpoint:  "http://example",
				Namespace: "core-test",
				NamespaceRouting: &NamespaceRoutingConfig{
					Mode:      "request",
					Parameter: "tm_namespace",
				},
			},
			authz: AuthzConfig{
				NamespaceClassifier: NamespaceClassifierConfig{DefaultSegment: "dev"},
			},
		},
		{
			name: "fixed routing requires namespace",
			backend: BackendConfig{
				Type:     "prometheus",
				Endpoint: "http://example",
				NamespaceRouting: &NamespaceRoutingConfig{
					Mode: "fixed",
				},
			},
			wantErr: true,
		},
		{
			name: "request routing valid",
			backend: BackendConfig{
				Type:     "prometheus",
				Endpoint: "http://example",
				NamespaceRouting: &NamespaceRoutingConfig{
					Mode:      "request",
					Parameter: "tm_namespace",
				},
			},
		},
		{
			name: "request routing accepts query source",
			backend: BackendConfig{
				Type:     "prometheus",
				Endpoint: "http://example",
				NamespaceRouting: &NamespaceRoutingConfig{
					Mode:      "request",
					Parameter: "tm_namespace",
					Source:    "query",
				},
			},
		},
		{
			name: "request routing accepts body source",
			backend: BackendConfig{
				Type:     "prometheus",
				Endpoint: "http://example",
				NamespaceRouting: &NamespaceRoutingConfig{
					Mode:      "request",
					Parameter: "tm_namespace",
					Source:    "body",
				},
			},
		},
		{
			name: "request routing rejects invalid source",
			backend: BackendConfig{
				Type:     "prometheus",
				Endpoint: "http://example",
				NamespaceRouting: &NamespaceRoutingConfig{
					Mode:      "request",
					Parameter: "tm_namespace",
					Source:    "header",
				},
			},
			wantErr: true,
		},
		{
			name: "fixed routing valid",
			backend: BackendConfig{
				Type:      "prometheus",
				Endpoint:  "http://example",
				Namespace: "monitoring",
				NamespaceRouting: &NamespaceRoutingConfig{
					Mode: "fixed",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				Server: ServerConfig{Port: 8080},
				Auth:   AuthConfig{Provider: "oidc", OIDC: OIDCConfig{IssuerURL: "https://issuer", ClientID: "client", ClientSecret: "secret", RedirectURL: "https://example.com/login/generic_oauth"}},
				Authz:  tt.authz,
				Backends: map[string]BackendConfig{
					"test": tt.backend,
				},
			}

			err := cfg.Validate()
			if tt.wantErr && err == nil {
				t.Fatal("expected validation error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("expected no validation error, got %v", err)
			}
		})
	}
}

func TestNamespaceClassifierClassify(t *testing.T) {
	classifier := NamespaceClassifierConfig{
		DefaultSegment: "dev",
		OpsExact:       []string{"monitoring"},
		OpsPrefixes:    []string{"kube-"},
		ClusterOverrides: map[string]NamespaceClassifierOverride{
			"tool-test": {
				OpsExact: []string{"arc-runners"},
			},
		},
	}

	tests := []struct {
		name      string
		cluster   string
		namespace string
		want      string
	}{
		{name: "base exact match becomes ops scope", cluster: "core-test", namespace: "monitoring", want: "core-test.ops"},
		{name: "cluster override extends ops rules", cluster: "tool-test", namespace: "arc-runners", want: "tool-test.ops"},
		{name: "default segment used when no ops rule matches", cluster: "core-test", namespace: "team-a", want: "core-test.dev"},
		{name: "classifier can return segment without cluster prefix", cluster: "", namespace: "kube-system", want: "ops"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifier.Classify(tt.cluster, tt.namespace); got != tt.want {
				t.Fatalf("expected %q, got %q", tt.want, got)
			}
		})
	}
}

func TestClusterResolverResolveCluster(t *testing.T) {
	resolver := ClusterResolverConfig{
		Source: "user",
		Mappings: map[string]string{
			"otel-collector-core":      "core",
			"otel-collector-core-test": "core-test",
		},
	}

	tests := []struct {
		name string
		user *auth.UserInfo
		want string
	}{
		{name: "maps user id to cluster", user: &auth.UserInfo{ID: "otel-collector-core-test"}, want: "core-test"},
		{name: "falls back to username", user: &auth.UserInfo{Username: "otel-collector-core"}, want: "core"},
		{name: "returns empty when unmapped", user: &auth.UserInfo{ID: "unknown"}, want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := resolver.ResolveCluster(tt.user); got != tt.want {
				t.Fatalf("expected %q, got %q", tt.want, got)
			}
		})
	}
}

func TestConfigValidateExternalPathPrefixes(t *testing.T) {
	tests := []struct {
		name    string
		backend BackendConfig
		wantErr bool
	}{
		{
			name: "external path prefixes require external host",
			backend: BackendConfig{
				Type:                 "generic",
				Endpoint:             "http://example",
				ExternalPathPrefixes: []string{"/otlp/v1/metrics"},
			},
			wantErr: true,
		},
		{
			name: "external path prefixes must start with slash",
			backend: BackendConfig{
				Type:                 "generic",
				Endpoint:             "http://example",
				ExternalHost:         "otlp.example.com",
				ExternalPathPrefixes: []string{"otlp/v1/metrics"},
			},
			wantErr: true,
		},
		{
			name: "external path prefixes valid",
			backend: BackendConfig{
				Type:                 "generic",
				Endpoint:             "http://example",
				ExternalHost:         "otlp.example.com",
				ExternalPathPrefixes: []string{"/otlp/v1/metrics", "/otlp/v1/traces"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := newTestConfig(tt.backend).Validate()
			if tt.wantErr && err == nil {
				t.Fatal("expected validation error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("expected no validation error, got %v", err)
			}
		})
	}
}

func TestConfigValidateQueryRewrite(t *testing.T) {
	tests := []struct {
		name    string
		backend BackendConfig
		wantErr bool
	}{
		{
			name:    "query rewrite requires operations",
			backend: newBackendWithQueryRewrite(&queryrewrite.RewriteConfig{}),
			wantErr: true,
		},
		{
			name: "query rewrite rejects invalid action",
			backend: newBackendWithQueryRewrite(&queryrewrite.RewriteConfig{Operations: []queryrewrite.RewriteOperation{
				{Action: "replace", Name: "query", Value: "up"},
			}}),
			wantErr: true,
		},
		{
			name:    "rename requires target parameter",
			backend: newBackendWithQueryRewrite(&queryrewrite.RewriteConfig{Operations: []queryrewrite.RewriteOperation{{Action: "rename", Name: "query"}}}),
			wantErr: true,
		},
		{
			name: "query rewrite valid",
			backend: newBackendWithQueryRewrite(&queryrewrite.RewriteConfig{Operations: []queryrewrite.RewriteOperation{
				{Action: "rename", Name: "query", To: "expr"},
				{Action: "add", Name: "tenant", Value: "{{namespace}}"},
				{Action: "set", Name: "source", Value: "{{backend}}"},
				{Action: "delete", Name: "debug"},
			}}),
		},
		{
			name: "query rewrite semantic rules valid",
			backend: newBackendWithQueryRewrite(&queryrewrite.RewriteConfig{Semantics: []queryrewrite.SemanticRule{{
				Language: "promql",
				Params:   []string{"query"},
				Routes:   []string{"/api/v1/query", "/api/v1/query_range"},
				Require: []queryrewrite.MatcherRequirement{{
					Name:  "namespace",
					Value: "{{namespace}}",
				}},
			}}}),
		},
		{
			name: "query rewrite semantic rules reject unsupported language",
			backend: newBackendWithQueryRewrite(&queryrewrite.RewriteConfig{Semantics: []queryrewrite.SemanticRule{{
				Language: "logql",
				Params:   []string{"query"},
				Require:  []queryrewrite.MatcherRequirement{{Name: "namespace", Value: "{{namespace}}"}},
			}}}),
			wantErr: true,
		},
		{
			name:    "query rewrite tenant label shorthand valid",
			backend: newBackendWithQueryRewrite(&queryrewrite.RewriteConfig{TenantLabel: &queryrewrite.TenantLabelRule{Name: "namespace"}}),
		},
		{
			name:    "query rewrite tenant label shorthand rejects invalid mode",
			backend: newBackendWithQueryRewrite(&queryrewrite.RewriteConfig{TenantLabel: &queryrewrite.TenantLabelRule{Mode: "rewrite"}}),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := newTestConfig(tt.backend).Validate()
			if tt.wantErr && err == nil {
				t.Fatal("expected validation error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("expected no validation error, got %v", err)
			}
		})
	}
}

func TestConfigValidateClusterResolver(t *testing.T) {
	tests := []struct {
		name    string
		authz   AuthzConfig
		wantErr bool
	}{
		{
			name: "cluster resolver valid",
			authz: AuthzConfig{
				ClusterResolver: ClusterResolverConfig{
					Source:   "user",
					Mappings: map[string]string{"otel-collector-core-test": "core-test"},
				},
			},
		},
		{
			name: "cluster resolver requires mappings",
			authz: AuthzConfig{
				ClusterResolver: ClusterResolverConfig{Source: "user"},
			},
			wantErr: true,
		},
		{
			name: "cluster resolver rejects unsupported source",
			authz: AuthzConfig{
				ClusterResolver: ClusterResolverConfig{
					Source:   "principal",
					Mappings: map[string]string{"otel-collector-core-test": "core-test"},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := newTestConfig(BackendConfig{Type: "prometheus", Endpoint: "http://example"})
			cfg.Authz = tt.authz
			err := cfg.Validate()
			if tt.wantErr && err == nil {
				t.Fatal("expected validation error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("expected no validation error, got %v", err)
			}
		})
	}
}

func TestConfigValidateTokenProvider(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{Port: 8080},
		Auth:   AuthConfig{Provider: "oidc", OIDC: OIDCConfig{IssuerURL: "https://issuer", ClientID: "client", ClientSecret: "secret", RedirectURL: "https://example.com/login/generic_oauth"}},
		Authz: AuthzConfig{
			Enabled:  true,
			Provider: "token",
			GroupMappings: map[string][]string{
				"Rolle Utvikler": {"core-test-01"},
			},
		},
		Backends: map[string]BackendConfig{
			"test": {Type: "prometheus", Endpoint: "http://example"},
		},
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected token authz config to validate, got %v", err)
	}
}

func TestOIDCProfileLoadsAndValidates(t *testing.T) {
	configPath := filepath.Join("..", "..", "config.oidc.yaml")

	cfg, err := Load(configPath)
	if err != nil {
		fatalf := "Load returned error for %s: %v"
		t.Fatalf(fatalf, configPath, err)
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate returned error for %s: %v", configPath, err)
	}

	if cfg.Auth.Provider != "oidc" {
		t.Fatalf("expected auth provider oidc, got %q", cfg.Auth.Provider)
	}
	if !cfg.Authz.Enabled || cfg.Authz.Provider != "token" {
		t.Fatalf("expected enabled token authz profile, got enabled=%v provider=%q", cfg.Authz.Enabled, cfg.Authz.Provider)
	}
	if len(cfg.Backends) == 0 {
		t.Fatal("expected OIDC profile to define backends")
	}
}

func TestTestProfileLoadsAndValidates(t *testing.T) {
	configPath := filepath.Join("..", "..", "config.test.yaml")

	cfg, err := Load(configPath)
	if err != nil {
		fatalf := "Load returned error for %s: %v"
		t.Fatalf(fatalf, configPath, err)
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate returned error for %s: %v", configPath, err)
	}

	if cfg.Auth.Provider != "oidc" {
		t.Fatalf("expected auth provider oidc, got %q", cfg.Auth.Provider)
	}
	if !cfg.Authz.Enabled || cfg.Authz.Provider != "token" {
		t.Fatalf("expected enabled token authz profile, got enabled=%v provider=%q", cfg.Authz.Enabled, cfg.Authz.Provider)
	}
	if len(cfg.Backends) == 0 {
		t.Fatal("expected test profile to define backends")
	}
	if cfg.Audit.Store != "memory" {
		t.Fatalf("expected memory audit store, got %q", cfg.Audit.Store)
	}
}
