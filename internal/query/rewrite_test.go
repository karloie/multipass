package query

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

var (
	testPromQLRoutes   = []string{"/api/v1/query", "/api/v1/query_range"}
	testSelectorRoutes = []string{"/api/v1/series"}
)

func mustRewriteWithError(t *testing.T, values url.Values, cfg *RewriteConfig, ctx Context) url.Values {
	t.Helper()

	rewritten, err := RewriteWithError(values, cfg, ctx)
	if err != nil {
		t.Fatalf("RewriteWithError returned error: %v", err)
	}

	return rewritten
}

func assertValidateResult(t *testing.T, cfg *RewriteConfig, wantErr bool) {
	t.Helper()

	err := Validate("test", cfg)
	if wantErr && err == nil {
		t.Fatal("expected validation error, got nil")
	}
	if !wantErr && err != nil {
		t.Fatalf("expected no validation error, got %v", err)
	}
}

func promQLSemanticConfig(requirements ...MatcherRequirement) *RewriteConfig {
	return &RewriteConfig{Semantics: []SemanticRule{promQLSemanticRule(requirements...)}}
}

func promQLSemanticRule(requirements ...MatcherRequirement) SemanticRule {
	return SemanticRule{
		Language: semanticLanguagePromQL,
		Params:   []string{"query"},
		Routes:   testPromQLRoutes,
		Require:  requirements,
	}
}

func selectorSemanticConfig(requirements ...MatcherRequirement) *RewriteConfig {
	return &RewriteConfig{Semantics: []SemanticRule{selectorSemanticRule(requirements...)}}
}

func selectorSemanticRule(requirements ...MatcherRequirement) SemanticRule {
	return SemanticRule{
		Language: semanticLanguageSelector,
		Params:   []string{"match[]"},
		Routes:   testSelectorRoutes,
		Require:  requirements,
	}
}

func TestRewriteOperations(t *testing.T) {
	values := url.Values{
		"tm_namespace": {"utv"},
		"query":        {"up", "rate"},
		"debug":        {"true"},
	}

	rewritten := Rewrite(values, &RewriteConfig{Operations: []RewriteOperation{
		{Action: "rename", Name: "query", To: "expr"},
		{Action: "add", Name: "tenant", Value: "{{namespace}}"},
		{Action: "set", Name: "source", Value: "{{host}}/{{backend}}"},
		{Action: "delete", Name: "debug"},
	}}, Context{
		Backend:   "mimir-shared",
		Namespace: "utv",
		Host:      "otlp.example.com",
	})

	if got := rewritten.Encode(); got != "expr=up&expr=rate&source=otlp.example.com%2Fmimir-shared&tenant=utv&tm_namespace=utv" {
		t.Fatalf("expected rewritten query, got %q", got)
	}

	if got := values.Encode(); got != "debug=true&query=up&query=rate&tm_namespace=utv" {
		t.Fatalf("expected original values to remain unchanged, got %q", got)
	}
}

func TestRewriteNoConfigReturnsOriginalValues(t *testing.T) {
	values := url.Values{"query": {"up"}}
	rewritten := Rewrite(values, nil, Context{Namespace: "utv"})

	if got := rewritten.Encode(); got != "query=up" {
		t.Fatalf("expected values without queryRewrite config to be unchanged, got %q", got)
	}
}

func TestRewriteRendersTemplates(t *testing.T) {
	rewritten := Rewrite(url.Values{}, &RewriteConfig{Operations: []RewriteOperation{
		{Action: "add", Name: "source", Value: "{{host}}/{{backend}}/{{namespace}}"},
	}}, Context{
		Backend:   "tempo",
		Namespace: "core-test.ops",
		Host:      "otlp.example.com",
	})

	if got := rewritten.Encode(); got != "source=otlp.example.com%2Ftempo%2Fcore-test.ops" {
		t.Fatalf("expected rendered template, got %q", got)
	}
}

func TestRewriteMatchesRoutes(t *testing.T) {
	rewritten := Rewrite(url.Values{"query": {"up"}, "match[]": {"{job=\"api\"}"}}, &RewriteConfig{Operations: []RewriteOperation{
		{Action: "rename", Name: "query", To: "expr", Routes: []string{"/api/v1/query", "/api/v1/query_range"}},
		{Action: "set", Name: "tenant", Value: "{{route}}", Routes: []string{"/api/v1/query"}},
	}}, Context{Route: "/api/v1/series"})

	if got := rewritten.Encode(); got != "match%5B%5D=%7Bjob%3D%22api%22%7D&query=up" {
		t.Fatalf("expected route-mismatched operations to be skipped, got %q", got)
	}
}

func TestRewritePromQLSemantics(t *testing.T) {
	rewritten := mustRewriteWithError(t, url.Values{"query": {"sum(rate(http_requests_total[5m]))"}}, promQLSemanticConfig(MatcherRequirement{Name: "namespace", Value: "{{namespace}}"}), Context{Namespace: "utv", Route: "/api/v1/query"})

	if got := rewritten.Get("query"); got != "sum(rate(http_requests_total{namespace=\"utv\"}[5m]))" {
		t.Fatalf("expected semantic promql enforcement, got %q", got)
	}
}

func TestRewriteSelectorSemantics(t *testing.T) {
	rewritten := mustRewriteWithError(t, url.Values{"match[]": {"up"}}, selectorSemanticConfig(MatcherRequirement{Name: "namespace", Value: "{{namespace}}"}), Context{Namespace: "utv", Route: "/api/v1/series"})

	if got := rewritten["match[]"][0]; got != "{__name__=\"up\",namespace=\"utv\"}" {
		t.Fatalf("expected selector semantic enforcement, got %q", got)
	}
}

func TestRewriteTenantLabelDefaults(t *testing.T) {
	rewrittenQuery := mustRewriteWithError(t, url.Values{"query": {"up"}}, &RewriteConfig{TenantLabel: &TenantLabelRule{}}, Context{Namespace: "utv", Route: "/api/v1/query"})
	if got := rewrittenQuery.Get("query"); got != "up{namespace=\"utv\"}" {
		t.Fatalf("expected tenant label promql enforcement, got %q", got)
	}

	rewrittenSelector := mustRewriteWithError(t, url.Values{"match[]": {"up"}}, &RewriteConfig{TenantLabel: &TenantLabelRule{}}, Context{Namespace: "utv", Route: "/api/v1/labels"})
	if got := rewrittenSelector.Get("match[]"); got != "{__name__=\"up\",namespace=\"utv\"}" {
		t.Fatalf("expected tenant label selector enforcement, got %q", got)
	}
}

func TestRewriteTenantLabelCustomName(t *testing.T) {
	rewritten := mustRewriteWithError(t, url.Values{"query": {"up"}}, &RewriteConfig{TenantLabel: &TenantLabelRule{
		Name:  "tenant",
		Value: "{{backend}}/{{namespace}}",
	}}, Context{Backend: "mimir-shared", Namespace: "utv", Route: "/api/v1/query"})

	if got := rewritten.Get("query"); got != "up{tenant=\"mimir-shared/utv\"}" {
		t.Fatalf("expected custom tenant label enforcement, got %q", got)
	}
}

func TestRewriteLogQLSemantics(t *testing.T) {
	rewritten := mustRewriteWithError(t, url.Values{"query": {"{app=\"api\"} |= \"error\""}}, &RewriteConfig{Semantics: []SemanticRule{{
		Language: semanticLanguageLogQL,
		Params:   []string{"query"},
		Routes:   []string{"/loki/api/v1/query"},
		Require:  []MatcherRequirement{{Name: "segment", Value: "dev"}},
	}}}, Context{Route: "/loki/api/v1/query"})

	if got := rewritten.Get("query"); got != "{app=\"api\",segment=\"dev\"} |= \"error\"" {
		t.Fatalf("expected semantic logql enforcement, got %q", got)
	}
}

func TestRewriteLogQLSemanticConflict(t *testing.T) {
	_, err := RewriteWithError(url.Values{"query": {"{segment=\"ops\"}"}}, &RewriteConfig{Semantics: []SemanticRule{{
		Language: semanticLanguageLogQL,
		Params:   []string{"query"},
		Routes:   []string{"/loki/api/v1/query"},
		Require:  []MatcherRequirement{{Name: "segment", Value: "dev"}},
	}}}, Context{Route: "/loki/api/v1/query"})
	if err == nil {
		t.Fatal("expected logql semantic conflict error, got nil")
	}
}

func TestRewriteTraceQLSemantics(t *testing.T) {
	rewritten := mustRewriteWithError(t, url.Values{"q": {"{ resource.service.name = \"api\" }"}}, &RewriteConfig{Semantics: []SemanticRule{{
		Language: semanticLanguageTraceQL,
		Params:   []string{"q"},
		Routes:   []string{"/api/search"},
		Require:  []MatcherRequirement{{Name: "resource.segment", Value: "ops"}},
	}}}, Context{Route: "/api/search"})

	if got := rewritten.Get("q"); got != "{ resource.service.name = \"api\" && resource.segment = \"ops\" }" {
		t.Fatalf("expected semantic traceql enforcement, got %q", got)
	}
}

func TestRewriteTraceQLSemanticConflict(t *testing.T) {
	_, err := RewriteWithError(url.Values{"q": {"{ resource.segment = \"dev\" }"}}, &RewriteConfig{Semantics: []SemanticRule{{
		Language: semanticLanguageTraceQL,
		Params:   []string{"q"},
		Routes:   []string{"/api/search"},
		Require:  []MatcherRequirement{{Name: "resource.segment", Value: "ops"}},
	}}}, Context{Route: "/api/search"})
	if err == nil {
		t.Fatal("expected traceql semantic conflict error, got nil")
	}
}

func TestRewritePromQLSemanticConflict(t *testing.T) {
	_, err := RewriteWithError(url.Values{"query": {"up{namespace=\"prod\"}"}}, promQLSemanticConfig(MatcherRequirement{Name: "namespace", Value: "utv"}), Context{Namespace: "utv", Route: "/api/v1/query"})
	if err == nil {
		t.Fatal("expected semantic conflict error, got nil")
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *RewriteConfig
		wantErr bool
	}{
		{name: "nil config is valid"},
		{name: "requires operations", cfg: &RewriteConfig{}, wantErr: true},
		{
			name:    "rejects invalid action",
			cfg:     &RewriteConfig{Operations: []RewriteOperation{{Action: "replace", Name: "query", Value: "up"}}},
			wantErr: true,
		},
		{
			name:    "rename requires target",
			cfg:     &RewriteConfig{Operations: []RewriteOperation{{Action: "rename", Name: "query"}}},
			wantErr: true,
		},
		{
			name:    "delete rejects target",
			cfg:     &RewriteConfig{Operations: []RewriteOperation{{Action: "delete", Name: "debug", To: "noop"}}},
			wantErr: true,
		},
		{
			name: "valid config",
			cfg:  &RewriteConfig{Operations: []RewriteOperation{{Action: "rename", Name: "query", To: "expr"}}},
		},
		{
			name: "semantic rule valid",
			cfg:  promQLSemanticConfig(MatcherRequirement{Name: "namespace", Value: "{{namespace}}"}),
		},
		{
			name: "logql semantic rule valid",
			cfg: &RewriteConfig{Semantics: []SemanticRule{{
				Language: semanticLanguageLogQL,
				Params:   []string{"query"},
				Routes:   []string{"/loki/api/v1/query"},
				Require:  []MatcherRequirement{{Name: "segment", Value: "dev"}},
			}}},
		},
		{
			name: "traceql semantic rule valid",
			cfg: &RewriteConfig{Semantics: []SemanticRule{{
				Language: semanticLanguageTraceQL,
				Params:   []string{"q"},
				Routes:   []string{"/api/search"},
				Require:  []MatcherRequirement{{Name: "resource.segment", Value: "dev"}},
			}}},
		},
		{
			name: "semantic rule requires params",
			cfg: &RewriteConfig{Semantics: []SemanticRule{{
				Language: semanticLanguagePromQL,
				Require:  []MatcherRequirement{{Name: "namespace", Value: "utv"}},
			}}},
			wantErr: true,
		},
		{
			name: "tenant label shorthand valid",
			cfg:  &RewriteConfig{TenantLabel: &TenantLabelRule{}},
		},
		{
			name: "tenant label shorthand rejects invalid mode",
			cfg: &RewriteConfig{TenantLabel: &TenantLabelRule{
				Mode: "rewrite",
			}},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertValidateResult(t, tt.cfg, tt.wantErr)
		})
	}
}

func TestRewriteRequestFormBody(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "http://otlp.example.com/mimir/api/v1/query?existing=1", strings.NewReader("query=up&debug=true"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rewritten, err := RewriteRequest(req, &RewriteConfig{Operations: []RewriteOperation{
		{Action: "rename", Name: "query", To: "expr"},
		{Action: "add", Name: "tenant", Value: "{{namespace}}"},
		{Action: "set", Name: "source", Value: "{{host}}/{{backend}}"},
		{Action: "delete", Name: "debug"},
	}}, Context{
		Backend:   "mimir-shared",
		Namespace: "utv",
		Host:      "otlp.example.com",
	})
	if err != nil {
		t.Fatalf("RewriteRequest returned error: %v", err)
	}

	body, err := io.ReadAll(rewritten.Body)
	if err != nil {
		t.Fatalf("read rewritten body: %v", err)
	}
	if got := rewritten.URL.RawQuery; got != "existing=1" {
		t.Fatalf("expected unchanged url query, got %q", got)
	}
	if got := string(body); got != "expr=up&source=otlp.example.com%2Fmimir-shared&tenant=utv" {
		t.Fatalf("expected rewritten form body, got %q", got)
	}

	originalBody, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("read restored original body: %v", err)
	}
	if got := string(originalBody); got != "query=up&debug=true" {
		t.Fatalf("expected original body to be restored, got %q", got)
	}
}
