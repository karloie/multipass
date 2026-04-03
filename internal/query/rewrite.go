package query

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
)

const (
	operationActionAdd    = "add"
	operationActionSet    = "set"
	operationActionDelete = "delete"
	operationActionRename = "rename"

	semanticLanguagePromQL   = "promql"
	semanticLanguageSelector = "selector"
	semanticLanguageLogQL    = "logql"
	semanticLanguageTraceQL  = "traceql"

	tenantLabelDefaultName  = "namespace"
	tenantLabelDefaultValue = "{{namespace}}"
	tenantLabelModeDefault  = "validate-or-append"

	semanticLanguageConstraint = "promql, selector, logql, traceql"
)

var (
	defaultPromQLParams   = []string{"query"}
	defaultPromQLRoutes   = []string{"/api/v1/query", "/api/v1/query_range"}
	defaultSelectorParams = []string{"match[]"}
	defaultSelectorRoutes = []string{"/api/v1/series", "/api/v1/labels", "/api/v1/label/*"}
)

type Context struct {
	Backend   string
	Namespace string
	Host      string
	Route     string
	Method    string
}

type RewriteConfig struct {
	Operations  []RewriteOperation `yaml:"operations,omitempty"`
	Semantics   []SemanticRule     `yaml:"semantics,omitempty"`
	TenantLabel *TenantLabelRule   `yaml:"tenantLabel,omitempty"`
}

type RewriteOperation struct {
	Action string   `yaml:"action,omitempty"`
	Name   string   `yaml:"name,omitempty"`
	Value  string   `yaml:"value,omitempty"`
	To     string   `yaml:"to,omitempty"`
	Routes []string `yaml:"routes,omitempty"`
}

type SemanticRule struct {
	Language string               `yaml:"language,omitempty"`
	Params   []string             `yaml:"params,omitempty"`
	Routes   []string             `yaml:"routes,omitempty"`
	Require  []MatcherRequirement `yaml:"require,omitempty"`
}

type TenantLabelRule struct {
	Name           string   `yaml:"name,omitempty"`
	Value          string   `yaml:"value,omitempty"`
	Mode           string   `yaml:"mode,omitempty"`
	PromQLParams   []string `yaml:"promqlParams,omitempty"`
	PromQLRoutes   []string `yaml:"promqlRoutes,omitempty"`
	SelectorParams []string `yaml:"selectorParams,omitempty"`
	SelectorRoutes []string `yaml:"selectorRoutes,omitempty"`
}

type MatcherRequirement struct {
	Name     string `yaml:"name,omitempty"`
	Value    string `yaml:"value,omitempty"`
	Operator string `yaml:"operator,omitempty"`
}

func HasRules(cfg *RewriteConfig) bool {
	return cfg != nil && (len(cfg.Operations) > 0 || len(cfg.Semantics) > 0 || cfg.TenantLabel != nil)
}

func Validate(backendName string, cfg *RewriteConfig) error {
	if cfg == nil {
		return nil
	}
	if !HasRules(cfg) {
		return fmt.Errorf("backend '%s' queryRewrite requires at least one operation, semantic rule, or tenantLabel rule", backendName)
	}

	for i, operation := range cfg.Operations {
		prefix := fmt.Sprintf("backend '%s' queryRewrite operation %d", backendName, i+1)
		if err := validateOperation(prefix, operation); err != nil {
			return err
		}
		if err := validateRoutes(prefix, operation.Routes); err != nil {
			return err
		}
	}

	for i, rule := range cfg.Semantics {
		prefix := fmt.Sprintf("backend '%s' queryRewrite semantic rule %d", backendName, i+1)
		if err := validateSemanticRule(prefix, rule); err != nil {
			return err
		}
	}

	if cfg.TenantLabel != nil {
		prefix := fmt.Sprintf("backend '%s' queryRewrite tenantLabel", backendName)
		if err := validateTenantLabel(prefix, *cfg.TenantLabel); err != nil {
			return err
		}
	}

	return nil
}

func Rewrite(values url.Values, cfg *RewriteConfig, ctx Context) url.Values {
	rewritten, err := RewriteWithError(values, cfg, ctx)
	if err != nil {
		return values
	}
	return rewritten
}

func RewriteWithError(values url.Values, cfg *RewriteConfig, ctx Context) (url.Values, error) {
	if !HasRules(cfg) {
		return values, nil
	}

	rewritten := cloneValues(values)
	renderer := newRenderer(ctx)

	for _, operation := range cfg.Operations {
		if !matchesRoute(ctx.Route, operation.Routes) {
			continue
		}

		name := strings.TrimSpace(operation.Name)
		if name == "" {
			continue
		}

		applyOperation(rewritten, operation, name, renderer)
	}

	return applySemanticRules(rewritten, semanticRulesForConfig(cfg), ctx)
}

func RewriteRequest(r *http.Request, cfg *RewriteConfig, ctx Context) (*http.Request, error) {
	if r == nil || !HasRules(cfg) {
		return r, nil
	}

	cloned := r.Clone(r.Context())
	cloned.URL = cloneURL(r.URL)

	if !hasRewriteableFormBody(r) {
		rewrittenQuery, err := RewriteWithError(cloned.URL.Query(), cfg, ctx)
		if err != nil {
			return nil, err
		}
		cloned.URL.RawQuery = rewrittenQuery.Encode()
		return cloned, nil
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	_ = r.Body.Close()
	r.Body = io.NopCloser(bytes.NewReader(body))

	values, err := url.ParseQuery(string(body))
	if err != nil {
		return nil, err
	}
	rewrittenBodyValues, err := RewriteWithError(values, cfg, ctx)
	if err != nil {
		return nil, err
	}
	rewrittenBody := rewrittenBodyValues.Encode()

	cloned.Body = io.NopCloser(strings.NewReader(rewrittenBody))
	cloned.ContentLength = int64(len(rewrittenBody))
	cloned.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(rewrittenBody)), nil
	}
	cloned.PostForm = rewrittenBodyValues
	cloned.Form = cloneValues(rewrittenBodyValues)

	return cloned, nil
}

func cloneValues(values url.Values) url.Values {
	if values == nil {
		return url.Values{}
	}

	cloned := make(url.Values, len(values))
	for key, items := range values {
		cloned[key] = append([]string(nil), items...)
	}
	return cloned
}

func cloneURL(source *url.URL) *url.URL {
	if source == nil {
		return &url.URL{}
	}
	cloned := *source
	return &cloned
}

func hasRewriteableFormBody(r *http.Request) bool {
	if r == nil {
		return false
	}
	switch r.Method {
	case http.MethodPost, http.MethodPut, http.MethodPatch:
	default:
		return false
	}

	contentType := strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Type")))
	return strings.HasPrefix(contentType, "application/x-www-form-urlencoded")
}

type renderer struct {
	replacements *strings.Replacer
}

func newRenderer(ctx Context) renderer {
	return renderer{
		replacements: strings.NewReplacer(
			"{{backend}}", strings.TrimSpace(ctx.Backend),
			"{{namespace}}", strings.TrimSpace(ctx.Namespace),
			"{{host}}", strings.TrimSpace(ctx.Host),
			"{{route}}", normalizeRoute(ctx.Route),
			"{{method}}", strings.TrimSpace(ctx.Method),
		),
	}
}

func (r renderer) render(value string) string {
	return r.replacements.Replace(value)
}

func validateOperation(prefix string, operation RewriteOperation) error {
	action := normalizedLowerTrim(operation.Action)
	if action == "" {
		return fmt.Errorf("%s action is required", prefix)
	}
	if strings.TrimSpace(operation.Name) == "" {
		return fmt.Errorf("%s name is required", prefix)
	}

	switch action {
	case operationActionAdd, operationActionSet:
		return nil
	case operationActionDelete:
		if strings.TrimSpace(operation.To) != "" {
			return fmt.Errorf("%s cannot set 'to' when action is delete", prefix)
		}
		return nil
	case operationActionRename:
		if strings.TrimSpace(operation.To) == "" {
			return fmt.Errorf("%s to is required when action is rename", prefix)
		}
		return nil
	default:
		return fmt.Errorf("%s action must be one of: add, set, delete, rename", prefix)
	}
}

func applyOperation(values url.Values, operation RewriteOperation, name string, renderer renderer) {
	switch normalizedLowerTrim(operation.Action) {
	case operationActionAdd:
		values.Add(name, renderer.render(operation.Value))
	case operationActionSet:
		values.Del(name)
		values.Add(name, renderer.render(operation.Value))
	case operationActionDelete:
		values.Del(name)
	case operationActionRename:
		target := strings.TrimSpace(renderer.render(operation.To))
		if target == "" || target == name {
			return
		}
		renamedValues := append([]string(nil), values[name]...)
		values.Del(name)
		for _, value := range renamedValues {
			values.Add(target, value)
		}
	}
}

func normalizedLowerTrim(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func semanticRulesForConfig(cfg *RewriteConfig) []SemanticRule {
	if cfg == nil {
		return nil
	}

	rules := append([]SemanticRule(nil), cfg.Semantics...)
	if cfg.TenantLabel != nil {
		rules = append(rules, cfg.TenantLabel.expand()...)
	}
	return rules
}

func validateSemanticRule(prefix string, rule SemanticRule) error {
	language := normalizedLowerTrim(rule.Language)
	if language == "" {
		return fmt.Errorf("%s language is required", prefix)
	}
	switch language {
	case semanticLanguagePromQL, semanticLanguageSelector, semanticLanguageLogQL:
	case semanticLanguageTraceQL:
		for i, requirement := range rule.Require {
			switch strings.TrimSpace(requirement.Operator) {
			case "", "=":
				continue
			default:
				return fmt.Errorf("%s matcher %d: operator must be one of: =", prefix, i+1)
			}
		}
	default:
		return fmt.Errorf("%s language must be one of: %s", prefix, semanticLanguageConstraint)
	}
	if len(rule.Params) == 0 {
		return fmt.Errorf("%s requires at least one parameter target", prefix)
	}
	for _, param := range rule.Params {
		if strings.TrimSpace(param) == "" {
			return fmt.Errorf("%s contains an empty parameter target", prefix)
		}
	}
	if len(rule.Require) == 0 {
		return fmt.Errorf("%s requires at least one matcher requirement", prefix)
	}
	for i, requirement := range rule.Require {
		if strings.TrimSpace(requirement.Name) == "" {
			return fmt.Errorf("%s matcher %d name is required", prefix, i+1)
		}
		if _, err := parseMatcherOperator(requirement.Operator); err != nil {
			return fmt.Errorf("%s matcher %d: %w", prefix, i+1, err)
		}
	}
	if err := validateRoutes(prefix, rule.Routes); err != nil {
		return err
	}
	return nil
}

func validateTenantLabel(prefix string, rule TenantLabelRule) error {
	mode := normalizedLowerTrim(rule.Mode)
	switch mode {
	case "", tenantLabelModeDefault:
	default:
		return fmt.Errorf("%s mode must be %s", prefix, tenantLabelModeDefault)
	}

	for i, semanticRule := range rule.expand() {
		if err := validateSemanticRule(fmt.Sprintf("%s generated rule %d", prefix, i+1), semanticRule); err != nil {
			return err
		}
	}

	return nil
}

func (r TenantLabelRule) expand() []SemanticRule {
	name := strings.TrimSpace(r.Name)
	if name == "" {
		name = tenantLabelDefaultName
	}

	value := strings.TrimSpace(r.Value)
	if value == "" {
		value = tenantLabelDefaultValue
	}

	rules := make([]SemanticRule, 0, 2)
	if params := normalizedOrDefault(r.PromQLParams, defaultPromQLParams); len(params) > 0 {
		rules = append(rules, SemanticRule{
			Language: semanticLanguagePromQL,
			Params:   params,
			Routes:   normalizedOrDefault(r.PromQLRoutes, defaultPromQLRoutes),
			Require:  []MatcherRequirement{{Name: name, Value: value}},
		})
	}
	if params := normalizedOrDefault(r.SelectorParams, defaultSelectorParams); len(params) > 0 {
		rules = append(rules, SemanticRule{
			Language: semanticLanguageSelector,
			Params:   params,
			Routes:   normalizedOrDefault(r.SelectorRoutes, defaultSelectorRoutes),
			Require:  []MatcherRequirement{{Name: name, Value: value}},
		})
	}
	return rules
}

func normalizedOrDefault(values []string, defaults []string) []string {
	normalized := normalizeNonEmptyStrings(values)
	if len(normalized) > 0 {
		return normalized
	}
	return append([]string(nil), defaults...)
}

func normalizeNonEmptyStrings(values []string) []string {
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed != "" {
			normalized = append(normalized, trimmed)
		}
	}
	return normalized
}

func validateRoutes(prefix string, routes []string) error {
	for _, route := range routes {
		if strings.TrimSpace(route) == "" {
			return fmt.Errorf("%s contains an empty route matcher", prefix)
		}
	}
	return nil
}

func matchesRoute(route string, patterns []string) bool {
	if len(patterns) == 0 {
		return true
	}

	normalizedRoute := normalizeRoute(route)
	for _, pattern := range patterns {
		normalizedPattern := normalizeRoutePattern(pattern)
		switch {
		case normalizedPattern == "*":
			return true
		case strings.HasSuffix(normalizedPattern, "/*"):
			prefix := strings.TrimSuffix(normalizedPattern, "/*")
			if normalizedRoute == prefix || strings.HasPrefix(normalizedRoute, prefix+"/") {
				return true
			}
		case normalizedRoute == normalizedPattern:
			return true
		}
	}

	return false
}

func normalizeRoute(route string) string {
	trimmed := strings.TrimSpace(route)
	if trimmed == "" {
		return "/"
	}
	if !strings.HasPrefix(trimmed, "/") {
		trimmed = "/" + trimmed
	}
	cleaned := path.Clean(trimmed)
	if cleaned == "." {
		return "/"
	}
	return cleaned
}

func normalizeRoutePattern(route string) string {
	trimmed := strings.TrimSpace(route)
	if trimmed == "*" {
		return "*"
	}
	if strings.HasSuffix(trimmed, "/*") {
		base := strings.TrimSuffix(trimmed, "/*")
		return normalizeRoute(base) + "/*"
	}
	return normalizeRoute(trimmed)
}
