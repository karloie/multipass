package query

import (
	"fmt"
	"net/url"
	"strings"

	promlabels "github.com/prometheus/prometheus/model/labels"
	promparser "github.com/prometheus/prometheus/promql/parser"
)

type semanticEngine interface {
	Enforce(value string, rule SemanticRule, ctx Context) (string, error)
}

func applySemanticRules(values url.Values, rules []SemanticRule, ctx Context) (url.Values, error) {
	if len(rules) == 0 {
		return values, nil
	}

	rewritten := cloneValues(values)
	for _, rule := range rules {
		if !matchesRoute(ctx.Route, rule.Routes) {
			continue
		}

		engine, err := semanticEngineFor(rule.Language)
		if err != nil {
			return nil, err
		}

		if err := applySemanticRule(rewritten, engine, rule, ctx); err != nil {
			return nil, err
		}
	}

	return rewritten, nil
}

func applySemanticRule(values url.Values, engine semanticEngine, rule SemanticRule, ctx Context) error {
	for _, name := range normalizedParamNames(rule.Params) {
		currentValues := values[name]
		if len(currentValues) == 0 {
			continue
		}

		nextValues, err := rewriteSemanticValues(currentValues, func(currentValue string) (string, error) {
			return engine.Enforce(currentValue, rule, ctx)
		})
		if err != nil {
			return fmt.Errorf("parameter %q: %w", name, err)
		}
		values[name] = nextValues
	}

	return nil
}

func normalizedParamNames(params []string) []string {
	return normalizeNonEmptyStrings(params)
}

func rewriteSemanticValues(values []string, rewrite func(string) (string, error)) ([]string, error) {
	rewritten := make([]string, 0, len(values))
	for _, value := range values {
		nextValue, err := rewrite(value)
		if err != nil {
			return nil, err
		}
		rewritten = append(rewritten, nextValue)
	}
	return rewritten, nil
}

func semanticEngineFor(language string) (semanticEngine, error) {
	switch strings.ToLower(strings.TrimSpace(language)) {
	case semanticLanguagePromQL:
		return promQLEngine{}, nil
	case semanticLanguageSelector:
		return selectorEngine{}, nil
	default:
		return nil, fmt.Errorf("unsupported semantic language %q: supported languages are %s", language, semanticLanguageConstraint)
	}
}

type promQLEngine struct{}

func (promQLEngine) Enforce(value string, rule SemanticRule, ctx Context) (string, error) {
	expr, err := promparser.ParseExpr(value)
	if err != nil {
		return "", err
	}

	var enforceErr error
	promparser.Inspect(expr, func(node promparser.Node, path []promparser.Node) error {
		if enforceErr != nil {
			return enforceErr
		}

		selector, ok := node.(*promparser.VectorSelector)
		if !ok {
			return nil
		}

		selector.LabelMatchers, enforceErr = enforceRequiredMatchers(selector.LabelMatchers, rule, ctx)
		return enforceErr
	})
	if enforceErr != nil {
		return "", enforceErr
	}

	return expr.String(), nil
}

type selectorEngine struct{}

func (selectorEngine) Enforce(value string, rule SemanticRule, ctx Context) (string, error) {
	matchers, err := promparser.ParseMetricSelector(value)
	if err != nil {
		return "", err
	}

	matchers, err = enforceRequiredMatchers(matchers, rule, ctx)
	if err != nil {
		return "", err
	}

	return renderSelector(matchers), nil
}

func enforceRequiredMatchers(existing []*promlabels.Matcher, rule SemanticRule, ctx Context) ([]*promlabels.Matcher, error) {
	required, err := requiredMatchersForRule(rule, ctx)
	if err != nil {
		return nil, err
	}

	return enforceMatchers(existing, required)
}

func requiredMatchersForRule(rule SemanticRule, ctx Context) ([]*promlabels.Matcher, error) {
	return buildRequiredMatchers(rule.Require, ctx)
}

func renderSelector(matchers []*promlabels.Matcher) string {
	parts := make([]string, 0, len(matchers))
	for _, matcher := range matchers {
		parts = append(parts, matcher.String())
	}
	return "{" + strings.Join(parts, ",") + "}"
}

func buildRequiredMatchers(requirements []MatcherRequirement, ctx Context) ([]*promlabels.Matcher, error) {
	renderer := newRenderer(ctx)
	matchers := make([]*promlabels.Matcher, 0, len(requirements))
	for _, requirement := range requirements {
		matchType, err := parseMatcherOperator(requirement.Operator)
		if err != nil {
			return nil, err
		}

		matcher, err := promlabels.NewMatcher(
			matchType,
			strings.TrimSpace(requirement.Name),
			renderer.render(requirement.Value),
		)
		if err != nil {
			return nil, err
		}
		matchers = append(matchers, matcher)
	}
	return matchers, nil
}

func parseMatcherOperator(operator string) (promlabels.MatchType, error) {
	switch strings.TrimSpace(operator) {
	case "", "=":
		return promlabels.MatchEqual, nil
	case "!=":
		return promlabels.MatchNotEqual, nil
	case "=~":
		return promlabels.MatchRegexp, nil
	case "!~":
		return promlabels.MatchNotRegexp, nil
	default:
		return 0, fmt.Errorf("operator must be one of: =, !=, =~, !~")
	}
}

func enforceMatchers(existing []*promlabels.Matcher, required []*promlabels.Matcher) ([]*promlabels.Matcher, error) {
	if len(required) == 0 {
		return existing, nil
	}

	updated := append([]*promlabels.Matcher(nil), existing...)
	for _, requiredMatcher := range required {
		found := false
		for _, currentMatcher := range updated {
			if currentMatcher.Name != requiredMatcher.Name {
				continue
			}
			if matchersEqual(currentMatcher, requiredMatcher) {
				found = true
				break
			}
			return nil, fmt.Errorf("matcher %s conflicts with required matcher %s", currentMatcher.String(), requiredMatcher.String())
		}
		if !found {
			updated = append(updated, requiredMatcher)
		}
	}

	return updated, nil
}

func matchersEqual(left, right *promlabels.Matcher) bool {
	if left == nil || right == nil {
		return left == right
	}
	return left.Name == right.Name && left.Type == right.Type && left.Value == right.Value
}
