package query

import (
	"testing"
)

func TestEvaluateCondition(t *testing.T) {
	tests := []struct {
		name      string
		condition string
		ctx       Context
		want      bool
	}{
		{
			name:      "empty condition always true",
			condition: "",
			ctx:       Context{Segment: "dev"},
			want:      true,
		},
		{
			name:      "segment equals dev",
			condition: "segment == dev",
			ctx:       Context{Segment: "dev"},
			want:      true,
		},
		{
			name:      "segment equals ops match",
			condition: "segment == ops",
			ctx:       Context{Segment: "ops"},
			want:      true,
		},
		{
			name:      "segment equals ops no match",
			condition: "segment == ops",
			ctx:       Context{Segment: "dev"},
			want:      false,
		},
		{
			name:      "segment not equals admin match",
			condition: "segment != admin",
			ctx:       Context{Segment: "dev"},
			want:      true,
		},
		{
			name:      "segment not equals admin no match",
			condition: "segment != admin",
			ctx:       Context{Segment: "admin"},
			want:      false,
		},
		{
			name:      "segment equals ops or admin (ops)",
			condition: "segment == ops|admin",
			ctx:       Context{Segment: "ops"},
			want:      true,
		},
		{
			name:      "segment equals ops or admin (admin)",
			condition: "segment == ops|admin",
			ctx:       Context{Segment: "admin"},
			want:      true,
		},
		{
			name:      "segment equals ops or admin (dev)",
			condition: "segment == ops|admin",
			ctx:       Context{Segment: "dev"},
			want:      false,
		},
		{
			name:      "whitespace handling",
			condition: "  segment  ==  dev  ",
			ctx:       Context{Segment: "dev"},
			want:      true,
		},
		{
			name:      "invalid operator",
			condition: "segment === dev",
			ctx:       Context{Segment: "dev"},
			want:      false,
		},
		{
			name:      "invalid variable",
			condition: "cluster == test",
			ctx:       Context{Segment: "dev"},
			want:      false,
		},
		{
			name:      "malformed condition",
			condition: "segmentdev",
			ctx:       Context{Segment: "dev"},
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := evaluateCondition(tt.condition, tt.ctx)
			if got != tt.want {
				t.Errorf("evaluateCondition() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConditionalLabelInjection(t *testing.T) {
	tests := []struct {
		name         string
		query        string
		requirements []MatcherRequirement
		ctx          Context
		want         string
		wantErr      bool
	}{
		{
			name:  "dev segment gets namespace filter",
			query: "{app=\"myapp\"}",
			requirements: []MatcherRequirement{
				{
					Name:      "namespace",
					Operator:  "!~",
					Value:     "kube-.*|monitoring",
					Condition: "segment == dev",
				},
			},
			ctx: Context{
				Segment: "dev",
			},
			want:    `{app="myapp",namespace!~"kube-.*|monitoring"}`,
			wantErr: false,
		},
		{
			name:  "ops segment no filter",
			query: "{app=\"myapp\"}",
			requirements: []MatcherRequirement{
				{
					Name:      "namespace",
					Operator:  "!~",
					Value:     "kube-.*|monitoring",
					Condition: "segment == dev",
				},
			},
			ctx: Context{
				Segment: "ops",
			},
			want:    `{app="myapp"}`,
			wantErr: false,
		},
		{
			name:  "admin segment no filter",
			query: "{app=\"myapp\"}",
			requirements: []MatcherRequirement{
				{
					Name:      "namespace",
					Operator:  "!~",
					Value:     "kube-.*|monitoring",
					Condition: "segment == dev",
				},
			},
			ctx: Context{
				Segment: "admin",
			},
			want:    `{app="myapp"}`,
			wantErr: false,
		},
		{
			name:  "multiple conditions - ops or admin",
			query: "{app=\"myapp\"}",
			requirements: []MatcherRequirement{
				{
					Name:      "cluster",
					Operator:  "=",
					Value:     "platform",
					Condition: "segment == ops|admin",
				},
			},
			ctx: Context{
				Segment: "ops",
			},
			want:    `{app="myapp",cluster="platform"}`,
			wantErr: false,
		},
		{
			name:  "inject segment label for dev users",
			query: "{app=\"myapp\"}",
			requirements: []MatcherRequirement{
				{
					Name:      "segment",
					Operator:  "=",
					Value:     "dev",
					Condition: "segment == dev",
				},
			},
			ctx: Context{
				Segment: "dev",
			},
			want:    `{app="myapp",segment="dev"}`,
			wantErr: false,
		},
		{
			name:  "no condition always applied",
			query: "{app=\"myapp\"}",
			requirements: []MatcherRequirement{
				{
					Name:     "cluster",
					Operator: "=",
					Value:    "test",
				},
			},
			ctx: Context{
				Segment: "dev",
			},
			want:    `{app="myapp",cluster="test"}`,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matchers, err := buildRequiredMatchers(tt.requirements, tt.ctx)
			if (err != nil) != tt.wantErr {
				t.Errorf("buildRequiredMatchers() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			engine := selectorEngine{}
			got, err := engine.Enforce(tt.query, SemanticRule{Require: tt.requirements}, tt.ctx)
			if (err != nil) != tt.wantErr {
				t.Errorf("selectorEngine.Enforce() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && got != tt.want {
				t.Errorf("selectorEngine.Enforce() = %v, want %v", got, tt.want)
			}

			// Verify the matcher count
			if !tt.wantErr {
				expectedMatcherCount := 0
				for _, req := range tt.requirements {
					if evaluateCondition(req.Condition, tt.ctx) {
						expectedMatcherCount++
					}
				}
				// Add the original matcher from the query
				expectedMatcherCount++

				if len(matchers) != expectedMatcherCount-1 {
					t.Errorf("buildRequiredMatchers() returned %d matchers, want %d", len(matchers), expectedMatcherCount-1)
				}
			}
		})
	}
}

func TestLogQLConditionalFiltering(t *testing.T) {
	tests := []struct {
		name    string
		query   string
		rule    SemanticRule
		ctx     Context
		want    string
		wantErr bool
	}{
		{
			name:  "dev user gets namespace filter in logql",
			query: `{app="myapp"}`,
			rule: SemanticRule{
				Language: "logql",
				Require: []MatcherRequirement{
					{
						Name:      "namespace",
						Operator:  "!~",
						Value:     "kube-.*|monitoring",
						Condition: "segment == dev",
					},
				},
			},
			ctx: Context{
				Segment: "dev",
			},
			want:    `{app="myapp",namespace!~"kube-.*|monitoring"}`,
			wantErr: false,
		},
		{
			name:  "ops user no filter in logql",
			query: `{app="myapp"}`,
			rule: SemanticRule{
				Language: "logql",
				Require: []MatcherRequirement{
					{
						Name:      "namespace",
						Operator:  "!~",
						Value:     "kube-.*|monitoring",
						Condition: "segment == dev",
					},
				},
			},
			ctx: Context{
				Segment: "ops",
			},
			want:    `{app="myapp"}`,
			wantErr: false,
		},
		{
			name:  "complex logql query with pipeline",
			query: `{app="myapp"} | json | level="error"`,
			rule: SemanticRule{
				Language: "logql",
				Require: []MatcherRequirement{
					{
						Name:      "segment",
						Operator:  "=",
						Value:     "dev",
						Condition: "segment == dev",
					},
				},
			},
			ctx: Context{
				Segment: "dev",
			},
			want:    `{app="myapp",segment="dev"} | json | level="error"`,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine := logQLEngine{}
			got, err := engine.Enforce(tt.query, tt.rule, tt.ctx)
			if (err != nil) != tt.wantErr {
				t.Errorf("logQLEngine.Enforce() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("logQLEngine.Enforce() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPromQLConditionalFiltering(t *testing.T) {
	tests := []struct {
		name    string
		query   string
		rule    SemanticRule
		ctx     Context
		want    string
		wantErr bool
	}{
		{
			name:  "dev user gets namespace filter in promql",
			query: `up{job="myapp"}`,
			rule: SemanticRule{
				Language: "promql",
				Require: []MatcherRequirement{
					{
						Name:      "namespace",
						Operator:  "!~",
						Value:     "kube-.*|monitoring",
						Condition: "segment == dev",
					},
				},
			},
			ctx: Context{
				Segment: "dev",
			},
			want:    `up{job="myapp",namespace!~"kube-.*|monitoring"}`,
			wantErr: false,
		},
		{
			name:  "admin user no filter in promql",
			query: `up{job="myapp"}`,
			rule: SemanticRule{
				Language: "promql",
				Require: []MatcherRequirement{
					{
						Name:      "namespace",
						Operator:  "!~",
						Value:     "kube-.*|monitoring",
						Condition: "segment == dev",
					},
				},
			},
			ctx: Context{
				Segment: "admin",
			},
			want:    `up{job="myapp"}`,
			wantErr: false,
		},
		{
			name:  "complex promql with aggregation",
			query: `sum(rate(http_requests_total{job="api"}[5m])) by (status)`,
			rule: SemanticRule{
				Language: "promql",
				Require: []MatcherRequirement{
					{
						Name:      "segment",
						Operator:  "=",
						Value:     "dev",
						Condition: "segment == dev",
					},
				},
			},
			ctx: Context{
				Segment: "dev",
			},
			want:    `sum by (status) (rate(http_requests_total{job="api",segment="dev"}[5m]))`,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine := promQLEngine{}
			got, err := engine.Enforce(tt.query, tt.rule, tt.ctx)
			if (err != nil) != tt.wantErr {
				t.Errorf("promQLEngine.Enforce() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("promQLEngine.Enforce() = %v, want %v", got, tt.want)
			}
		})
	}
}
