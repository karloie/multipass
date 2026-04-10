package config

import (
	"testing"
)

func TestOpsNamespaceExclusionPattern(t *testing.T) {
	tests := []struct {
		name     string
		config   NamespaceClassifierConfig
		cluster  string
		expected string
	}{
		{
			name:     "no ops namespaces returns empty",
			config:   NamespaceClassifierConfig{},
			cluster:  "",
			expected: "",
		},
		{
			name: "exact matches only",
			config: NamespaceClassifierConfig{
				OpsExact: []string{"kube-system", "monitoring", "argocd"},
			},
			cluster:  "",
			expected: "kube-system|monitoring|argocd",
		},
		{
			name: "prefix matches only",
			config: NamespaceClassifierConfig{
				OpsPrefixes: []string{"kube-", "istio-"},
			},
			cluster:  "",
			expected: "kube-.*|istio-.*",
		},
		{
			name: "suffix matches only",
			config: NamespaceClassifierConfig{
				OpsSuffixes: []string{"-system"},
			},
			cluster:  "",
			expected: ".*-system",
		},
		{
			name: "mixed exact, prefix, and suffix",
			config: NamespaceClassifierConfig{
				OpsExact:    []string{"monitoring", "argocd"},
				OpsPrefixes: []string{"kube-"},
				OpsSuffixes: []string{"-system"},
			},
			cluster:  "",
			expected: "monitoring|argocd|kube-.*|.*-system",
		},
		{
			name: "cluster override adds to base",
			config: NamespaceClassifierConfig{
				OpsExact: []string{"monitoring"},
				ClusterOverrides: map[string]NamespaceClassifierOverride{
					"core-test": {
						OpsExact: []string{"special-namespace"},
					},
				},
			},
			cluster:  "core-test",
			expected: "monitoring|special-namespace",
		},
		{
			name: "cluster override with prefix and suffix",
			config: NamespaceClassifierConfig{
				OpsPrefixes: []string{"kube-"},
				ClusterOverrides: map[string]NamespaceClassifierOverride{
					"mgmt-plat": {
						OpsExact:    []string{"argocd"},
						OpsPrefixes: []string{"prometheus-"},
						OpsSuffixes: []string{"-operator"},
					},
				},
			},
			cluster:  "mgmt-plat",
			expected: "argocd|kube-.*|prometheus-.*|.*-operator",
		},
		{
			name: "whitespace trimming and normalization",
			config: NamespaceClassifierConfig{
				OpsExact:    []string{"  monitoring  ", "ARGOCD"},
				OpsPrefixes: []string{" kube- "},
			},
			cluster:  "",
			expected: "monitoring|argocd|kube-.*",
		},
		{
			name: "empty values ignored",
			config: NamespaceClassifierConfig{
				OpsExact:    []string{"monitoring", "", "argocd", "   "},
				OpsPrefixes: []string{"", "kube-"},
			},
			cluster:  "",
			expected: "monitoring|argocd|kube-.*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pattern := tt.config.OpsNamespaceExclusionPattern(tt.cluster)
			if pattern != tt.expected {
				t.Errorf("expected pattern %q, got %q", tt.expected, pattern)
			}
		})
	}
}
