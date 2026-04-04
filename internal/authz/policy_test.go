package authz

import (
	"context"
	"testing"
	"time"

	"github.com/karloie/multipass/internal/auth"
)

type countingProvider struct {
	groups            []string
	roles             []ElevatedRole
	groupCalls        int
	elevatedRoleCalls int
}

func (p *countingProvider) GetUserGroups(ctx context.Context, userInfo *auth.UserInfo) ([]string, error) {
	p.groupCalls++
	return append([]string(nil), p.groups...), nil
}

func (p *countingProvider) GetActiveElevatedRoles(ctx context.Context, userInfo *auth.UserInfo) ([]ElevatedRole, error) {
	p.elevatedRoleCalls++
	return append([]ElevatedRole(nil), p.roles...), nil
}

func TestPolicyEvaluatorCachesPermissions(t *testing.T) {
	provider := &countingProvider{
		groups: []string{"team-platform"},
		roles:  []ElevatedRole{{Role: "prod-admin"}},
	}
	evaluator := NewPolicyEvaluator(provider, provider, map[string][]string{
		"team-platform": {"dev", "test"},
		"prod-admin":    {"prod"},
	})

	now := time.Date(2026, time.March, 27, 12, 0, 0, 0, time.UTC)
	evaluator.now = func() time.Time { return now }
	evaluator.cacheTTL = time.Minute

	permission, err := evaluator.EvaluatePermissions(context.Background(), &auth.UserInfo{ID: "user-123"})
	if err != nil {
		t.Fatalf("unexpected evaluation error: %v", err)
	}
	permission.ExternalGroups[0] = "mutated"

	permission, err = evaluator.EvaluatePermissions(context.Background(), &auth.UserInfo{ID: "user-123"})
	if err != nil {
		t.Fatalf("unexpected cached evaluation error: %v", err)
	}

	if provider.groupCalls != 1 || provider.elevatedRoleCalls != 1 {
		t.Fatalf("expected one provider call per source, got groups=%d elevated_roles=%d", provider.groupCalls, provider.elevatedRoleCalls)
	}
	if permission.ExternalGroups[0] != "team-platform" {
		t.Fatalf("expected cached permission to be isolated from mutation, got %q", permission.ExternalGroups[0])
	}
	if len(permission.AllowedNamespaces) != 3 {
		t.Fatalf("unexpected namespace count: got %d want 3", len(permission.AllowedNamespaces))
	}
}

func TestPolicyEvaluatorCacheExpires(t *testing.T) {
	provider := &countingProvider{groups: []string{"team-sre"}}
	evaluator := NewPolicyEvaluator(provider, provider, map[string][]string{
		"team-sre": {"prod"},
	})

	now := time.Date(2026, time.March, 27, 12, 0, 0, 0, time.UTC)
	evaluator.now = func() time.Time { return now }
	evaluator.cacheTTL = 30 * time.Second

	if _, err := evaluator.EvaluatePermissions(context.Background(), &auth.UserInfo{ID: "user-456"}); err != nil {
		t.Fatalf("unexpected evaluation error: %v", err)
	}
	now = now.Add(31 * time.Second)
	if _, err := evaluator.EvaluatePermissions(context.Background(), &auth.UserInfo{ID: "user-456"}); err != nil {
		t.Fatalf("unexpected evaluation error after cache expiry: %v", err)
	}

	if provider.groupCalls != 2 || provider.elevatedRoleCalls != 2 {
		t.Fatalf("expected cache miss after expiry, got groups=%d elevated_roles=%d", provider.groupCalls, provider.elevatedRoleCalls)
	}
}

func TestPolicyEvaluatorResolvesInternalRolesFromExternalGroups(t *testing.T) {
	provider := &countingProvider{groups: []string{"Rolle Utvikler", "Rolle Gjest"}}
	evaluator := NewPolicyEvaluatorWithRoleMappings(provider, provider,
		map[string][]string{
			"dev": {"team-a.dev", "team-a.test"},
			"man": {"team-a.readonly"},
		},
		map[string][]string{
			"Rolle Utvikler": {"dev"},
			"Rolle Gjest":    {"man"},
		},
	)

	permission, err := evaluator.EvaluatePermissions(context.Background(), &auth.UserInfo{ID: "user-123"})
	if err != nil {
		t.Fatalf("unexpected evaluation error: %v", err)
	}

	wantExternalGroups := []string{"Rolle Utvikler", "Rolle Gjest"}
	if len(permission.ExternalGroups) != len(wantExternalGroups) {
		t.Fatalf("unexpected external group count: got %d want %d (%v)", len(permission.ExternalGroups), len(wantExternalGroups), permission.ExternalGroups)
	}
	for index, group := range wantExternalGroups {
		if permission.ExternalGroups[index] != group {
			t.Fatalf("unexpected external group at %d: got %q want %q", index, permission.ExternalGroups[index], group)
		}
	}

	wantInternalRoles := []string{"dev", "man"}
	if len(permission.InternalRoles) != len(wantInternalRoles) {
		t.Fatalf("unexpected internal role count: got %d want %d (%v)", len(permission.InternalRoles), len(wantInternalRoles), permission.InternalRoles)
	}
	for index, role := range wantInternalRoles {
		if permission.InternalRoles[index] != role {
			t.Fatalf("unexpected internal role at %d: got %q want %q", index, permission.InternalRoles[index], role)
		}
	}

	wantNamespaces := []string{"team-a.dev", "team-a.readonly", "team-a.test"}
	if len(permission.AllowedNamespaces) != len(wantNamespaces) {
		t.Fatalf("unexpected namespace count: got %d want %d (%v)", len(permission.AllowedNamespaces), len(wantNamespaces), permission.AllowedNamespaces)
	}
	for index, namespace := range wantNamespaces {
		if permission.AllowedNamespaces[index] != namespace {
			t.Fatalf("unexpected namespace at %d: got %q want %q", index, permission.AllowedNamespaces[index], namespace)
		}
	}
}

func TestNamespacesAllowed(t *testing.T) {
	tests := []struct {
		name      string
		allowed   []string
		namespace string
		want      bool
	}{
		{name: "single namespace exact match", allowed: []string{"core.dev"}, namespace: "core.dev", want: true},
		{name: "multi namespace requires all parts", allowed: []string{"core.dev"}, namespace: "core.dev|core.ops", want: false},
		{name: "multi namespace exact all parts", allowed: []string{"core.dev", "core.ops"}, namespace: "core.dev|core.ops", want: true},
		{name: "wildcard allows all", allowed: []string{"*"}, namespace: "local.dev|local.ops", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := namespacesAllowed(tt.allowed, tt.namespace); got != tt.want {
				t.Fatalf("unexpected access result: got %v want %v", got, tt.want)
			}
		})
	}
}
