package authz

import (
	"context"
	"testing"

	"github.com/karloie/multipass/internal/auth"
)

func TestTokenProviderGetUserGroups(t *testing.T) {
	provider := NewTokenProvider()

	groups, err := provider.GetUserGroups(context.Background(), &auth.UserInfo{
		Groups: []string{" Rolle Utvikler ", "", "Rolle Plattformadmin utvikling", "Rolle Utvikler"},
	})
	if err != nil {
		t.Fatalf("GetUserGroups returned error: %v", err)
	}

	if len(groups) != 2 {
		t.Fatalf("expected 2 groups, got %d (%v)", len(groups), groups)
	}
	if groups[0] != "Rolle Plattformadmin utvikling" {
		t.Fatalf("unexpected first group: %q", groups[0])
	}
	if groups[1] != "Rolle Utvikler" {
		t.Fatalf("unexpected second group: %q", groups[1])
	}
}

func TestTokenProviderGetActiveElevatedRolesReturnsEmpty(t *testing.T) {
	provider := NewTokenProvider()

	roles, err := provider.GetActiveElevatedRoles(context.Background(), &auth.UserInfo{ID: "user-123"})
	if err != nil {
		t.Fatalf("GetActiveElevatedRoles returned error: %v", err)
	}
	if len(roles) != 0 {
		t.Fatalf("expected no elevated roles, got %v", roles)
	}
}
