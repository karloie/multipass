package authz

import (
	"context"
	"testing"
	"time"

	"github.com/karloie/multipass/internal/auth"
)

func TestCachedGroupProviderUsesDirectGroupsAndSeedsCache(t *testing.T) {
	cache := NewMemoryGroupCache(time.Hour)
	provider := NewCachedGroupProvider(NewTokenProvider(), cache)
	userInfo := &auth.UserInfo{ID: "(usr!koi)", Username: "koi", Groups: []string{" Rolle Plattformadmin utvikling "}}

	groups, err := provider.GetUserGroups(context.Background(), userInfo)
	if err != nil {
		t.Fatalf("GetUserGroups returned error: %v", err)
	}
	if len(groups) != 1 || groups[0] != "Rolle Plattformadmin utvikling" {
		t.Fatalf("unexpected groups: %v", groups)
	}

	cached := cache.Lookup(&auth.UserInfo{Username: "koi"})
	if len(cached) != 1 || cached[0] != "Rolle Plattformadmin utvikling" {
		t.Fatalf("unexpected cached groups: %v", cached)
	}
}

func TestCachedGroupProviderUsesCacheOnlyWhenContextAllows(t *testing.T) {
	cache := NewMemoryGroupCache(time.Hour)
	cache.Store(&auth.UserInfo{ID: "(usr!koi)", Username: "koi"}, []string{"Rolle Plattformadmin utvikling"})
	provider := NewCachedGroupProvider(NewTokenProvider(), cache)

	groups, err := provider.GetUserGroups(context.Background(), &auth.UserInfo{Username: "koi"})
	if err != nil {
		t.Fatalf("GetUserGroups returned error: %v", err)
	}
	if len(groups) != 0 {
		t.Fatalf("expected no groups without cache hint, got %v", groups)
	}

	ctx := WithGroupCacheLookupAllowed(context.Background(), true)
	groups, err = provider.GetUserGroups(ctx, &auth.UserInfo{Username: "koi"})
	if err != nil {
		t.Fatalf("GetUserGroups with cache hint returned error: %v", err)
	}
	if len(groups) != 1 || groups[0] != "Rolle Plattformadmin utvikling" {
		t.Fatalf("unexpected cached groups: %v", groups)
	}
}
