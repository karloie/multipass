package authz

import (
	"context"
	"sort"
	"strings"

	"github.com/karloie/multipass/internal/auth"
)

type TokenProvider struct{}

func NewTokenProvider() *TokenProvider {
	return &TokenProvider{}
}

func (p *TokenProvider) GetUserGroups(ctx context.Context, userInfo *auth.UserInfo) ([]string, error) {
	_ = ctx
	if userInfo == nil || len(userInfo.Groups) == 0 {
		return []string{}, nil
	}

	seen := make(map[string]struct{}, len(userInfo.Groups))
	groups := make([]string, 0, len(userInfo.Groups))
	for _, group := range userInfo.Groups {
		trimmedGroup := strings.TrimSpace(group)
		if trimmedGroup == "" {
			continue
		}
		if _, ok := seen[trimmedGroup]; ok {
			continue
		}
		seen[trimmedGroup] = struct{}{}
		groups = append(groups, trimmedGroup)
	}

	sort.Strings(groups)
	return groups, nil
}

func (p *TokenProvider) GetActiveElevatedRoles(ctx context.Context, userInfo *auth.UserInfo) ([]ElevatedRole, error) {
	_ = ctx
	_ = userInfo
	return []ElevatedRole{}, nil
}
