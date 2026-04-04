package authz

import (
	"context"
	"sort"
	"time"

	"github.com/karloie/multipass/internal/auth"
)

type CompositeRoleProvider struct {
	providers []ElevatedRoleProvider
}

func NewCompositeRoleProvider(providers ...ElevatedRoleProvider) *CompositeRoleProvider {
	filtered := make([]ElevatedRoleProvider, 0, len(providers))
	for _, provider := range providers {
		if provider == nil {
			continue
		}
		filtered = append(filtered, provider)
	}

	return &CompositeRoleProvider{providers: filtered}
}

func (p *CompositeRoleProvider) GetActiveElevatedRoles(ctx context.Context, userInfo *auth.UserInfo) ([]ElevatedRole, error) {
	combined := make(map[string]time.Time)
	for _, provider := range p.providers {
		roles, err := provider.GetActiveElevatedRoles(ctx, userInfo)
		if err != nil {
			return nil, err
		}
		for _, role := range roles {
			if existing, ok := combined[role.Role]; !ok || role.ExpiresAt.After(existing) {
				combined[role.Role] = role.ExpiresAt
			}
		}
	}

	result := make([]ElevatedRole, 0, len(combined))
	for role, expiresAt := range combined {
		result = append(result, ElevatedRole{Role: role, ExpiresAt: expiresAt})
	}

	sort.Slice(result, func(i, j int) bool {
		if result[i].Role == result[j].Role {
			return result[i].ExpiresAt.Before(result[j].ExpiresAt)
		}
		return result[i].Role < result[j].Role
	})

	return result, nil
}
