package authz

import (
	"context"

	"github.com/karloie/multipass/internal/auth"
)

type CachedGroupProvider struct {
	next  GroupProvider
	cache GroupCache
}

func NewCachedGroupProvider(next GroupProvider, cache GroupCache) *CachedGroupProvider {
	return &CachedGroupProvider{next: next, cache: cache}
}

func (p *CachedGroupProvider) GetUserGroups(ctx context.Context, userInfo *auth.UserInfo) ([]string, error) {
	if p == nil || p.next == nil {
		return []string{}, nil
	}

	groups, err := p.next.GetUserGroups(ctx, userInfo)
	if err != nil {
		return nil, err
	}
	if len(groups) > 0 {
		if p.cache != nil {
			p.cache.Store(userInfo, groups)
		}
		return groups, nil
	}
	if p.cache == nil || !GroupCacheLookupAllowed(ctx) {
		return groups, nil
	}

	cachedGroups := p.cache.Lookup(userInfo)
	if len(cachedGroups) == 0 {
		return groups, nil
	}
	return cachedGroups, nil
}