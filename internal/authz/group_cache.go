package authz

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/karloie/multipass/internal/auth"
)

const defaultUserGroupsCacheTTL = 24 * time.Hour

type groupCacheLookupContextKey string

const groupCacheLookupAllowedKey groupCacheLookupContextKey = "groupCacheLookupAllowed"

type GroupCache interface {
	Store(userInfo *auth.UserInfo, groups []string)
	Lookup(userInfo *auth.UserInfo) []string
}

type cachedUserGroups struct {
	groups    []string
	expiresAt time.Time
}

type MemoryGroupCache struct {
	ttl     time.Duration
	now     func() time.Time
	mu      sync.RWMutex
	entries map[string]cachedUserGroups
}

func NewMemoryGroupCache(ttl time.Duration) *MemoryGroupCache {
	if ttl <= 0 {
		ttl = defaultUserGroupsCacheTTL
	}

	return &MemoryGroupCache{
		ttl:     ttl,
		now:     time.Now,
		entries: make(map[string]cachedUserGroups),
	}
}

func (c *MemoryGroupCache) Store(userInfo *auth.UserInfo, groups []string) {
	if c == nil || c.ttl <= 0 {
		return
	}

	identifiers := cacheUserIdentifiers(userInfo)
	normalizedGroups := normalizeCachedGroups(groups)
	if len(identifiers) == 0 || len(normalizedGroups) == 0 {
		return
	}

	entry := cachedUserGroups{
		groups:    normalizedGroups,
		expiresAt: c.now().Add(c.ttl),
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	for _, identifier := range identifiers {
		c.entries[identifier] = entry
	}
}

func (c *MemoryGroupCache) Lookup(userInfo *auth.UserInfo) []string {
	if c == nil || c.ttl <= 0 {
		return nil
	}

	identifiers := cacheUserIdentifiers(userInfo)
	if len(identifiers) == 0 {
		return nil
	}

	now := c.now()
	for _, identifier := range identifiers {
		c.mu.RLock()
		entry, ok := c.entries[identifier]
		c.mu.RUnlock()
		if !ok {
			continue
		}
		if now.After(entry.expiresAt) {
			c.mu.Lock()
			delete(c.entries, identifier)
			c.mu.Unlock()
			continue
		}
		return append([]string(nil), entry.groups...)
	}

	return nil
}

func WithGroupCacheLookupAllowed(ctx context.Context, allowed bool) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, groupCacheLookupAllowedKey, allowed)
}

func GroupCacheLookupAllowed(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	allowed, _ := ctx.Value(groupCacheLookupAllowedKey).(bool)
	return allowed
}

func cacheUserIdentifiers(userInfo *auth.UserInfo) []string {
	if userInfo == nil {
		return nil
	}

	seen := map[string]struct{}{}
	identifiers := make([]string, 0, 8)
	for _, candidate := range []string{userInfo.ID, userInfo.Username, userInfo.PrincipalID, userInfo.Email} {
		for _, key := range normalizedCacheUserKeys(candidate) {
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			identifiers = append(identifiers, key)
		}
	}

	return identifiers
}

func normalizedCacheUserKeys(candidate string) []string {
	trimmed := strings.TrimSpace(candidate)
	if trimmed == "" {
		return nil
	}

	keys := []string{trimmed, strings.ToLower(trimmed)}
	if alias := normalizeWrappedUserIdentifier(trimmed); alias != "" && alias != trimmed {
		keys = append(keys, alias, strings.ToLower(alias))
	}

	return keys
}

func normalizeWrappedUserIdentifier(identifier string) string {
	trimmed := strings.TrimSpace(identifier)
	if len(trimmed) < 6 || trimmed[0] != '(' || trimmed[len(trimmed)-1] != ')' {
		return ""
	}

	bang := strings.IndexByte(trimmed, '!')
	if bang < 0 || bang+1 >= len(trimmed)-1 {
		return ""
	}

	alias := strings.TrimSpace(trimmed[bang+1 : len(trimmed)-1])
	if alias == "" {
		return ""
	}

	return alias
}

func normalizeCachedGroups(groups []string) []string {
	if len(groups) == 0 {
		return nil
	}

	seen := make(map[string]struct{}, len(groups))
	normalized := make([]string, 0, len(groups))
	for _, group := range groups {
		trimmed := strings.TrimSpace(group)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		normalized = append(normalized, trimmed)
	}

	if len(normalized) == 0 {
		return nil
	}

	sort.Strings(normalized)
	return normalized
}
