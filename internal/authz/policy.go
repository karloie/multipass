package authz

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/karloie/multipass/internal/auth"
)

const defaultPermissionCacheTTL = 15 * time.Second

type cachedPermission struct {
	permission *Permission
	expiresAt  time.Time
}

type PolicyEvaluator struct {
	provider      Provider
	groupMappings map[string][]string // group -> allowed namespaces
	cache         map[string]cachedPermission
	cacheMu       sync.RWMutex
	cacheTTL      time.Duration
	now           func() time.Time
}

func NewPolicyEvaluator(provider Provider, groupMappings map[string][]string) *PolicyEvaluator {
	return &PolicyEvaluator{
		provider:      provider,
		groupMappings: groupMappings,
		cache:         make(map[string]cachedPermission),
		cacheTTL:      defaultPermissionCacheTTL,
		now:           time.Now,
	}
}

func (p *PolicyEvaluator) EvaluatePermissions(ctx context.Context, userInfo *auth.UserInfo) (*Permission, error) {
	cacheKey := permissionCacheKey(userInfo)
	if permission, ok := p.getCachedPermission(cacheKey); ok {
		return permission, nil
	}
	if userInfo == nil {
		return nil, fmt.Errorf("missing user info")
	}

	groups, err := p.provider.GetUserGroups(ctx, userInfo)
	if err != nil {
		return nil, fmt.Errorf("fetching user groups: %w", err)
	}

	elevatedRoles, err := p.provider.GetActiveElevatedRoles(ctx, userInfo)
	if err != nil {
		return nil, fmt.Errorf("fetching elevated roles: %w", err)
	}

	namespacesMap := make(map[string]bool)
	for _, group := range groups {
		if namespaces, ok := p.groupMappings[group]; ok {
			for _, ns := range namespaces {
				namespacesMap[ns] = true
			}
		}
	}

	for _, elevatedRole := range elevatedRoles {
		if namespaces, ok := p.groupMappings[elevatedRole.Role]; ok {
			for _, ns := range namespaces {
				namespacesMap[ns] = true
			}
		}
	}

	allowedNamespaces := make([]string, 0, len(namespacesMap))
	for ns := range namespacesMap {
		allowedNamespaces = append(allowedNamespaces, ns)
	}
	sort.Strings(allowedNamespaces)

	permission := &Permission{
		UserID:            permissionUserID(userInfo),
		Groups:            append([]string(nil), groups...),
		ElevatedRoles:     append([]ElevatedRole(nil), elevatedRoles...),
		AllowedNamespaces: allowedNamespaces,
	}

	p.setCachedPermission(cacheKey, permission)
	return clonePermission(permission), nil
}

func (p *PolicyEvaluator) CanAccessNamespace(ctx context.Context, userInfo *auth.UserInfo, namespace string) (bool, error) {
	perm, err := p.EvaluatePermissions(ctx, userInfo)
	if err != nil {
		return false, err
	}

	for _, ns := range perm.AllowedNamespaces {
		if ns == namespace || ns == "*" {
			return true, nil
		}
	}

	return false, nil
}

func permissionCacheKey(userInfo *auth.UserInfo) string {
	if userInfo == nil {
		return ""
	}
	if userInfo.PrincipalID != "" {
		return userInfo.PrincipalID
	}
	if userInfo.ID != "" {
		return userInfo.ID
	}
	return userInfo.Email
}

func permissionUserID(userInfo *auth.UserInfo) string {
	if userInfo == nil {
		return ""
	}
	if userInfo.ID != "" {
		return userInfo.ID
	}
	if userInfo.Email != "" {
		return userInfo.Email
	}
	return userInfo.PrincipalID
}

func (p *PolicyEvaluator) getCachedPermission(userID string) (*Permission, bool) {
	if userID == "" || p.cacheTTL <= 0 {
		return nil, false
	}

	now := p.now()
	p.cacheMu.RLock()
	entry, ok := p.cache[userID]
	p.cacheMu.RUnlock()
	if !ok || now.After(entry.expiresAt) {
		if ok {
			p.cacheMu.Lock()
			delete(p.cache, userID)
			p.cacheMu.Unlock()
		}
		return nil, false
	}

	return clonePermission(entry.permission), true
}

func (p *PolicyEvaluator) setCachedPermission(userID string, permission *Permission) {
	if userID == "" || p.cacheTTL <= 0 || permission == nil {
		return
	}

	p.cacheMu.Lock()
	p.cache[userID] = cachedPermission{
		permission: clonePermission(permission),
		expiresAt:  p.now().Add(p.cacheTTL),
	}
	p.cacheMu.Unlock()
}

func clonePermission(permission *Permission) *Permission {
	if permission == nil {
		return nil
	}

	return &Permission{
		UserID:            permission.UserID,
		Groups:            append([]string(nil), permission.Groups...),
		ElevatedRoles:     append([]ElevatedRole(nil), permission.ElevatedRoles...),
		AllowedNamespaces: append([]string(nil), permission.AllowedNamespaces...),
	}
}
