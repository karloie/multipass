package authz

import (
	"context"
	"time"

	"github.com/karloie/multipass/internal/auth"
)

type ElevatedRole struct {
	Role      string
	ExpiresAt time.Time
}

type GroupProvider interface {
	GetUserGroups(ctx context.Context, userInfo *auth.UserInfo) ([]string, error)
}

type ElevatedRoleProvider interface {
	GetActiveElevatedRoles(ctx context.Context, userInfo *auth.UserInfo) ([]ElevatedRole, error)
}

type Provider interface {
	GroupProvider
	ElevatedRoleProvider
}

type Evaluator interface {
	EvaluatePermissions(ctx context.Context, userInfo *auth.UserInfo) (*Permission, error)
	CanAccessNamespace(ctx context.Context, userInfo *auth.UserInfo, namespace string) (bool, error)
}

type Permission struct {
	UserID            string
	ExternalGroups    []string
	InternalRoles     []string
	ElevatedRoles     []ElevatedRole
	AllowedNamespaces []string
}
