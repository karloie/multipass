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

type Provider interface {
	GetUserGroups(ctx context.Context, userInfo *auth.UserInfo) ([]string, error)
	GetActiveElevatedRoles(ctx context.Context, userInfo *auth.UserInfo) ([]ElevatedRole, error)
}

type Evaluator interface {
	EvaluatePermissions(ctx context.Context, userInfo *auth.UserInfo) (*Permission, error)
	CanAccessNamespace(ctx context.Context, userInfo *auth.UserInfo, namespace string) (bool, error)
}

type Permission struct {
	UserID            string
	Groups            []string
	ElevatedRoles     []ElevatedRole
	AllowedNamespaces []string
}
