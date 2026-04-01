package auth

import (
	"context"
	"time"
)

// UserInfo represents authenticated user information
type UserInfo struct {
	ID          string   // Subject from JWT (sub claim) - kept stable for sessions, audit, and UI headers
	Username    string   // Preferred username/login for UI backends when available
	PrincipalID string   // Provider principal identifier (oid claim) when available
	TenantID    string   // Provider tenant or realm identifier (tid claim) when available
	Email       string   // User email (optional, for UI backends)
	Name        string   // User display name (optional, for UI backends)
	Groups      []string // Group names/IDs from JWT claims when available
}

type Session struct {
	SessionID string
	UserInfo  *UserInfo
	ExpiresAt time.Time
}

type Provider interface {
	ExchangeCode(ctx context.Context, code string) (*UserInfo, error)
	GetAuthURL(state string) string
	GetLogoutURL() string
	ValidateToken(ctx context.Context, token string) (*UserInfo, error)
}
