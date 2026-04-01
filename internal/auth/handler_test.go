package auth

import (
	"context"
	"testing"
	"time"
)

type noopProvider struct{}

func (noopProvider) GetAuthURL(state string) string { return "/mock?state=" + state }
func (noopProvider) ExchangeCode(ctx context.Context, code string) (*UserInfo, error) {
	return nil, nil
}
func (noopProvider) ValidateToken(ctx context.Context, token string) (*UserInfo, error) {
	return nil, nil
}
func (noopProvider) GetLogoutURL() string { return "" }

func TestNewHandlerDefaultsToGrafanaOIDCShape(t *testing.T) {
	h := NewHandler(noopProvider{}, NewMemorySessionStore(time.Hour), time.Hour, false)

	if h.loginPath != "/login" {
		t.Fatalf("expected default login path /login, got %q", h.loginPath)
	}
	if h.callbackPath != "/login/generic_oauth" {
		t.Fatalf("expected default callback path /login/generic_oauth, got %q", h.callbackPath)
	}
	if h.logoutPath != "/logout" {
		t.Fatalf("expected default logout path /logout, got %q", h.logoutPath)
	}
}

func TestNewHandlerWithPathsOverridesDefaults(t *testing.T) {
	h := NewHandlerWithPaths(noopProvider{}, NewMemorySessionStore(time.Hour), time.Hour, false, PathsConfig{
		LoginPath:    "/auth/login",
		CallbackPath: "/auth/callback",
		LogoutPath:   "/auth/logout",
	})

	if h.loginPath != "/auth/login" || h.callbackPath != "/auth/callback" || h.logoutPath != "/auth/logout" {
		t.Fatalf("expected custom handler paths, got login=%q callback=%q logout=%q", h.loginPath, h.callbackPath, h.logoutPath)
	}
}
