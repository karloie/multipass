package proxy

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/karloie/multipass/internal/auth"
	"github.com/karloie/multipass/internal/config"
)

func (p *Proxy) authenticateAPIRequest(w http.ResponseWriter, r *http.Request, next http.Handler) {
	// Extract JWT from Authorization header.
	authHeader := r.Header.Get(headerAuthorization)
	if authHeader != "" {
		p.authenticateBearerRequest(w, r, next, authHeader)
		return
	}

	userInfo, ok, err := p.authenticateTrustedProxyRequest(r)
	if err != nil {
		slog.WarnContext(r.Context(), "trusted proxy authentication failed", slog.Any("error", err))
		http.Error(w, errMsgInvalidToken, http.StatusUnauthorized)
		return
	}
	if ok {
		ctx := context.WithValue(r.Context(), userInfoKey, userInfo)
		next.ServeHTTP(w, r.WithContext(ctx))
		return
	}

	http.Error(w, errMsgMissingAuth, http.StatusUnauthorized)
}

func (p *Proxy) authenticateBearerRequest(w http.ResponseWriter, r *http.Request, next http.Handler, authHeader string) {
	if !strings.HasPrefix(authHeader, headerBearerPrefix) {
		http.Error(w, errMsgInvalidAuth, http.StatusUnauthorized)
		return
	}

	token := strings.TrimPrefix(authHeader, headerBearerPrefix)
	if token == "" {
		http.Error(w, errMsgEmptyToken, http.StatusUnauthorized)
		return
	}

	userInfo, err := p.authProvider.ValidateToken(r.Context(), token)
	if err != nil {
		slog.WarnContext(r.Context(), "token validation failed", slog.Any("error", err))
		http.Error(w, errMsgInvalidToken, http.StatusUnauthorized)
		return
	}

	if userInfo == nil {
		slog.WarnContext(r.Context(), "token validation returned nil user info")
		http.Error(w, errMsgInvalidToken, http.StatusUnauthorized)
		return
	}

	ctx := context.WithValue(r.Context(), userInfoKey, userInfo)
	ctx = context.WithValue(ctx, jwtTokenKey, token)
	next.ServeHTTP(w, r.WithContext(ctx))
}

func (p *Proxy) authenticateTrustedProxyRequest(r *http.Request) (*auth.UserInfo, bool, error) {
	if r == nil || !p.config.Auth.TrustedProxy.Enabled {
		return nil, false, nil
	}

	trustedProxy := p.config.Auth.TrustedProxy
	if r.Header.Get(trustedProxy.SecretHeader) != trustedProxy.SecretValue {
		return nil, false, nil
	}

	userInfo, err := trustedProxyUserInfo(r, trustedProxy)
	if err != nil {
		return nil, false, err
	}

	return userInfo, true, nil
}

func trustedProxyUserInfo(r *http.Request, trustedProxyConfig config.TrustedProxyConfig) (*auth.UserInfo, error) {
	if r == nil {
		return nil, fmt.Errorf("trusted proxy request is required")
	}

	trustedUser := strings.TrimSpace(r.Header.Get(trustedProxyConfig.UserHeader))
	trustedID := strings.TrimSpace(r.Header.Get(trustedProxyConfig.IDHeader))
	if trustedID == "" {
		trustedID = trustedUser
	}
	if trustedID == "" {
		return nil, fmt.Errorf("trusted proxy user identity header is missing")
	}

	email := strings.TrimSpace(r.Header.Get(trustedProxyConfig.EmailHeader))
	if email == "" {
		email = trustedUser
	}

	return &auth.UserInfo{
		ID:          trustedID,
		PrincipalID: strings.TrimSpace(r.Header.Get(trustedProxyConfig.PrincipalIDHeader)),
		TenantID:    strings.TrimSpace(r.Header.Get(trustedProxyConfig.TenantIDHeader)),
		Email:       email,
		Name:        strings.TrimSpace(r.Header.Get(trustedProxyConfig.NameHeader)),
	}, nil
}
