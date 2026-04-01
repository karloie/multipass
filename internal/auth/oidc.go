package auth

import (
	"context"
	"fmt"
	"net/url"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// OIDCProvider implements generic OpenID Connect authentication.
type OIDCProvider struct {
	oauth2Config *oauth2.Config
	verifier     *oidc.IDTokenVerifier
	providerName string
	logoutURL    string
}

// OIDCConfig defines OIDC provider settings.
type OIDCConfig struct {
	ProviderName          string // e.g., "forgerock", "keycloak" (for logging)
	IssuerURL             string // OIDC issuer URL (without /.well-known/openid-configuration)
	ClientID              string
	ClientSecret          string
	RedirectURL           string
	PostLogoutRedirectURL string
	Scopes                []string // Default: ["openid", "profile", "email"]
}

// NewOIDCProvider creates an OIDC provider.
func NewOIDCProvider(cfg OIDCConfig) (*OIDCProvider, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("fetching OIDC discovery: %w", err)
	}

	var discovery struct {
		EndSessionEndpoint string `json:"end_session_endpoint"`
	}
	if err := provider.Claims(&discovery); err != nil {
		return nil, fmt.Errorf("reading OIDC discovery claims: %w", err)
	}

	logoutURL := discovery.EndSessionEndpoint
	if logoutURL != "" && cfg.PostLogoutRedirectURL != "" {
		parsedLogoutURL, err := url.Parse(logoutURL)
		if err != nil {
			return nil, fmt.Errorf("parsing OIDC logout URL: %w", err)
		}
		query := parsedLogoutURL.Query()
		query.Set("post_logout_redirect_uri", cfg.PostLogoutRedirectURL)
		parsedLogoutURL.RawQuery = query.Encode()
		logoutURL = parsedLogoutURL.String()
	}

	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email"}
	}

	oauth2Config := &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       scopes,
	}

	return &OIDCProvider{
		oauth2Config: oauth2Config,
		verifier:     provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
		providerName: cfg.ProviderName,
		logoutURL:    logoutURL,
	}, nil
}

// GetAuthURL returns the authorization URL.
func (p *OIDCProvider) GetAuthURL(state string) string {
	return p.oauth2Config.AuthCodeURL(state, oauth2.AccessTypeOffline)
}

// ExchangeCode exchanges an authorization code for user info.
func (p *OIDCProvider) ExchangeCode(ctx context.Context, code string) (*UserInfo, error) {
	token, err := p.oauth2Config.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("token exchange failed: %w", err)
	}

	idToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("no id_token in response")
	}

	verifiedToken, err := p.verifier.Verify(ctx, idToken)
	if err != nil {
		return nil, fmt.Errorf("verifying id_token: %w", err)
	}

	return p.userInfoFromToken(verifiedToken)
}

// ValidateToken verifies a bearer token.
func (p *OIDCProvider) ValidateToken(ctx context.Context, token string) (*UserInfo, error) {
	verifiedToken, err := p.verifier.Verify(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("verifying token: %w", err)
	}

	return p.userInfoFromToken(verifiedToken)
}

// GetLogoutURL returns the logout URL.
func (p *OIDCProvider) GetLogoutURL() string {
	return p.logoutURL
}

type oidcUserClaims struct {
	Subject           string   `json:"sub"`
	ObjectID          string   `json:"oid"`
	TenantID          string   `json:"tid"`
	Email             string   `json:"email"`
	Name              string   `json:"name"`
	PreferredUsername string   `json:"preferred_username"`
	Groups            []string `json:"groups"`
}

func (p *OIDCProvider) userInfoFromToken(token *oidc.IDToken) (*UserInfo, error) {
	var claims oidcUserClaims
	if err := token.Claims(&claims); err != nil {
		return nil, fmt.Errorf("parsing token claims: %w", err)
	}

	return userInfoFromClaims(claims)
}

func userInfoFromClaims(claims oidcUserClaims) (*UserInfo, error) {
	if claims.Subject == "" {
		return nil, fmt.Errorf("missing sub claim")
	}

	email := claims.Email
	if email == "" {
		email = claims.PreferredUsername
	}

	return &UserInfo{
		ID:          claims.Subject,
		Username:    claims.PreferredUsername,
		PrincipalID: claims.ObjectID,
		TenantID:    claims.TenantID,
		Email:       email,
		Name:        claims.Name,
		Groups:      append([]string(nil), claims.Groups...),
	}, nil
}
