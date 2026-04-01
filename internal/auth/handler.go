package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"log/slog"
	"net/http"
	"net/url"
	"time"
)

const (
	authStateCookieName    = "multipass_auth_state"
	returnToCookieName     = "multipass_return_to"
	defaultReturnToPath    = "/"
	returnToQueryParameter = "return_to"
	stateQueryParameter    = "state"
)

// Handler manages auth endpoints and middleware.
type Handler struct {
	provider            Provider
	sessionStore        SessionStore
	sessionTTL          time.Duration
	trustForwardedProto bool
	loginPath           string
	callbackPath        string
	logoutPath          string
}

type PathsConfig struct {
	LoginPath    string
	CallbackPath string
	LogoutPath   string
}

// NewHandler creates an auth handler.
func NewHandler(provider Provider, sessionStore SessionStore, sessionTTL time.Duration, trustForwardedProto bool) *Handler {
	return NewHandlerWithPaths(provider, sessionStore, sessionTTL, trustForwardedProto, PathsConfig{})
}

// NewHandlerWithPaths creates an auth handler with custom paths.
func NewHandlerWithPaths(provider Provider, sessionStore SessionStore, sessionTTL time.Duration, trustForwardedProto bool, paths PathsConfig) *Handler {
	if paths.LoginPath == "" {
		paths.LoginPath = "/login"
	}
	if paths.CallbackPath == "" {
		paths.CallbackPath = "/login/generic_oauth"
	}
	if paths.LogoutPath == "" {
		paths.LogoutPath = "/logout"
	}

	return &Handler{
		provider:            provider,
		sessionStore:        sessionStore,
		sessionTTL:          sessionTTL,
		trustForwardedProto: trustForwardedProto,
		loginPath:           paths.LoginPath,
		callbackPath:        paths.CallbackPath,
		logoutPath:          paths.LogoutPath,
	}
}

// RegisterRoutes registers auth routes on a mux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc(h.loginPath, h.handleLogin)
	mux.HandleFunc(h.callbackPath, h.handleCallback)
	mux.HandleFunc(h.logoutPath, h.handleLogout)
}

// handleLogin starts the OAuth2 login flow.
func (h *Handler) handleLogin(w http.ResponseWriter, r *http.Request) {
	state, err := generateState()
	if err != nil {
		http.Error(w, "Failed to generate state", http.StatusInternalServerError)
		return
	}

	secure := IsSecureRequest(r, h.trustForwardedProto)
	setTransientCookie(w, authStateCookieName, state, secure)
	setTransientCookie(w, returnToCookieName, sanitizeReturnTo(r.URL.Query().Get(returnToQueryParameter)), secure)

	authURL := h.provider.GetAuthURL(state)
	http.Redirect(w, r, authURL, http.StatusFound)
}

// handleCallback handles the OAuth2 callback.
func (h *Handler) handleCallback(w http.ResponseWriter, r *http.Request) {
	secure := IsSecureRequest(r, h.trustForwardedProto)
	expectedState, err := readCookieValue(r, authStateCookieName)
	if err != nil || expectedState == "" {
		http.Error(w, "Missing login state", http.StatusBadRequest)
		return
	}

	returnedState := r.URL.Query().Get(stateQueryParameter)
	if returnedState == "" || returnedState != expectedState {
		http.Error(w, "Invalid login state", http.StatusBadRequest)
		return
	}

	returnTo := defaultReturnToPath
	if storedReturnTo, err := readCookieValue(r, returnToCookieName); err == nil {
		returnTo = sanitizeReturnTo(storedReturnTo)
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Missing authorization code", http.StatusBadRequest)
		return
	}

	userInfo, err := h.provider.ExchangeCode(r.Context(), code)
	if err != nil {
		slog.ErrorContext(r.Context(), "token exchange failed", slog.Any("error", err))
		http.Error(w, "Authentication failed", http.StatusUnauthorized)
		return
	}

	session, err := h.sessionStore.CreateSession(r.Context(), userInfo)
	if err != nil {
		slog.ErrorContext(r.Context(), "session creation failed", slog.Any("error", err))
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	SetSessionCookie(w, session.SessionID, int(h.sessionTTL.Seconds()), secure)
	clearTransientCookie(w, authStateCookieName, secure)
	clearTransientCookie(w, returnToCookieName, secure)

	http.Redirect(w, r, returnTo, http.StatusFound)
}

// handleLogout logs out the user.
func (h *Handler) handleLogout(w http.ResponseWriter, r *http.Request) {
	secure := IsSecureRequest(r, h.trustForwardedProto)

	sessionID, err := GetSessionCookie(r)
	if err == nil {
		if err := h.sessionStore.DeleteSession(r.Context(), sessionID); err != nil {
			slog.ErrorContext(r.Context(), "failed to delete session", slog.Any("error", err))
		}
	}

	ClearSessionCookie(w, secure)
	clearTransientCookie(w, authStateCookieName, secure)
	clearTransientCookie(w, returnToCookieName, secure)

	logoutURL := h.provider.GetLogoutURL()
	if logoutURL != "" {
		http.Redirect(w, r, logoutURL, http.StatusFound)
		return
	}

	http.Redirect(w, r, "/", http.StatusFound)
}

// AuthenticateRequest returns the authenticated browser user.
func (h *Handler) AuthenticateRequest(r *http.Request) (*UserInfo, bool) {
	sessionID, err := GetSessionCookie(r)
	if err != nil {
		return nil, false
	}

	session, ok, err := h.sessionStore.GetSession(r.Context(), sessionID)
	if err != nil || !ok || session == nil || session.UserInfo == nil {
		return nil, false
	}

	return session.UserInfo, true
}

// LoginURL returns the login path with a return target.
func (h *Handler) LoginURL(returnTo string) string {
	return h.loginPath + "?" + returnToQueryParameter + "=" + url.QueryEscape(sanitizeReturnTo(returnTo))
}

// Middleware returns auth-required middleware.
func (h *Handler) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		skipPaths := []string{h.loginPath, h.callbackPath, "/health"}

		for _, path := range skipPaths {
			if r.URL.Path == path {
				next.ServeHTTP(w, r)
				return
			}
		}

		sessionID, err := GetSessionCookie(r)
		if err != nil {
			http.Redirect(w, r, h.loginPath, http.StatusFound)
			return
		}

		session, ok, err := h.sessionStore.GetSession(r.Context(), sessionID)
		if err != nil || !ok {
			http.Redirect(w, r, h.loginPath, http.StatusFound)
			return
		}

		ctx := context.WithValue(r.Context(), userInfoKey, session.UserInfo)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// GetUserInfo returns user info from context.
func GetUserInfo(ctx context.Context) (*UserInfo, bool) {
	userInfo, ok := ctx.Value(userInfoKey).(*UserInfo)
	return userInfo, ok
}

type contextKey string

const userInfoKey contextKey = "userInfo"

// generateState creates a random OAuth2 state token.
func generateState() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

func sanitizeReturnTo(returnTo string) string {
	if returnTo == "" {
		return defaultReturnToPath
	}
	if returnTo[0] != '/' {
		return defaultReturnToPath
	}
	if len(returnTo) > 1 && returnTo[1] == '/' {
		return defaultReturnToPath
	}
	return returnTo
}

func setTransientCookie(w http.ResponseWriter, name, value string, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    url.QueryEscape(value),
		Path:     "/",
		MaxAge:   600,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

func clearTransientCookie(w http.ResponseWriter, name string, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

func readCookieValue(r *http.Request, name string) (string, error) {
	cookie, err := r.Cookie(name)
	if err != nil {
		return "", err
	}

	value, err := url.QueryUnescape(cookie.Value)
	if err != nil {
		return "", err
	}

	return value, nil
}
