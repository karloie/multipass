package proxy

import (
	"context"
	"net/http"

	"github.com/karloie/multipass/internal/auth"
)

type browserAuthenticator interface {
	AuthenticateRequest(r *http.Request) (*auth.UserInfo, bool)
	LoginURL(returnTo string) string
}

func (p *Proxy) authenticateBrowserRequest(w http.ResponseWriter, r *http.Request, next http.Handler, backendName string) {
	if p.browserAuth == nil {
		http.Error(w, "Browser authentication is not configured", http.StatusInternalServerError)
		return
	}

	userInfo, ok := p.browserAuth.AuthenticateRequest(r)
	if !ok {
		http.Redirect(w, r, p.browserAuth.LoginURL(requestReturnTo(r, backendName)), http.StatusFound)
		return
	}

	ctx := context.WithValue(r.Context(), userInfoKey, userInfo)
	next.ServeHTTP(w, r.WithContext(ctx))
}

func requestReturnTo(r *http.Request, backendName string) string {
	if r == nil {
		return "/" + backendName
	}
	if r.URL.RawQuery == "" {
		return r.URL.Path
	}
	return r.URL.Path + "?" + r.URL.RawQuery
}
