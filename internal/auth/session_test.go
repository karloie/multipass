package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestMemorySessionStoreSessionLifecycle(t *testing.T) {
	store := NewMemorySessionStore(time.Hour)
	defer func() {
		if err := store.Close(); err != nil {
			t.Fatalf("close store: %v", err)
		}
	}()

	ctx := context.Background()
	userInfo := &UserInfo{ID: "user-123", Email: "user@example.com", Name: "Test User"}

	session, err := store.CreateSession(ctx, userInfo)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	loaded, ok, err := store.GetSession(ctx, session.SessionID)
	if err != nil {
		t.Fatalf("get session: %v", err)
	}
	if !ok {
		t.Fatal("expected session to exist")
	}
	if loaded.UserInfo == userInfo {
		t.Fatal("expected stored session to return a copy of user info")
	}
	if loaded.UserInfo.ID != userInfo.ID {
		t.Fatalf("unexpected user id: got %q want %q", loaded.UserInfo.ID, userInfo.ID)
	}

	if err := store.DeleteSession(ctx, session.SessionID); err != nil {
		t.Fatalf("delete session: %v", err)
	}

	loaded, ok, err = store.GetSession(ctx, session.SessionID)
	if err != nil {
		t.Fatalf("get deleted session: %v", err)
	}
	if ok || loaded != nil {
		t.Fatal("expected deleted session to be missing")
	}
}

func TestMemorySessionStoreExpiresSession(t *testing.T) {
	store := NewMemorySessionStore(10 * time.Millisecond)
	defer func() {
		if err := store.Close(); err != nil {
			t.Fatalf("close store: %v", err)
		}
	}()

	ctx := context.Background()
	session, err := store.CreateSession(ctx, &UserInfo{ID: "user-123"})
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	time.Sleep(20 * time.Millisecond)

	loaded, ok, err := store.GetSession(ctx, session.SessionID)
	if err != nil {
		t.Fatalf("get expired session: %v", err)
	}
	if ok || loaded != nil {
		t.Fatal("expected expired session to be missing")
	}
}

func TestIsSecureRequest(t *testing.T) {
	t.Run("marks tls requests secure", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "https://example.com", nil)
		if !IsSecureRequest(req, false) {
			t.Fatal("expected tls request to be secure")
		}
	})

	t.Run("does not trust forwarded proto by default", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://example.com", nil)
		req.Header.Set("X-Forwarded-Proto", "https")
		if IsSecureRequest(req, false) {
			t.Fatal("expected forwarded proto to be ignored when not trusted")
		}
	})

	t.Run("trusts forwarded proto when enabled", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://example.com", nil)
		req.Header.Set("X-Forwarded-Proto", "https")
		if !IsSecureRequest(req, true) {
			t.Fatal("expected forwarded proto to be honored when trusted")
		}
	})
}
