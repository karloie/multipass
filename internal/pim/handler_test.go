package pim

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/karloie/multipass/internal/auth"
	"github.com/karloie/multipass/internal/config"
)

type testBrowserAuth struct {
	user *auth.UserInfo
}

func (b *testBrowserAuth) AuthenticateRequest(r *http.Request) (*auth.UserInfo, bool) {
	if b.user == nil {
		return nil, false
	}
	return b.user, true
}

func (b *testBrowserAuth) LoginURL(returnTo string) string {
	return "/login?return_to=" + url.QueryEscape(returnTo)
}

type testInvalidator struct {
	userID string
}

func (i *testInvalidator) InvalidateUserID(userID string) {
	i.userID = userID
}

func TestHandlerRedirectsUnauthenticatedUsers(t *testing.T) {
	handler, err := NewHandler(config.PIMConfig{
		Enabled: true,
		Roles: map[string]config.PIMRoleConfig{
			"admin": {Approver: "approver@example.com", MaxDuration: "1h"},
		},
	}, false, &testBrowserAuth{}, NewMemoryStore(), nil, nil)
	if err != nil {
		t.Fatalf("NewHandler returned error: %v", err)
	}

	request := httptest.NewRequest(http.MethodGet, "/pim", nil)
	recorder := httptest.NewRecorder()

	handler.handleRequests(recorder, request)

	if recorder.Code != http.StatusFound {
		t.Fatalf("expected redirect, got %d", recorder.Code)
	}
	if location := recorder.Header().Get("Location"); location != "/login?return_to=%2Fpim" {
		t.Fatalf("unexpected location: %q", location)
	}
}

func TestHandlerRequestAndApproveFlow(t *testing.T) {
	store := NewMemoryStore()
	invalidator := &testInvalidator{}
	requesterAuth := &testBrowserAuth{user: &auth.UserInfo{ID: "user-1", Email: "user-1@example.com", Name: "User One"}}
	approverAuth := &testBrowserAuth{user: &auth.UserInfo{Email: "approver@example.com", Name: "Approver"}}

	requesterHandler, err := NewHandler(config.PIMConfig{
		Enabled:         true,
		DefaultDuration: "30m",
		Roles: map[string]config.PIMRoleConfig{
			"admin":  {Approver: "approver@example.com", MaxDuration: "1h"},
			"dev":    {Approver: "approver@example.com", MaxDuration: "4h"},
			"devops": {Approver: "approver@example.com", MaxDuration: "2h"},
		},
	}, false, requesterAuth, store, nil, invalidator)
	if err != nil {
		t.Fatalf("NewHandler returned error: %v", err)
	}
	approverHandler, err := NewHandler(config.PIMConfig{
		Enabled:         true,
		DefaultDuration: "30m",
		Roles: map[string]config.PIMRoleConfig{
			"admin":  {Approver: "approver@example.com", MaxDuration: "1h"},
			"dev":    {Approver: "approver@example.com", MaxDuration: "4h"},
			"devops": {Approver: "approver@example.com", MaxDuration: "2h"},
		},
	}, false, approverAuth, store, nil, invalidator)
	if err != nil {
		t.Fatalf("NewHandler returned error: %v", err)
	}

	form := url.Values{}
	form.Set("role", "admin")
	form.Set("duration_minutes", "30")
	form.Set("reason", "Need to troubleshoot production")
	request := httptest.NewRequest(http.MethodPost, "/pim/request", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", "http://example.com")
	request.Host = "example.com"
	recorder := httptest.NewRecorder()

	requesterHandler.handleRequests(recorder, request)

	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("expected redirect after create, got %d", recorder.Code)
	}

	pending, err := store.ListPendingForApprover(context.Background(), approverAuth.user)
	if err != nil {
		t.Fatalf("ListPendingForApprover returned error: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("expected one pending request, got %d", len(pending))
	}

	approveRequest := httptest.NewRequest(http.MethodPost, "/pim/approve/"+pending[0].ID+"/approve", nil)
	approveRequest.Header.Set("Origin", "http://example.com")
	approveRequest.Host = "example.com"
	approveRecorder := httptest.NewRecorder()

	approverHandler.handleApprovals(approveRecorder, approveRequest)

	if approveRecorder.Code != http.StatusSeeOther {
		t.Fatalf("expected redirect after approve, got %d", approveRecorder.Code)
	}

	roles, err := store.GetActiveElevatedRoles(context.Background(), requesterAuth.user)
	if err != nil {
		t.Fatalf("GetActiveElevatedRoles returned error: %v", err)
	}
	if len(roles) != 1 || roles[0].Role != "admin" {
		t.Fatalf("unexpected active roles: %+v", roles)
	}
	if invalidator.userID != requestCacheKey(requesterAuth.user) {
		t.Fatalf("expected invalidation for %q, got %q", requestCacheKey(requesterAuth.user), invalidator.userID)
	}
}

func TestHandlerRequestAndApproveFlowByApproverGroup(t *testing.T) {
	store := NewMemoryStore()
	invalidator := &testInvalidator{}
	requesterAuth := &testBrowserAuth{user: &auth.UserInfo{ID: "user-1", Email: "user-1@example.com", Name: "User One", Groups: []string{"Rolle Utvikler"}}}
	approverAuth := &testBrowserAuth{user: &auth.UserInfo{Email: "boss@example.com", Name: "Boss", Groups: []string{"Leder"}}}

	requesterHandler, err := NewHandler(config.PIMConfig{
		Enabled: true,
		Roles: map[string]config.PIMRoleConfig{
			"admin": {ApproverGroups: []string{"Leder"}, MaxDuration: "1h"},
		},
	}, false, requesterAuth, store, nil, invalidator)
	if err != nil {
		t.Fatalf("NewHandler returned error: %v", err)
	}
	approverHandler, err := NewHandler(config.PIMConfig{
		Enabled: true,
		Roles: map[string]config.PIMRoleConfig{
			"admin": {ApproverGroups: []string{"Leder"}, MaxDuration: "1h"},
		},
	}, false, approverAuth, store, nil, invalidator)
	if err != nil {
		t.Fatalf("NewHandler returned error: %v", err)
	}

	form := url.Values{}
	form.Set("role", "admin")
	form.Set("duration_minutes", "30")
	form.Set("reason", "Need temporary production access")
	request := httptest.NewRequest(http.MethodPost, "/pim/request", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", "http://example.com")
	request.Host = "example.com"
	recorder := httptest.NewRecorder()

	requesterHandler.handleRequests(recorder, request)

	if recorder.Code != http.StatusSeeOther {
		t.Fatalf("expected redirect after create, got %d", recorder.Code)
	}

	pending, err := store.ListPendingForApprover(context.Background(), approverAuth.user)
	if err != nil {
		t.Fatalf("ListPendingForApprover returned error: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("expected one pending request, got %d", len(pending))
	}
	if len(pending[0].AssignedApproverGroups) != 1 || pending[0].AssignedApproverGroups[0] != "Leder" {
		t.Fatalf("unexpected approver groups: %+v", pending[0].AssignedApproverGroups)
	}

	approveRequest := httptest.NewRequest(http.MethodPost, "/pim/approve/"+pending[0].ID+"/approve", nil)
	approveRequest.Header.Set("Origin", "http://example.com")
	approveRequest.Host = "example.com"
	approveRecorder := httptest.NewRecorder()

	approverHandler.handleApprovals(approveRecorder, approveRequest)

	if approveRecorder.Code != http.StatusSeeOther {
		t.Fatalf("expected redirect after approve, got %d", approveRecorder.Code)
	}
}
