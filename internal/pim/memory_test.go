package pim

import (
	"context"
	"testing"
	"time"

	"github.com/karloie/multipass/internal/auth"
)

func TestMemoryStoreBlocksDuplicatePendingOrActiveRole(t *testing.T) {
	store := NewMemoryStore()
	now := time.Date(2026, 4, 4, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }

	requester := &auth.UserInfo{ID: "user-1", Email: "user-1@example.com"}
	_, err := store.CreateRequest(context.Background(), &Request{
		RequesterID:       requestUserID(requester),
		RequesterLabel:    requestUserLabel(requester),
		RequesterCacheKey: requestCacheKey(requester),
		RequestedRole:     "admin",
		AssignedApprover:  "approver@example.com",
		Reason:            "Need to inspect prod issue",
		Duration:          30 * time.Minute,
	})
	if err != nil {
		t.Fatalf("CreateRequest returned error: %v", err)
	}

	_, err = store.CreateRequest(context.Background(), &Request{
		RequesterID:       requestUserID(requester),
		RequesterLabel:    requestUserLabel(requester),
		RequesterCacheKey: requestCacheKey(requester),
		RequestedRole:     "admin",
		AssignedApprover:  "approver@example.com",
		Reason:            "Need to inspect another issue",
		Duration:          30 * time.Minute,
	})
	if err != ErrDuplicateRequest {
		t.Fatalf("expected ErrDuplicateRequest, got %v", err)
	}
}

func TestMemoryStoreActivatesApprovedRole(t *testing.T) {
	store := NewMemoryStore()
	now := time.Date(2026, 4, 4, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }

	requester := &auth.UserInfo{ID: "user-1", Email: "user-1@example.com"}
	approver := &auth.UserInfo{Email: "approver@example.com"}

	req, err := store.CreateRequest(context.Background(), &Request{
		RequesterID:       requestUserID(requester),
		RequesterLabel:    requestUserLabel(requester),
		RequesterCacheKey: requestCacheKey(requester),
		RequestedRole:     "devops",
		AssignedApprover:  "approver@example.com",
		Reason:            "Need temporary access",
		Duration:          45 * time.Minute,
	})
	if err != nil {
		t.Fatalf("CreateRequest returned error: %v", err)
	}

	if _, err := store.DecideRequest(context.Background(), req.ID, approver, true); err != nil {
		t.Fatalf("DecideRequest returned error: %v", err)
	}

	roles, err := store.GetActiveElevatedRoles(context.Background(), requester)
	if err != nil {
		t.Fatalf("GetActiveElevatedRoles returned error: %v", err)
	}
	if len(roles) != 1 || roles[0].Role != "devops" {
		t.Fatalf("unexpected active roles: %+v", roles)
	}
	if !roles[0].ExpiresAt.Equal(now.Add(45 * time.Minute)) {
		t.Fatalf("unexpected expiry: %v", roles[0].ExpiresAt)
	}
}

func TestMemoryStoreNilReceiverReturnsNoRoles(t *testing.T) {
	var store *MemoryStore

	roles, err := store.GetActiveElevatedRoles(context.Background(), &auth.UserInfo{ID: "user-1"})
	if err != nil {
		t.Fatalf("GetActiveElevatedRoles returned error: %v", err)
	}
	if len(roles) != 0 {
		t.Fatalf("expected no roles, got %+v", roles)
	}
}
