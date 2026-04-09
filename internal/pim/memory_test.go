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

func TestMemoryStoreApproveReplacesExistingActiveRole(t *testing.T) {
	store := NewMemoryStore()
	now := time.Date(2026, 4, 4, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }

	requester := &auth.UserInfo{ID: "user-1", Email: "user-1@example.com"}
	approver := &auth.UserInfo{Email: "approver@example.com"}

	adminReq, err := store.CreateRequest(context.Background(), &Request{
		RequesterID:       requestUserID(requester),
		RequesterLabel:    requestUserLabel(requester),
		RequesterCacheKey: requestCacheKey(requester),
		RequestedRole:     "admin",
		AssignedApprover:  "approver@example.com",
		Reason:            "Need admin for incident",
		Duration:          45 * time.Minute,
	})
	if err != nil {
		t.Fatalf("CreateRequest returned error: %v", err)
	}

	if _, err := store.DecideRequest(context.Background(), adminReq.ID, approver, true); err != nil {
		t.Fatalf("DecideRequest returned error: %v", err)
	}

	now = now.Add(5 * time.Minute)
	devReq, err := store.CreateRequest(context.Background(), &Request{
		RequesterID:       requestUserID(requester),
		RequesterLabel:    requestUserLabel(requester),
		RequesterCacheKey: requestCacheKey(requester),
		RequestedRole:     "dev",
		AssignedApprover:  "approver@example.com",
		Reason:            "PoC downgrade to dev",
		Duration:          30 * time.Minute,
	})
	if err != nil {
		t.Fatalf("CreateRequest returned error: %v", err)
	}

	if _, err := store.DecideRequest(context.Background(), devReq.ID, approver, true); err != nil {
		t.Fatalf("DecideRequest returned error: %v", err)
	}

	roles, err := store.GetActiveElevatedRoles(context.Background(), requester)
	if err != nil {
		t.Fatalf("GetActiveElevatedRoles returned error: %v", err)
	}
	if len(roles) != 1 || roles[0].Role != "dev" {
		t.Fatalf("expected only dev to be active, got %+v", roles)
	}
}

func TestMemoryStoreSelfApprovalBlockedByDefault(t *testing.T) {
	store := NewMemoryStore()
	requester := &auth.UserInfo{ID: "user-1", Email: "user@example.com"}

	// Try to create a request where the requester is also the approver
	_, err := store.CreateRequest(context.Background(), &Request{
		RequesterID:       requestUserID(requester),
		RequesterLabel:    requestUserLabel(requester),
		RequesterCacheKey: requestCacheKey(requester),
		RequestedRole:     "admin",
		AssignedApprover:  "user@example.com",
		Reason:            "Self-approval test",
		Duration:          30 * time.Minute,
	})
	if err != ErrSelfApproval {
		t.Fatalf("expected ErrSelfApproval, got %v", err)
	}
}

func TestMemoryStoreSelfApprovalAllowedWhenEnabled(t *testing.T) {
	store := NewMemoryStoreWithOptions(true) // Enable self-approval
	now := time.Date(2026, 4, 4, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }

	requester := &auth.UserInfo{ID: "user-1", Email: "user@example.com"}

	// Create a request where the requester is also the approver
	req, err := store.CreateRequest(context.Background(), &Request{
		RequesterID:       requestUserID(requester),
		RequesterLabel:    requestUserLabel(requester),
		RequesterCacheKey: requestCacheKey(requester),
		RequestedRole:     "admin",
		AssignedApprover:  "user@example.com",
		Reason:            "Self-approval test",
		Duration:          30 * time.Minute,
	})
	if err != nil {
		t.Fatalf("CreateRequest returned error: %v", err)
	}

	// Approve their own request
	approved, err := store.DecideRequest(context.Background(), req.ID, requester, true)
	if err != nil {
		t.Fatalf("DecideRequest returned error: %v", err)
	}

	if approved.Status != StatusApproved {
		t.Fatalf("expected approved status, got %v", approved.Status)
	}

	// Verify the role is active
	roles, err := store.GetActiveElevatedRoles(context.Background(), requester)
	if err != nil {
		t.Fatalf("GetActiveElevatedRoles returned error: %v", err)
	}
	if len(roles) != 1 || roles[0].Role != "admin" {
		t.Fatalf("unexpected active roles: %+v", roles)
	}
}

