package pim

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/karloie/multipass/internal/auth"
	"github.com/karloie/multipass/internal/authz"
)

var (
	ErrRequestNotFound      = errors.New("pim request not found")
	ErrRequestAlreadyClosed = errors.New("pim request already decided")
	ErrApproverMismatch     = errors.New("pim request is assigned to a different approver")
	ErrDuplicateRequest     = errors.New("pim request already pending or active for this role")
	ErrSelfApproval         = errors.New("pim request cannot be self-approved")
)

type MemoryStore struct {
	mu       sync.RWMutex
	requests map[string]*Request
	now      func() time.Time
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		requests: make(map[string]*Request),
		now:      time.Now,
	}
}

func (s *MemoryStore) CreateRequest(ctx context.Context, req *Request) (*Request, error) {
	_ = ctx
	if req == nil {
		return nil, ErrRequestNotFound
	}

	created := cloneRequest(req)
	created.ID = newRequestID()
	created.Status = StatusPending
	created.CreatedAt = s.now().UTC()

	s.mu.Lock()
	defer s.mu.Unlock()

	for _, existing := range s.requests {
		if existing.RequesterCacheKey != created.RequesterCacheKey {
			continue
		}
		if existing.RequestedRole != created.RequestedRole {
			continue
		}
		if existing.Status == StatusPending || existing.IsActive(s.now()) {
			return nil, ErrDuplicateRequest
		}
	}

	if strings.EqualFold(strings.TrimSpace(created.AssignedApprover), strings.TrimSpace(created.RequesterID)) || strings.EqualFold(strings.TrimSpace(created.AssignedApprover), strings.TrimSpace(created.RequesterLabel)) || strings.EqualFold(strings.TrimSpace(created.AssignedApprover), strings.TrimSpace(created.RequesterCacheKey)) {
		return nil, ErrSelfApproval
	}
	created.AssignedApproverGroups = normalizeApproverGroups(created.AssignedApproverGroups)

	s.requests[created.ID] = created
	return cloneRequest(created), nil
}

func (s *MemoryStore) ListRequestsForUser(ctx context.Context, userInfo *auth.UserInfo) ([]Request, error) {
	_ = ctx
	s.mu.RLock()
	defer s.mu.RUnlock()

	requests := make([]Request, 0)
	for _, req := range s.requests {
		if !matchesIdentity(userInfo, req.RequesterID) && !matchesIdentity(userInfo, req.RequesterLabel) && requestCacheKey(userInfo) != req.RequesterCacheKey {
			continue
		}
		requests = append(requests, *cloneRequest(req))
	}

	sortRequests(requests)
	return requests, nil
}

func (s *MemoryStore) ListPendingForApprover(ctx context.Context, userInfo *auth.UserInfo) ([]Request, error) {
	_ = ctx
	s.mu.RLock()
	defer s.mu.RUnlock()

	requests := make([]Request, 0)
	for _, req := range s.requests {
		if req.Status != StatusPending {
			continue
		}
		if !matchesIdentity(userInfo, req.AssignedApprover) && !matchesAnyGroup(userInfo, req.AssignedApproverGroups) {
			continue
		}
		requests = append(requests, *cloneRequest(req))
	}

	sortRequests(requests)
	return requests, nil
}

func (s *MemoryStore) DecideRequest(ctx context.Context, id string, approver *auth.UserInfo, approve bool) (*Request, error) {
	_ = ctx
	s.mu.Lock()
	defer s.mu.Unlock()

	req, ok := s.requests[id]
	if !ok {
		return nil, ErrRequestNotFound
	}
	if req.Status != StatusPending {
		return nil, ErrRequestAlreadyClosed
	}
	if !matchesIdentity(approver, req.AssignedApprover) && !matchesAnyGroup(approver, req.AssignedApproverGroups) {
		return nil, ErrApproverMismatch
	}
	if matchesIdentity(approver, req.RequesterID) || matchesIdentity(approver, req.RequesterLabel) || strings.EqualFold(requestCacheKey(approver), req.RequesterCacheKey) {
		return nil, ErrSelfApproval
	}

	now := s.now().UTC()
	if approve {
		// A newly approved request becomes the active PIM level for the user.
		for _, existing := range s.requests {
			if existing == req {
				continue
			}
			if existing.RequesterCacheKey != req.RequesterCacheKey {
				continue
			}
			if existing.IsActive(now) {
				existing.ExpiresAt = now
			}
		}
		req.Status = StatusApproved
		req.ExpiresAt = now.Add(req.Duration)
	} else {
		req.Status = StatusDenied
		req.ExpiresAt = time.Time{}
	}
	req.DecidedAt = now
	req.DecidedBy = requestUserLabel(approver)

	return cloneRequest(req), nil
}

func (s *MemoryStore) GetActiveElevatedRoles(ctx context.Context, userInfo *auth.UserInfo) ([]authz.ElevatedRole, error) {
	_ = ctx
	if s == nil {
		return nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.requests == nil {
		return nil, nil
	}

	now := s.now()
	activeByRole := make(map[string]time.Time)
	for _, req := range s.requests {
		if !req.IsActive(now) {
			continue
		}
		if !matchesIdentity(userInfo, req.RequesterID) && !matchesIdentity(userInfo, req.RequesterLabel) && requestCacheKey(userInfo) != req.RequesterCacheKey {
			continue
		}
		if existing, ok := activeByRole[req.RequestedRole]; !ok || req.ExpiresAt.After(existing) {
			activeByRole[req.RequestedRole] = req.ExpiresAt
		}
	}

	roles := make([]authz.ElevatedRole, 0, len(activeByRole))
	for role, expiresAt := range activeByRole {
		roles = append(roles, authz.ElevatedRole{Role: role, ExpiresAt: expiresAt})
	}

	sort.Slice(roles, func(i, j int) bool {
		return roles[i].Role < roles[j].Role
	})

	return roles, nil
}

func cloneRequest(req *Request) *Request {
	if req == nil {
		return nil
	}
	cloned := *req
	return &cloned
}

func sortRequests(requests []Request) {
	sort.Slice(requests, func(i, j int) bool {
		if requests[i].CreatedAt.Equal(requests[j].CreatedAt) {
			return requests[i].ID > requests[j].ID
		}
		return requests[i].CreatedAt.After(requests[j].CreatedAt)
	})
}

func newRequestID() string {
	raw := make([]byte, 8)
	if _, err := rand.Read(raw); err != nil {
		return hex.EncodeToString([]byte(time.Now().UTC().Format(time.RFC3339Nano)))
	}
	return hex.EncodeToString(raw)
}
