package audit

import (
	"context"
	"sort"
	"sync"
	"time"
)

// MemoryStore implements in-memory audit storage.
type MemoryStore struct {
	events []AuditEvent
	mu     sync.RWMutex
	nextID int64
}

// NewMemoryStore creates an in-memory audit store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		events: make([]AuditEvent, 0),
		nextID: 1,
	}
}

// Log records an audit event in memory.
func (m *MemoryStore) Log(ctx context.Context, event *AuditEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	event.ID = m.nextID
	m.nextID++

	if len(event.Groups) > 0 {
		groups := make([]string, len(event.Groups))
		copy(groups, event.Groups)
		event.Groups = groups
	}

	m.events = append(m.events, *event)

	return nil
}

// Query returns audit events that match the filters.
func (m *MemoryStore) Query(ctx context.Context, filters AuditFilters) ([]AuditEvent, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var results []AuditEvent

	for _, event := range m.events {
		if !matchesFilters(event, filters) {
			continue
		}
		results = append(results, event)
	}

	sortByTimestampDesc(results)

	start := filters.Offset
	if start > len(results) {
		return []AuditEvent{}, nil
	}

	end := len(results)
	if filters.Limit > 0 && start+filters.Limit < end {
		end = start + filters.Limit
	}

	return results[start:end], nil
}

// Close is a no-op.
func (m *MemoryStore) Close() error {
	return nil
}

// Clear removes all events.
func (m *MemoryStore) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = make([]AuditEvent, 0)
	m.nextID = 1
}

// GetEventCount returns the number of stored events.
func (m *MemoryStore) GetEventCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.events)
}

// matchesFilters reports whether an event matches the filters.
func matchesFilters(event AuditEvent, filters AuditFilters) bool {
	if filters.UserID != "" && event.UserID != filters.UserID {
		return false
	}
	if filters.Backend != "" && event.Backend != filters.Backend {
		return false
	}
	if filters.Namespace != "" && event.Namespace != filters.Namespace {
		return false
	}
	if filters.ElevatedAccessActive != nil && event.ElevatedAccessActive != *filters.ElevatedAccessActive {
		return false
	}
	if !filters.From.IsZero() && event.Timestamp.Before(filters.From) {
		return false
	}
	if !filters.To.IsZero() && event.Timestamp.After(filters.To) {
		return false
	}
	return true
}

// sortByTimestampDesc sorts events by newest timestamp first.
func sortByTimestampDesc(events []AuditEvent) {
	sort.Slice(events, func(i, j int) bool {
		return events[i].Timestamp.After(events[j].Timestamp)
	})
}
