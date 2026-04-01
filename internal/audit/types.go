package audit

import (
	"context"
	"time"
)

// AuditEvent represents a single audit log entry.
type AuditEvent struct {
	ID                   int64     `json:"id"`
	Timestamp            time.Time `json:"timestamp"`
	UserID               string    `json:"user_id"`                 // Subject (sub) from JWT
	Backend              string    `json:"backend"`                 // "loki", "mimir", "grafana", "tempo"
	Namespace            string    `json:"namespace"`               // "dev-team-1", "prod", etc.
	StatusCode           int       `json:"status_code,omitempty"`   // HTTP status code
	ElevatedAccessActive bool      `json:"elevated_access_active"`  // Was elevated access active during this action?
	ElevatedRole         string    `json:"elevated_role,omitempty"` // Which elevated role was active
	Groups               []string  `json:"groups,omitempty"`        // User's groups at time of action
	Error                string    `json:"error,omitempty"`         // Error message if failed
}

// AuditFilters defines audit query criteria.
type AuditFilters struct {
	UserID               string
	Backend              string
	Namespace            string
	ElevatedAccessActive *bool
	From                 time.Time
	To                   time.Time
	Limit                int
	Offset               int
}

// Store defines audit log storage.
type Store interface {
	// Log records an audit event.
	Log(ctx context.Context, event *AuditEvent) error

	// Query returns audit events that match the filters.
	Query(ctx context.Context, filters AuditFilters) ([]AuditEvent, error)

	// Close closes the store.
	Close() error
}
