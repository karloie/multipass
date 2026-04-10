package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/karloie/multipass/internal/authz"
)

func TestResolveSegment(t *testing.T) {
	tests := []struct {
		name            string
		internalRoles   []string
		elevatedRoles   []authz.ElevatedRole
		expectedSegment string
	}{
		{
			name:            "no roles defaults to dev",
			internalRoles:   []string{},
			elevatedRoles:   []authz.ElevatedRole{},
			expectedSegment: segmentDev,
		},
		{
			name:            "admin role returns admin segment",
			internalRoles:   []string{"admin"},
			elevatedRoles:   []authz.ElevatedRole{},
			expectedSegment: segmentAdmin,
		},
		{
			name:            "plat-admin role returns admin segment",
			internalRoles:   []string{"plat-admin"},
			elevatedRoles:   []authz.ElevatedRole{},
			expectedSegment: segmentAdmin,
		},
		{
			name:            "ops role returns ops segment",
			internalRoles:   []string{"ops"},
			elevatedRoles:   []authz.ElevatedRole{},
			expectedSegment: segmentOps,
		},
		{
			name:            "plat-ops role returns ops segment",
			internalRoles:   []string{"plat-ops"},
			elevatedRoles:   []authz.ElevatedRole{},
			expectedSegment: segmentOps,
		},
		{
			name:            "devops role returns ops segment",
			internalRoles:   []string{"devops"},
			elevatedRoles:   []authz.ElevatedRole{},
			expectedSegment: segmentOps,
		},
		{
			name:            "dev role returns dev segment",
			internalRoles:   []string{"dev"},
			elevatedRoles:   []authz.ElevatedRole{},
			expectedSegment: segmentDev,
		},
		{
			name:            "unknown role defaults to dev segment",
			internalRoles:   []string{"unknown-role"},
			elevatedRoles:   []authz.ElevatedRole{},
			expectedSegment: segmentDev,
		},
		{
			name:            "admin elevated role returns admin segment",
			internalRoles:   []string{"dev"},
			elevatedRoles:   []authz.ElevatedRole{{Role: "admin", ExpiresAt: time.Now().Add(time.Hour)}},
			expectedSegment: segmentAdmin,
		},
		{
			name:            "ops elevated role returns ops segment",
			internalRoles:   []string{"dev"},
			elevatedRoles:   []authz.ElevatedRole{{Role: "ops", ExpiresAt: time.Now().Add(time.Hour)}},
			expectedSegment: segmentOps,
		},
		{
			name:            "admin takes priority over ops",
			internalRoles:   []string{"ops", "admin"},
			elevatedRoles:   []authz.ElevatedRole{},
			expectedSegment: segmentAdmin,
		},
		{
			name:            "ops takes priority over dev",
			internalRoles:   []string{"dev", "ops"},
			elevatedRoles:   []authz.ElevatedRole{},
			expectedSegment: segmentOps,
		},
		{
			name:            "elevated admin overrides internal ops",
			internalRoles:   []string{"ops"},
			elevatedRoles:   []authz.ElevatedRole{{Role: "admin", ExpiresAt: time.Now().Add(time.Hour)}},
			expectedSegment: segmentAdmin,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			perms := &authz.Permission{
				InternalRoles: tt.internalRoles,
				ElevatedRoles: tt.elevatedRoles,
			}

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			ctx := context.WithValue(req.Context(), permissionsKey, perms)
			req = req.WithContext(ctx)

			segment := resolveSegment(req)
			if segment != tt.expectedSegment {
				t.Errorf("expected segment %q, got %q", tt.expectedSegment, segment)
			}
		})
	}
}
