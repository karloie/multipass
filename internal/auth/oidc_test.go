package auth

import "testing"

func TestUserInfoFromClaims(t *testing.T) {
	tests := []struct {
		name           string
		claims         oidcUserClaims
		expectID       string
		expectUsername string
		expectOID      string
		expectTID      string
		expectEmail    string
		expectName     string
		expectGroups   []string
		expectErr      bool
	}{
		{
			name: "extracts standard claims",
			claims: oidcUserClaims{
				Subject:           "user-123",
				ObjectID:          "object-123",
				TenantID:          "tenant-123",
				Email:             "user@example.com",
				Name:              "Test User",
				PreferredUsername: "test.user",
				Groups:            []string{"App-Grafana-Editors"},
			},
			expectID:       "user-123",
			expectUsername: "test.user",
			expectOID:      "object-123",
			expectTID:      "tenant-123",
			expectEmail:    "user@example.com",
			expectName:     "Test User",
			expectGroups:   []string{"App-Grafana-Editors"},
		},
		{
			name: "falls back to preferred username when email missing",
			claims: oidcUserClaims{
				Subject:           "user-456",
				PreferredUsername: "user456@example.com",
			},
			expectID:       "user-456",
			expectUsername: "user456@example.com",
			expectEmail:    "user456@example.com",
		},
		{
			name: "requires sub claim",
			claims: oidcUserClaims{
				Email: "missing-sub@example.com",
			},
			expectErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			userInfo, err := userInfoFromClaims(test.claims)
			if test.expectErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if userInfo.ID != test.expectID {
				t.Fatalf("unexpected user id: got %q want %q", userInfo.ID, test.expectID)
			}
			if userInfo.Username != test.expectUsername {
				t.Fatalf("unexpected username: got %q want %q", userInfo.Username, test.expectUsername)
			}
			if userInfo.PrincipalID != test.expectOID {
				t.Fatalf("unexpected principal id: got %q want %q", userInfo.PrincipalID, test.expectOID)
			}
			if userInfo.TenantID != test.expectTID {
				t.Fatalf("unexpected tenant id: got %q want %q", userInfo.TenantID, test.expectTID)
			}
			if userInfo.Email != test.expectEmail {
				t.Fatalf("unexpected user email: got %q want %q", userInfo.Email, test.expectEmail)
			}
			if userInfo.Name != test.expectName {
				t.Fatalf("unexpected user name: got %q want %q", userInfo.Name, test.expectName)
			}
			if len(userInfo.Groups) != len(test.expectGroups) {
				t.Fatalf("unexpected group count: got %v want %v", userInfo.Groups, test.expectGroups)
			}
			for index, group := range test.expectGroups {
				if userInfo.Groups[index] != group {
					t.Fatalf("unexpected group at index %d: got %q want %q", index, userInfo.Groups[index], group)
				}
			}
		})
	}
}
