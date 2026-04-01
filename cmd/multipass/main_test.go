package main

import "testing"

func TestParseConfigPath(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		want    string
		wantErr bool
	}{
		{
			name: "accepts one config file",
			args: []string{"config.oidc.yaml"},
			want: "config.oidc.yaml",
		},
		{
			name:    "rejects missing config file",
			args:    nil,
			wantErr: true,
		},
		{
			name:    "rejects more than one config file",
			args:    []string{"one.yaml", "two.yaml"},
			wantErr: true,
		},
		{
			name:    "rejects blank config file",
			args:    []string{"   "},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseConfigPath(tt.args)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("unexpected config path: got %q want %q", got, tt.want)
			}
		})
	}
}
