package auth

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// ParseTestJWT parses a JWT token and extracts user info (for testing)
// This exposes the real JWT parsing logic for use in integration tests
func ParseTestJWT(token string) (*UserInfo, error) {
	parts := splitJWT(token)
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format")
	}

	// Decode payload (base64url)
	payload, err := decodeBase64URL(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decoding JWT payload: %w", err)
	}

	// Parse claims
	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("parsing JWT claims: %w", err)
	}

	// Extract standard OIDC claims
	userInfo := &UserInfo{}
	if sub, ok := claims["sub"].(string); ok {
		userInfo.ID = sub
	}
	if preferredUsername, ok := claims["preferred_username"].(string); ok {
		userInfo.Username = preferredUsername
	}
	if groups, ok := parseStringListClaim(claims["groups"]); ok {
		userInfo.Groups = groups
	}

	return userInfo, nil
}

func parseStringListClaim(value interface{}) ([]string, bool) {
	if value == nil {
		return nil, false
	}

	switch typed := value.(type) {
	case []string:
		return append([]string(nil), typed...), true
	case []interface{}:
		groups := make([]string, 0, len(typed))
		for _, item := range typed {
			group, ok := item.(string)
			if !ok || group == "" {
				continue
			}
			groups = append(groups, group)
		}
		if len(groups) == 0 {
			return nil, false
		}
		return groups, true
	case string:
		if typed == "" {
			return nil, false
		}
		return []string{typed}, true
	default:
		return nil, false
	}
}

// splitJWT splits a JWT into header, payload, signature
func splitJWT(token string) []string {
	return strings.Split(token, ".")
}

// decodeBase64URL decodes base64url-encoded data (JWT format)
func decodeBase64URL(data string) ([]byte, error) {
	// JWT uses base64url encoding (RFC 4648)
	// Add padding if missing
	switch len(data) % 4 {
	case 2:
		data += "=="
	case 3:
		data += "="
	}

	// Replace URL-safe chars with standard base64
	data = strings.ReplaceAll(data, "-", "+")
	data = strings.ReplaceAll(data, "_", "/")

	return base64.StdEncoding.DecodeString(data)
}
