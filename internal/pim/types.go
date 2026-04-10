package pim

import (
	"sort"
	"strings"
	"time"

	"github.com/karloie/multipass/internal/auth"
)

const (
	StatusPending  = "pending"
	StatusApproved = "approved"
	StatusDenied   = "denied"
)

type Request struct {
	ID                     string
	RequesterID            string
	RequesterLabel         string
	RequesterUsername      string
	RequesterCacheKey      string
	RequestedRole          string
	AssignedApprover       string
	AssignedApproverGroups []string
	Reason                 string
	Duration               time.Duration
	Status                 string
	CreatedAt              time.Time
	DecidedAt              time.Time
	DecidedBy              string
	ExpiresAt              time.Time
}

func (r Request) IsActive(now time.Time) bool {
	return r.Status == StatusApproved && now.Before(r.ExpiresAt)
}

func requestUserID(userInfo *auth.UserInfo) string {
	if userInfo == nil {
		return ""
	}
	for _, candidate := range []string{userInfo.ID, userInfo.Email, userInfo.Username, userInfo.PrincipalID} {
		trimmed := strings.TrimSpace(candidate)
		if trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func requestUserLabel(userInfo *auth.UserInfo) string {
	if userInfo == nil {
		return ""
	}
	for _, candidate := range []string{userInfo.Name, userInfo.Email, userInfo.Username, userInfo.ID, userInfo.PrincipalID} {
		trimmed := strings.TrimSpace(candidate)
		if trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func requestCacheKey(userInfo *auth.UserInfo) string {
	if userInfo == nil {
		return ""
	}
	for _, candidate := range []string{userInfo.PrincipalID, userInfo.ID, userInfo.Email} {
		trimmed := strings.TrimSpace(candidate)
		if trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func matchesIdentity(userInfo *auth.UserInfo, identifier string) bool {
	trimmedIdentifier := strings.TrimSpace(identifier)
	if userInfo == nil || trimmedIdentifier == "" {
		return false
	}

	for _, candidate := range []string{userInfo.Name, userInfo.ID, userInfo.Email, userInfo.Username, userInfo.PrincipalID} {
		if strings.EqualFold(strings.TrimSpace(candidate), trimmedIdentifier) {
			return true
		}
	}

	return false
}

func matchesAnyGroup(userInfo *auth.UserInfo, groups []string) bool {
	if userInfo == nil || len(groups) == 0 || len(userInfo.Groups) == 0 {
		return false
	}

	userGroups := make(map[string]struct{}, len(userInfo.Groups))
	for _, group := range userInfo.Groups {
		trimmedGroup := strings.TrimSpace(group)
		if trimmedGroup == "" {
			continue
		}
		userGroups[strings.ToLower(trimmedGroup)] = struct{}{}
	}

	for _, group := range groups {
		trimmedGroup := strings.ToLower(strings.TrimSpace(group))
		if trimmedGroup == "" {
			continue
		}
		if _, ok := userGroups[trimmedGroup]; ok {
			return true
		}
	}

	return false
}

func normalizeApproverGroups(groups []string) []string {
	if len(groups) == 0 {
		return nil
	}

	seen := make(map[string]struct{}, len(groups))
	normalized := make([]string, 0, len(groups))
	for _, group := range groups {
		trimmedGroup := strings.TrimSpace(group)
		if trimmedGroup == "" {
			continue
		}
		key := strings.ToLower(trimmedGroup)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		normalized = append(normalized, trimmedGroup)
	}

	sort.Strings(normalized)
	return normalized
}
