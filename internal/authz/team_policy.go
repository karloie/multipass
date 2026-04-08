package authz

import (
	"sort"
	"strings"
)

const (
	TeamAccessModeGlobal     = "global"
	TeamAccessModeTeamScoped = "team_scoped"
	TeamAccessModeDeny       = "deny"
)

const (
	TeamDecisionReasonAdminOverride  = "role.admin_override"
	TeamDecisionReasonDevopsOverride = "role.devops_override"
	TeamDecisionReasonDeveloperScope = "role.developer_scoped"
	TeamDecisionReasonDeveloperEmpty = "role.developer_no_teams"
	TeamDecisionReasonNoRole         = "role.none"
)

type TeamPolicyConfig struct {
	AdminRoles     []string
	DevopsRoles    []string
	DeveloperRoles []string
	MappingVersion string
}

type TeamAccessDecision struct {
	AccessMode      string
	Allow           bool
	AllowedTeamIDs  []string
	Reason          string
	MappingVersion  string
	MatchedGroups   map[string]string
	UnmatchedGroups []string
	EffectiveRoles  []string
}

type TeamPolicyEvaluator struct {
	groupToTeamID   map[string]string
	adminRoles      map[string]struct{}
	devopsRoles     map[string]struct{}
	developerRoles  map[string]struct{}
	mappingVersion  string
}

func NewTeamPolicyEvaluator(groupToTeamID map[string]string, cfg TeamPolicyConfig) *TeamPolicyEvaluator {
	return &TeamPolicyEvaluator{
		groupToTeamID:  normalizeGroupMapping(groupToTeamID),
		adminRoles:     roleSet(cfg.AdminRoles),
		devopsRoles:    roleSet(cfg.DevopsRoles),
		developerRoles: roleSet(cfg.DeveloperRoles),
		mappingVersion: strings.TrimSpace(cfg.MappingVersion),
	}
}

func (e *TeamPolicyEvaluator) Evaluate(roles []string, groups []string) *TeamAccessDecision {
	normalizedRoles := normalizeRoles(roles)
	resolvedTeamIDs, matched, unmatched := e.resolveGroups(groups)

	decision := &TeamAccessDecision{
		AccessMode:      TeamAccessModeDeny,
		Allow:           false,
		AllowedTeamIDs:  []string{},
		Reason:          TeamDecisionReasonNoRole,
		MappingVersion:  e.mappingVersion,
		MatchedGroups:   matched,
		UnmatchedGroups: unmatched,
		EffectiveRoles:  normalizedRoles,
	}

	if hasAnyRole(normalizedRoles, e.adminRoles) {
		decision.AccessMode = TeamAccessModeGlobal
		decision.Allow = true
		decision.Reason = TeamDecisionReasonAdminOverride
		return decision
	}

	if hasAnyRole(normalizedRoles, e.devopsRoles) {
		decision.AccessMode = TeamAccessModeGlobal
		decision.Allow = true
		decision.Reason = TeamDecisionReasonDevopsOverride
		return decision
	}

	if hasAnyRole(normalizedRoles, e.developerRoles) {
		if len(resolvedTeamIDs) == 0 {
			decision.Reason = TeamDecisionReasonDeveloperEmpty
			return decision
		}
		decision.AccessMode = TeamAccessModeTeamScoped
		decision.Allow = true
		decision.AllowedTeamIDs = resolvedTeamIDs
		decision.Reason = TeamDecisionReasonDeveloperScope
		return decision
	}

	return decision
}

func (e *TeamPolicyEvaluator) EvaluatePermission(permission *Permission) *TeamAccessDecision {
	if permission == nil {
		return e.Evaluate(nil, nil)
	}

	roles := make([]string, 0, len(permission.InternalRoles)+len(permission.ElevatedRoles))
	roles = append(roles, permission.InternalRoles...)
	for _, elevatedRole := range permission.ElevatedRoles {
		roles = append(roles, elevatedRole.Role)
	}

	return e.Evaluate(roles, permission.ExternalGroups)
}

func (e *TeamPolicyEvaluator) CanAccessTeam(decision *TeamAccessDecision, teamID string) bool {
	if decision == nil {
		return false
	}

	switch decision.AccessMode {
	case TeamAccessModeGlobal:
		return true
	case TeamAccessModeTeamScoped:
		trimmedTeamID := strings.TrimSpace(teamID)
		if trimmedTeamID == "" {
			return false
		}
		for _, allowedTeamID := range decision.AllowedTeamIDs {
			if allowedTeamID == trimmedTeamID {
				return true
			}
		}
		return false
	default:
		return false
	}
}

func normalizeGroupMapping(source map[string]string) map[string]string {
	if len(source) == 0 {
		return map[string]string{}
	}

	normalized := make(map[string]string, len(source))
	for group, teamID := range source {
		trimmedTeamID := strings.TrimSpace(teamID)
		if trimmedTeamID == "" {
			continue
		}
		normalizedGroup := normalizeGroupKey(group)
		if normalizedGroup == "" {
			continue
		}
		normalized[normalizedGroup] = trimmedTeamID
	}

	return normalized
}

func roleSet(roles []string) map[string]struct{} {
	set := make(map[string]struct{}, len(roles))
	for _, role := range roles {
		normalized := normalizeRole(role)
		if normalized == "" {
			continue
		}
		set[normalized] = struct{}{}
	}
	return set
}

func normalizeRoles(roles []string) []string {
	set := roleSet(roles)
	resolved := make([]string, 0, len(set))
	for role := range set {
		resolved = append(resolved, role)
	}
	sort.Strings(resolved)
	return resolved
}

func hasAnyRole(roles []string, candidates map[string]struct{}) bool {
	if len(roles) == 0 || len(candidates) == 0 {
		return false
	}
	for _, role := range roles {
		if _, ok := candidates[role]; ok {
			return true
		}
	}
	return false
}

func (e *TeamPolicyEvaluator) resolveGroups(groups []string) ([]string, map[string]string, []string) {
	matched := make(map[string]string)
	unmatched := make([]string, 0)
	teamSet := make(map[string]struct{})
	seenUnmatched := make(map[string]struct{})

	for _, rawGroup := range groups {
		trimmedGroup := strings.TrimSpace(rawGroup)
		if trimmedGroup == "" {
			continue
		}

		normalizedGroup := normalizeGroupKey(trimmedGroup)
		teamID, ok := e.groupToTeamID[normalizedGroup]
		if !ok {
			if _, alreadySeen := seenUnmatched[trimmedGroup]; !alreadySeen {
				unmatched = append(unmatched, trimmedGroup)
				seenUnmatched[trimmedGroup] = struct{}{}
			}
			continue
		}

		matched[trimmedGroup] = teamID
		teamSet[teamID] = struct{}{}
	}

	teamIDs := make([]string, 0, len(teamSet))
	for teamID := range teamSet {
		teamIDs = append(teamIDs, teamID)
	}
	sort.Strings(teamIDs)
	sort.Strings(unmatched)

	return teamIDs, matched, unmatched
}

func normalizeRole(role string) string {
	return strings.ToLower(strings.TrimSpace(role))
}

func normalizeGroupKey(group string) string {
	normalized := strings.ToLower(strings.TrimSpace(group))
	normalized = strings.Join(strings.Fields(normalized), " ")
	return normalized
}
