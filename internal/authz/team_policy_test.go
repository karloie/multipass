package authz

import "testing"

func TestTeamPolicyEvaluatorAdminOverridesTeamScoping(t *testing.T) {
	evaluator := NewTeamPolicyEvaluator(
		map[string]string{
			"team appark": "appark",
		},
		TeamPolicyConfig{
			AdminRoles:     []string{"admin"},
			DevopsRoles:    []string{"devops"},
			DeveloperRoles: []string{"developer"},
			MappingVersion: "2026-04-08.1",
		},
	)

	decision := evaluator.Evaluate(
		[]string{"developer", "admin"},
		[]string{"Team Appark"},
	)

	if decision.AccessMode != TeamAccessModeGlobal {
		t.Fatalf("unexpected access mode: got %q want %q", decision.AccessMode, TeamAccessModeGlobal)
	}
	if !decision.Allow {
		t.Fatalf("expected allow=true")
	}
	if decision.Reason != TeamDecisionReasonAdminOverride {
		t.Fatalf("unexpected decision reason: got %q want %q", decision.Reason, TeamDecisionReasonAdminOverride)
	}
	if !evaluator.CanAccessTeam(decision, "any-team") {
		t.Fatalf("expected global decision to allow any team")
	}
}

func TestTeamPolicyEvaluatorDevopsOverridesDeveloperScope(t *testing.T) {
	evaluator := NewTeamPolicyEvaluator(
		map[string]string{
			"team appark": "appark",
		},
		TeamPolicyConfig{
			AdminRoles:     []string{"admin"},
			DevopsRoles:    []string{"devops"},
			DeveloperRoles: []string{"developer"},
		},
	)

	decision := evaluator.Evaluate(
		[]string{"developer", "devops"},
		[]string{"Team Appark"},
	)

	if decision.AccessMode != TeamAccessModeGlobal {
		t.Fatalf("unexpected access mode: got %q want %q", decision.AccessMode, TeamAccessModeGlobal)
	}
	if decision.Reason != TeamDecisionReasonDevopsOverride {
		t.Fatalf("unexpected decision reason: got %q want %q", decision.Reason, TeamDecisionReasonDevopsOverride)
	}
}

func TestTeamPolicyEvaluatorDeveloperGetsTeamScopedAccess(t *testing.T) {
	evaluator := NewTeamPolicyEvaluator(
		map[string]string{
			"team appark":                "appark",
			"team applikasjonsplattform": "applikasjonsplattform",
		},
		TeamPolicyConfig{
			DeveloperRoles: []string{"developer"},
		},
	)

	decision := evaluator.Evaluate(
		[]string{"developer"},
		[]string{"Team Appark", "Team Applikasjonsplattform", "Unknown Group"},
	)

	if decision.AccessMode != TeamAccessModeTeamScoped {
		t.Fatalf("unexpected access mode: got %q want %q", decision.AccessMode, TeamAccessModeTeamScoped)
	}
	if !decision.Allow {
		t.Fatalf("expected allow=true")
	}
	if decision.Reason != TeamDecisionReasonDeveloperScope {
		t.Fatalf("unexpected decision reason: got %q want %q", decision.Reason, TeamDecisionReasonDeveloperScope)
	}
	if len(decision.AllowedTeamIDs) != 2 {
		t.Fatalf("unexpected allowed team count: got %d want 2 (%v)", len(decision.AllowedTeamIDs), decision.AllowedTeamIDs)
	}
	if !evaluator.CanAccessTeam(decision, "appark") {
		t.Fatalf("expected appark access")
	}
	if evaluator.CanAccessTeam(decision, "premie") {
		t.Fatalf("did not expect premie access")
	}
	if len(decision.UnmatchedGroups) != 1 || decision.UnmatchedGroups[0] != "Unknown Group" {
		t.Fatalf("unexpected unmatched groups: %+v", decision.UnmatchedGroups)
	}
}

func TestTeamPolicyEvaluatorDeveloperDeniedWithoutResolvedTeams(t *testing.T) {
	evaluator := NewTeamPolicyEvaluator(
		map[string]string{
			"team appark": "appark",
		},
		TeamPolicyConfig{
			DeveloperRoles: []string{"developer"},
		},
	)

	decision := evaluator.Evaluate(
		[]string{"developer"},
		[]string{"Unknown Group"},
	)

	if decision.AccessMode != TeamAccessModeDeny {
		t.Fatalf("unexpected access mode: got %q want %q", decision.AccessMode, TeamAccessModeDeny)
	}
	if decision.Allow {
		t.Fatalf("expected allow=false")
	}
	if decision.Reason != TeamDecisionReasonDeveloperEmpty {
		t.Fatalf("unexpected reason: got %q want %q", decision.Reason, TeamDecisionReasonDeveloperEmpty)
	}
}

func TestTeamPolicyEvaluatorNoKnownRolesDenied(t *testing.T) {
	evaluator := NewTeamPolicyEvaluator(
		map[string]string{"team appark": "appark"},
		TeamPolicyConfig{
			AdminRoles:     []string{"admin"},
			DevopsRoles:    []string{"devops"},
			DeveloperRoles: []string{"developer"},
		},
	)

	decision := evaluator.Evaluate(
		[]string{"viewer"},
		[]string{"Team Appark"},
	)

	if decision.AccessMode != TeamAccessModeDeny {
		t.Fatalf("unexpected access mode: got %q want %q", decision.AccessMode, TeamAccessModeDeny)
	}
	if decision.Allow {
		t.Fatalf("expected allow=false")
	}
	if decision.Reason != TeamDecisionReasonNoRole {
		t.Fatalf("unexpected reason: got %q want %q", decision.Reason, TeamDecisionReasonNoRole)
	}
}

func TestTeamPolicyEvaluatorEvaluatePermissionUsesElevatedRolesForOverride(t *testing.T) {
	evaluator := NewTeamPolicyEvaluator(
		map[string]string{"team appark": "appark"},
		TeamPolicyConfig{
			AdminRoles:     []string{"admin"},
			DevopsRoles:    []string{"devops"},
			DeveloperRoles: []string{"developer"},
		},
	)

	decision := evaluator.EvaluatePermission(&Permission{
		ExternalGroups: []string{"Unknown Group"},
		InternalRoles:  []string{"developer"},
		ElevatedRoles:  []ElevatedRole{{Role: "devops"}},
	})

	if decision.AccessMode != TeamAccessModeGlobal {
		t.Fatalf("unexpected access mode: got %q want %q", decision.AccessMode, TeamAccessModeGlobal)
	}
	if decision.Reason != TeamDecisionReasonDevopsOverride {
		t.Fatalf("unexpected reason: got %q want %q", decision.Reason, TeamDecisionReasonDevopsOverride)
	}
}
