package policy

import (
	"testing"
	"time"

	"github.com/dceoy/segh/internal/config"
	"github.com/dceoy/segh/internal/model"
)

func TestEvaluateStatusesAndSuppressionExpiry(t *testing.T) {
	now := time.Date(2026, 7, 27, 0, 0, 0, 0, time.UTC)
	expired := now.Add(-time.Hour)
	future := now.Add(time.Hour)
	cfg := config.Default()
	cfg.Organization = "example"
	cfg.Policies.Actions.RequireSHAPinningEnforcement = true
	cfg.Policies.Repository.RequireSecurityMD = true
	cfg.Suppressions = []model.Suppression{
		{Policy: "actions.sha_pinning_enforced", Repository: "example/repo", Owner: "sec", Rationale: "migration", Expires: &future},
		{Policy: "repository.security_md", Repository: "example/repo", Owner: "sec", Rationale: "expired", Expires: &expired},
	}
	inventory := model.Inventory{
		Organization: "example",
		Repositories: []model.Repository{{
			FullName:           "example/repo",
			SHAPinningEnforced: model.Observed[bool]{State: model.Available, Value: false, Source: "fixture"},
			SecurityMD:         model.Observed[bool]{State: model.Unknown, Source: "fixture", Reason: "permission"},
		}},
	}
	audit := New(cfg, now).Evaluate(inventory)
	if audit.PolicyCounts[string(model.PolicyExempt)] != 1 {
		t.Fatalf("expected exempt result: %#v", audit.PolicyCounts)
	}
	if audit.PolicyCounts[string(model.PolicyUnknown)] != 1 {
		t.Fatalf("expected unknown result: %#v", audit.PolicyCounts)
	}
	if audit.PolicyCounts[string(model.PolicyFail)] != 1 {
		t.Fatalf("expected expired-suppression failure: %#v", audit.PolicyCounts)
	}
	if audit.Coverage != "partial" {
		t.Fatalf("coverage = %q, want partial", audit.Coverage)
	}
}

func TestUnsupportedDoesNotPass(t *testing.T) {
	result := observed("example/repo", "test", "high",
		model.Observed[bool]{State: model.Unsupported, Reason: "GHES"}, true, "upgrade")
	if result.Status != model.PolicyUnsupported {
		t.Fatalf("status = %s", result.Status)
	}
}

func TestObservedSupportsComparableTypes(t *testing.T) {
	if result := observed("example/repo", "bool", "high",
		model.Observed[bool]{State: model.Available, Value: true}, true, "fix"); result.Status != model.PolicyPass {
		t.Fatalf("bool status = %s", result.Status)
	}
	if result := observed("example/repo", "string", "high",
		model.Observed[string]{State: model.Available, Value: "write"}, "read", "fix"); result.Status != model.PolicyFail {
		t.Fatalf("string status = %s", result.Status)
	}
}

func TestRepositoryMatchesNarrowGlob(t *testing.T) {
	if !repositoryMatches("example/legacy-*", "example/legacy-one") {
		t.Fatal("expected match")
	}
	if repositoryMatches("example/legacy-*", "other/legacy-one") {
		t.Fatal("unexpected cross-organization match")
	}
}

func TestAllConfiguredChecksProduceDeterministicRecords(t *testing.T) {
	enabled := true
	cfg := config.Default()
	cfg.Organization = "example"
	cfg.Policies.Actions = config.ActionsPolicy{
		Enabled: &enabled, DefaultWorkflowPermissions: "read", AllowedActions: "selected",
		RequireSHAPinningEnforcement: true,
		RequireForkPRApproval:        &enabled,
	}
	cfg.Policies.Dependencies = config.DependenciesPolicy{
		DependencyGraph:           &enabled,
		DependabotAlerts:          &enabled,
		DependabotSecurityUpdates: &enabled,
	}
	cfg.Policies.Repository = config.RepositoryPolicy{
		RequireRuleset: true, RequireBranchProtection: true, RequirePullRequest: true,
		RequireRequiredChecks: true, RestrictForcePushes: true, RestrictDeletions: true,
		RequireSecurityMD: true, AllowedVisibilities: []string{"private"},
		ProhibitArchived: true, ProhibitForks: true, ProhibitTemplates: true,
	}
	availableTrue := model.Observed[bool]{State: model.Available, Value: true, Source: "fixture"}
	repository := model.Repository{
		FullName: "example/repo", Visibility: "private",
		ActionsEnabled: availableTrue, DefaultWorkflowPermissions: model.Observed[string]{State: model.Available, Value: "read"},
		AllowedActions:            model.Observed[string]{State: model.Available, Value: "selected"},
		SHAPinningEnforced:        availableTrue,
		ForkPRApproval:            availableTrue,
		DependencyGraph:           availableTrue,
		DependabotAlerts:          availableTrue,
		DependabotSecurityUpdates: availableTrue,
		Ruleset:                   availableTrue, BranchProtection: availableTrue, RequiredPullRequests: availableTrue,
		RequiredChecks: availableTrue, ForcePushRestricted: availableTrue, DeletionRestricted: availableTrue,
		SecurityMD: availableTrue,
	}
	audit := New(cfg, time.Now()).Evaluate(model.Inventory{Organization: "example", Repositories: []model.Repository{repository}})
	if len(audit.Results) != 19 || audit.PolicyCounts[string(model.PolicyPass)] != 19 {
		t.Fatalf("results=%d counts=%#v", len(audit.Results), audit.PolicyCounts)
	}
	for i := 1; i < len(audit.Results); i++ {
		if audit.Results[i-1].PolicyID > audit.Results[i].PolicyID {
			t.Fatal("policy output is not deterministic")
		}
	}
}

func TestDependencyPoliciesAreIndependentAndFailClosed(t *testing.T) {
	enabled := true
	cfg := config.Default()
	cfg.Organization = "example"
	cfg.Policies.Dependencies = config.DependenciesPolicy{
		DependencyGraph:           &enabled,
		DependabotAlerts:          &enabled,
		DependabotSecurityUpdates: &enabled,
	}
	repository := model.Repository{
		FullName:                  "example/repo",
		DependencyGraph:           model.Observed[bool]{State: model.Available, Value: true, Source: "sbom"},
		DependabotAlerts:          model.Observed[bool]{State: model.Available, Value: false, Source: "alerts"},
		DependabotSecurityUpdates: model.Observed[bool]{State: model.Unknown, Reason: "permission"},
	}
	audit := New(cfg, time.Now()).Evaluate(model.Inventory{
		Organization: "example", Complete: true, Repositories: []model.Repository{repository},
	})
	statuses := map[string]model.PolicyStatus{}
	for _, result := range audit.Results {
		statuses[result.PolicyID] = result.Status
	}
	for _, test := range []struct {
		id   string
		want model.PolicyStatus
	}{
		{id: "dependencies.dependency_graph", want: model.PolicyPass},
		{id: "dependencies.dependabot_alerts", want: model.PolicyFail},
		{id: "dependencies.dependabot_security_updates", want: model.PolicyUnknown},
	} {
		if got := statuses[test.id]; got != test.want {
			t.Errorf("%s status = %s, want %s", test.id, got, test.want)
		}
	}
}
