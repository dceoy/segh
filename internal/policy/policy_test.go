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
	cfg.Policies.Actions.RequireFullSHA = true
	cfg.Policies.Repository.RequireSecurityMD = true
	cfg.Suppressions = []model.Suppression{
		{Policy: "actions.full_sha", Repository: "example/repo", Owner: "sec", Rationale: "migration", Expires: &future},
		{Policy: "repository.security_md", Repository: "example/repo", Owner: "sec", Rationale: "expired", Expires: &expired},
	}
	inventory := model.Inventory{
		Organization: "example",
		Repositories: []model.Repository{{
			FullName:       "example/repo",
			FullSHAPinning: model.Observed[bool]{State: model.Available, Value: false, Source: "fixture"},
			SecurityMD:     model.Observed[bool]{State: model.Unknown, Source: "fixture", Reason: "permission"},
		}},
	}
	audit := New(cfg, now).Evaluate(inventory)
	if audit.Counts[string(model.PolicyExempt)] != 1 {
		t.Fatalf("expected exempt result: %#v", audit.Counts)
	}
	if audit.Counts[string(model.PolicyUnknown)] != 1 {
		t.Fatalf("expected unknown result: %#v", audit.Counts)
	}
	if audit.Counts[string(model.PolicyFail)] != 1 {
		t.Fatalf("expected expired-suppression failure: %#v", audit.Counts)
	}
}

func TestUnsupportedDoesNotPass(t *testing.T) {
	result := observedBool("example/repo", "test", "high",
		model.Observed[bool]{State: model.Unsupported, Reason: "GHES"}, true, "upgrade")
	if result.Status != model.PolicyUnsupported {
		t.Fatalf("status = %s", result.Status)
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
		RequireFullSHA: true, RequireSHAPinningEnforcement: true, RequireRenovate: true,
		RequireForkPRApproval: &enabled,
	}
	cfg.Policies.CodeSecurity = config.CodeSecurityPolicy{
		Configuration: "default", CodeQL: "required", SecretScanning: "required",
		PushProtection: "required", DependencyGraph: "required", DependabotAlerts: "required",
		DependabotUpdates: "required",
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
		AllowedActions: model.Observed[string]{State: model.Available, Value: "selected"},
		FullSHAPinning: availableTrue, SHAPinningEnforced: availableTrue, RenovateConfigured: availableTrue,
		ForkPRApproval: availableTrue, CodeSecurityConfiguration: model.Observed[string]{State: model.Available, Value: "default"},
		CodeQL: availableTrue, SecretScanning: availableTrue, PushProtection: availableTrue,
		DependencyGraph: availableTrue, DependabotAlerts: availableTrue, DependabotSecurityUpdates: availableTrue,
		Ruleset: availableTrue, BranchProtection: availableTrue, RequiredPullRequests: availableTrue,
		RequiredChecks: availableTrue, ForcePushRestricted: availableTrue, DeletionRestricted: availableTrue,
		SecurityMD: availableTrue,
	}
	audit := New(cfg, time.Now()).Evaluate(model.Inventory{Organization: "example", Repositories: []model.Repository{repository}})
	if len(audit.Results) != 25 || audit.Counts[string(model.PolicyPass)] != 25 {
		t.Fatalf("results=%d counts=%#v", len(audit.Results), audit.Counts)
	}
	for i := 1; i < len(audit.Results); i++ {
		if audit.Results[i-1].PolicyID > audit.Results[i].PolicyID {
			t.Fatal("policy output is not deterministic")
		}
	}
}
