package policy

import (
	"fmt"
	"path"
	"slices"
	"sort"
	"time"

	"github.com/dceoy/segh/internal/config"
	"github.com/dceoy/segh/internal/model"
)

type Evaluator struct {
	cfg config.Config
	now time.Time
}

func New(cfg config.Config, now time.Time) *Evaluator {
	return &Evaluator{cfg: cfg, now: now.UTC()}
}

func (e *Evaluator) Evaluate(inventory model.Inventory) model.Audit {
	audit := model.Audit{
		SchemaVersion: model.SchemaVersion,
		Organization:  inventory.Organization,
		GeneratedAt:   e.now,
		RepositoryCounts: model.RepositoryCounts{
			Total: inventory.Total, Selected: inventory.Selected, Excluded: inventory.Excluded,
		},
		PolicyCounts: map[string]int{},
		Coverage:     "complete",
	}
	for _, repo := range inventory.Repositories {
		results := e.repository(repo)
		for i := range results {
			e.applySuppression(&results[i])
		}
		audit.Results = append(audit.Results, results...)
	}
	audit.Results = append(audit.Results, e.expiredSuppressions()...)
	sort.Slice(audit.Results, func(i, j int) bool {
		if audit.Results[i].Repository != audit.Results[j].Repository {
			return audit.Results[i].Repository < audit.Results[j].Repository
		}
		return audit.Results[i].PolicyID < audit.Results[j].PolicyID
	})
	for _, result := range audit.Results {
		audit.PolicyCounts[string(result.Status)]++
	}
	if !inventory.Complete || Partial(audit) {
		audit.Coverage = "partial"
	}
	return audit
}

func (e *Evaluator) repository(repo model.Repository) []model.PolicyResult {
	var results []model.PolicyResult
	actions := e.cfg.Policies.Actions
	if actions.Enabled != nil {
		results = append(results, observed(repo.FullName, "actions.enabled", "high", repo.ActionsEnabled, *actions.Enabled,
			"Configure the repository or organization Actions policy with GitHub-native controls."))
	}
	if actions.DefaultWorkflowPermissions != "" {
		results = append(results, observed(repo.FullName, "actions.default_workflow_permissions", "high", repo.DefaultWorkflowPermissions, actions.DefaultWorkflowPermissions,
			"Set the organization default GITHUB_TOKEN workflow permission to read."))
	}
	if actions.AllowedActions != "" {
		results = append(results, observed(repo.FullName, "actions.allowed_actions", "high", repo.AllowedActions, actions.AllowedActions,
			"Configure the repository or organization allowed Actions policy with GitHub-native controls."))
	}
	if actions.RequireSHAPinningEnforcement {
		results = append(results, observed(repo.FullName, "actions.sha_pinning_enforced", "high", repo.SHAPinningEnforced, true,
			"After mutable references are remediated, require full-length SHA pinning in the organization or enterprise Actions policy."))
	}
	if actions.RequireForkPRApproval != nil {
		results = append(results, observed(repo.FullName, "actions.fork_pr_approval", "medium", repo.ForkPRApproval, *actions.RequireForkPRApproval,
			"Configure fork pull-request workflow approval in the repository or organization Actions settings."))
	}

	code := e.cfg.Policies.CodeSecurity
	if code.Configuration != "" {
		observation := model.Observed[model.CodeSecurityAttachment]{
			State: model.Unknown, Reason: "approved configuration association is missing",
		}
		if repo.CodeSecurityConfiguration != nil {
			observation = *repo.CodeSecurityConfiguration
		}
		results = append(results, codeSecurity(repo.FullName, code.Configuration, observation))
	}

	repository := e.cfg.Policies.Repository
	if repository.RequireRuleset {
		results = append(results, observed(repo.FullName, "repository.ruleset", "high", repo.Ruleset, true,
			"Create an organization ruleset covering the repository's default branch."))
	}
	if repository.RequireBranchProtection {
		results = append(results, observed(repo.FullName, "repository.branch_protection", "high", repo.BranchProtection, true,
			"Prefer an organization ruleset; otherwise protect the default branch with pull-request and required-check rules."))
	}
	for _, check := range []struct {
		enabled     bool
		id          string
		observed    model.Observed[bool]
		remediation string
	}{
		{repository.RequirePullRequest, "repository.required_pull_request", repo.RequiredPullRequests, "Require pull requests through an organization ruleset or default-branch protection."},
		{repository.RequireRequiredChecks, "repository.required_checks", repo.RequiredChecks, "Require the approved status checks through an organization ruleset or default-branch protection."},
		{repository.RestrictForcePushes, "repository.force_push_restricted", repo.ForcePushRestricted, "Disable force pushes through an organization ruleset or default-branch protection."},
		{repository.RestrictDeletions, "repository.deletion_restricted", repo.DeletionRestricted, "Disable branch deletion through an organization ruleset or default-branch protection."},
	} {
		if check.enabled {
			results = append(results, observed(repo.FullName, check.id, "high", check.observed, true, check.remediation))
		}
	}
	if repository.RequireSecurityMD {
		results = append(results, observed(repo.FullName, "repository.security_md", "medium", repo.SecurityMD, true,
			"Add SECURITY.md on the default branch or provide an organization-wide default community health file."))
	}
	if len(repository.AllowedVisibilities) > 0 {
		results = append(results, direct(repo.FullName, "repository.visibility", "high",
			slices.Contains(repository.AllowedVisibilities, repo.Visibility), repo.Visibility, repository.AllowedVisibilities,
			"Change repository visibility or add a narrowly scoped, owned suppression."))
	}
	for _, check := range []struct {
		id       string
		prohibit bool
		observed bool
	}{
		{"repository.archived", repository.ProhibitArchived, repo.Archived},
		{"repository.fork", repository.ProhibitForks, repo.Fork},
		{"repository.template", repository.ProhibitTemplates, repo.Template},
	} {
		if check.prohibit {
			results = append(results, direct(repo.FullName, check.id, "medium", !check.observed, check.observed, false,
				"Change the repository classification or add a narrowly scoped, owned suppression."))
		}
	}
	return results
}

func codeSecurity(
	repository, expected string,
	observation model.Observed[model.CodeSecurityAttachment],
) model.PolicyResult {
	result := model.PolicyResult{
		Repository: repository, PolicyID: "code_security.configuration", Severity: "high",
		Expected: expected, Evidence: observation.Source,
		Remediation: "Attach the approved GitHub Code Security Configuration at organization scope.",
	}
	switch observation.State {
	case model.Available:
		result.Observed = observation.Value.Status
		if observation.Value.Status == "attached" || observation.Value.Status == "enforced" {
			result.Status = model.PolicyPass
		} else {
			result.Status = model.PolicyFail
		}
	case model.Unsupported:
		result.Status = model.PolicyUnsupported
		result.Observed = observation.Reason
	default:
		result.Status = model.PolicyUnknown
		result.Observed = observation.Reason
	}
	return result
}

func observed[T comparable](repository, id, severity string, value model.Observed[T], expected T, remediation string) model.PolicyResult {
	result := model.PolicyResult{
		Repository: repository, PolicyID: id, Severity: severity, Expected: expected,
		Evidence: value.Source, Remediation: remediation,
	}
	switch value.State {
	case model.Available:
		result.Observed = value.Value
		if value.Value == expected {
			result.Status = model.PolicyPass
		} else {
			result.Status = model.PolicyFail
		}
	case model.Unsupported:
		result.Status = model.PolicyUnsupported
		result.Observed = value.Reason
	default:
		result.Status = model.PolicyUnknown
		result.Observed = value.Reason
	}
	return result
}

func direct(repository, id, severity string, pass bool, observed, expected any, remediation string) model.PolicyResult {
	status := model.PolicyFail
	if pass {
		status = model.PolicyPass
	}
	return model.PolicyResult{
		Repository: repository, PolicyID: id, Status: status, Severity: severity,
		Observed: observed, Expected: expected, Evidence: "inventory", Remediation: remediation,
	}
}

func (e *Evaluator) applySuppression(result *model.PolicyResult) {
	if result.Status != model.PolicyFail {
		return
	}
	for i := range e.cfg.Suppressions {
		suppression := &e.cfg.Suppressions[i]
		if suppression.Policy != result.PolicyID || !repositoryMatches(suppression.Repository, result.Repository) {
			continue
		}
		if suppression.Expires != nil && !suppression.Expires.After(e.now) {
			continue
		}
		applied := *suppression
		result.Status = model.PolicyExempt
		result.Suppression = &applied
		return
	}
}

func (e *Evaluator) expiredSuppressions() []model.PolicyResult {
	var results []model.PolicyResult
	for _, suppression := range e.cfg.Suppressions {
		if suppression.Expires == nil || suppression.Expires.After(e.now) {
			continue
		}
		results = append(results, model.PolicyResult{
			Repository:  suppression.Repository,
			PolicyID:    "suppression.expired." + suppression.Policy,
			Status:      model.PolicyFail,
			Severity:    "medium",
			Observed:    suppression.Expires.UTC().Format(time.RFC3339),
			Expected:    "a future expiry or removal",
			Evidence:    "segh.yaml suppressions",
			Remediation: fmt.Sprintf("Remove or renew this suppression after review by %s; rationale: %s", suppression.Owner, suppression.Rationale),
		})
	}
	return results
}

func repositoryMatches(pattern, repository string) bool {
	if pattern == "" {
		return true
	}
	matched, err := path.Match(pattern, repository)
	return err == nil && matched
}

func Violations(audit model.Audit) bool {
	return audit.PolicyCounts[string(model.PolicyFail)] > 0
}

func Partial(audit model.Audit) bool {
	return audit.PolicyCounts[string(model.PolicyUnknown)] > 0 ||
		audit.PolicyCounts[string(model.PolicyUnsupported)] > 0
}
