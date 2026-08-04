package github

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/dceoy/segh/internal/config"
	"github.com/dceoy/segh/internal/model"
)

type InventoryService struct {
	cfg            config.Config
	client         API
	installationID int64

	permissionMu  sync.Mutex
	permissionErr *APIError
}

type apiRepository struct {
	ID            int64  `json:"id"`
	FullName      string `json:"full_name"`
	HTMLURL       string `json:"html_url"`
	Visibility    string `json:"visibility"`
	Private       bool   `json:"private"`
	Archived      bool   `json:"archived"`
	Disabled      bool   `json:"disabled"`
	Fork          bool   `json:"fork"`
	IsTemplate    bool   `json:"is_template"`
	DefaultBranch string `json:"default_branch"`
}

type apiInstallation struct {
	ID                  int64  `json:"id"`
	RepositorySelection string `json:"repository_selection"`
	Account             struct {
		Login string `json:"login"`
	} `json:"account"`
}

func NewInventoryService(cfg config.Config, client API, installationID int64) *InventoryService {
	return &InventoryService{cfg: cfg, client: client, installationID: installationID}
}

// notePermissionFailure records the first 401/403 encountered while collecting
// per-repository Actions, Administration, or Contents data. Those calls
// otherwise fold every failure into an Observed value, so a missing GitHub App
// repository permission would only ever weaken audit coverage to partial
// instead of surfacing the documented authentication/permission exit code.
func (s *InventoryService) notePermissionFailure(err error) {
	var apiErr *APIError
	if !errors.As(err, &apiErr) || (apiErr.StatusCode != 401 && apiErr.StatusCode != 403) {
		return
	}
	s.permissionMu.Lock()
	defer s.permissionMu.Unlock()
	if s.permissionErr == nil {
		s.permissionErr = apiErr
	}
}

func (s *InventoryService) Run(ctx context.Context) (model.Inventory, error) {
	inventory := model.Inventory{
		SchemaVersion: model.SchemaVersion,
		Organization:  s.cfg.Organization,
		GitHubHost:    s.client.Hostname(),
		GeneratedAt:   time.Now().UTC(),
		Complete:      true,
	}
	installationCount, installationErr := s.verifyInstallationCoversOrganization(ctx)
	if installationErr != nil {
		inventory.Complete = false
		inventory.Errors = append(inventory.Errors, model.RunError{Component: "inventory", Kind: "installation_scope", Message: installationErr.Error()})
	}
	repos, err := s.listRepositories(ctx)
	if err != nil {
		inventory.Complete = false
		inventory.Errors = append(inventory.Errors, model.RunError{Component: "inventory", Kind: "enumeration", Message: err.Error()})
		if installationErr != nil {
			return inventory, errors.Join(
				fmt.Errorf("verify installation coverage: %w", installationErr),
				err,
			)
		}
		return inventory, err
	}
	inventory.Total = len(repos)
	if installationErr == nil && installationCount != len(repos) {
		inventory.Complete = false
		inventory.Errors = append(inventory.Errors, model.RunError{
			Component: "inventory", Kind: "installation_scope",
			Message: fmt.Sprintf(
				"installation reports %d accessible repositories but organization enumeration returned %d; inventory coverage cannot be verified",
				installationCount, len(repos),
			),
		})
	}
	for _, missing := range missingExplicitRepositories(s.cfg.Selectors.Repositories, repos) {
		inventory.Complete = false
		inventory.Errors = append(inventory.Errors, model.RunError{
			Repository: missing, Component: "selectors", Kind: "repository_not_found",
			Message: fmt.Sprintf("repository %q in selectors.repositories was not found in the organization's enumerated repositories", missing),
		})
	}

	concurrency := s.cfg.Inventory.Concurrency
	jobs := make(chan apiRepository)
	results := make(chan model.Repository, len(repos))
	var workers sync.WaitGroup
	for range concurrency {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for repo := range jobs {
				results <- s.enrich(ctx, repo)
			}
		}()
	}
	go func() {
		defer close(results)
		for _, repo := range repos {
			select {
			case <-ctx.Done():
				close(jobs)
				workers.Wait()
				return
			case jobs <- repo:
			}
		}
		close(jobs)
		workers.Wait()
	}()

	for repo := range results {
		reason := s.exclusionReason(repo)
		if reason == "" {
			inventory.Repositories = append(inventory.Repositories, repo)
		} else {
			inventory.Exclusions = append(inventory.Exclusions, model.RepositoryExclusion{Repository: repo.FullName, Reason: reason})
		}
	}
	inventory.Selected = len(inventory.Repositories)
	inventory.Excluded = len(inventory.Exclusions)
	if err := ctx.Err(); err != nil {
		inventory.Complete = false
		inventory.Errors = append(inventory.Errors, model.RunError{Component: "inventory", Kind: "timeout", Message: err.Error()})
	}
	if s.permissionErr != nil {
		inventory.Complete = false
		inventory.Errors = append(inventory.Errors, model.RunError{
			Component: "inventory", Kind: "repository_permission",
			Message: "repository collection lacks a required permission: " + s.permissionErr.Error(),
		})
	}
	sort.Slice(inventory.Repositories, func(i, j int) bool {
		return inventory.Repositories[i].FullName < inventory.Repositories[j].FullName
	})
	sort.Slice(inventory.Exclusions, func(i, j int) bool {
		return inventory.Exclusions[i].Repository < inventory.Exclusions[j].Repository
	})
	sort.Slice(inventory.Errors, func(i, j int) bool {
		left, right := inventory.Errors[i], inventory.Errors[j]
		if left.Repository != right.Repository {
			return left.Repository < right.Repository
		}
		if left.Component != right.Component {
			return left.Component < right.Component
		}
		if left.Kind != right.Kind {
			return left.Kind < right.Kind
		}
		return left.Message < right.Message
	})
	if !inventory.Complete {
		runErr := fmt.Errorf("repository enumeration incomplete")
		if installationErr != nil {
			runErr = fmt.Errorf("verify installation coverage: %w", installationErr)
		}
		runErrs := []error{runErr}
		if s.permissionErr != nil {
			runErrs = append(runErrs, fmt.Errorf("collect repository controls: %w", s.permissionErr))
		}
		return inventory, errors.Join(runErrs...)
	}
	return inventory, nil
}

// verifyInstallationCoversOrganization fails closed unless authoritative
// organization installation metadata says the installation is scoped to all
// repositories. actions/create-github-app-token with owner expands to every
// repository in the installation, not every repository in the organization,
// so a selected-repository installation would otherwise silently omit
// ungoverned repositories.
//
// GET /installation/repositories does not guarantee repository_selection.
// The workflow therefore passes the installation ID emitted alongside
// GH_TOKEN, and the read-only organization Administration permission lets
// segh find that exact ID through GET /orgs/{org}/installations. The accessible
// repository endpoint remains useful for binding the token to the configured
// account and cross-checking its total_count against organization enumeration.
func (s *InventoryService) verifyInstallationCoversOrganization(ctx context.Context) (int, error) {
	metadata, err := s.getInstallationMetadata(ctx)
	if err != nil {
		return 0, err
	}
	if metadata.RepositorySelection != "all" {
		return 0, fmt.Errorf(
			"installation %d repository_selection is %q, not \"all\"; organization-wide inventory coverage cannot be verified",
			s.installationID, metadata.RepositorySelection,
		)
	}
	if !strings.EqualFold(metadata.Account.Login, s.cfg.Organization) {
		return 0, fmt.Errorf(
			"installation %d account %q does not match configured organization %q; organization-wide inventory coverage cannot be verified",
			s.installationID, metadata.Account.Login, s.cfg.Organization,
		)
	}

	var accessible struct {
		TotalCount   int `json:"total_count"`
		Repositories []struct {
			FullName string `json:"full_name"`
		} `json:"repositories"`
	}
	if err := s.client.Get(ctx, "/installation/repositories?per_page=1", &accessible); err != nil {
		return 0, fmt.Errorf("list repositories accessible to installation %d: %w", s.installationID, err)
	}
	if len(accessible.Repositories) == 0 {
		if accessible.TotalCount == 0 {
			return 0, nil
		}
		return 0, fmt.Errorf(
			"installation %d reports repository_selection \"all\" but returned no repositories; cannot verify it covers organization %q",
			s.installationID, s.cfg.Organization,
		)
	}
	owner, _, ok := strings.Cut(accessible.Repositories[0].FullName, "/")
	if !ok || !strings.EqualFold(owner, s.cfg.Organization) {
		return 0, fmt.Errorf(
			"installation %d repository owner %q does not match configured organization %q; organization-wide inventory coverage cannot be verified",
			s.installationID, owner, s.cfg.Organization,
		)
	}
	return accessible.TotalCount, nil
}

func (s *InventoryService) getInstallationMetadata(ctx context.Context) (apiInstallation, error) {
	if s.installationID <= 0 {
		return apiInstallation{}, fmt.Errorf("SEGH_GITHUB_INSTALLATION_ID must be a positive integer")
	}
	for page := 1; ; page++ {
		var response struct {
			Installations []apiInstallation `json:"installations"`
		}
		apiPath := fmt.Sprintf(
			"/orgs/%s/installations?per_page=100&page=%d",
			pathEscape(s.cfg.Organization), page,
		)
		if err := s.client.Get(ctx, apiPath, &response); err != nil {
			return apiInstallation{}, fmt.Errorf("get organization installation metadata: %w", err)
		}
		for _, installation := range response.Installations {
			if installation.ID == s.installationID {
				return installation, nil
			}
		}
		if len(response.Installations) < 100 {
			return apiInstallation{}, fmt.Errorf(
				"installation %d was not found in configured organization %q",
				s.installationID, s.cfg.Organization,
			)
		}
	}
}

func (s *InventoryService) listRepositories(ctx context.Context) ([]apiRepository, error) {
	var repositories []apiRepository
	for page := 1; ; page++ {
		var batch []apiRepository
		apiPath := fmt.Sprintf(
			"/orgs/%s/repos?per_page=100&page=%d&type=all&sort=full_name&direction=asc",
			pathEscape(s.cfg.Organization), page,
		)
		if err := s.client.Get(ctx, apiPath, &batch); err != nil {
			return nil, err
		}
		repositories = append(repositories, batch...)
		if len(batch) < 100 {
			return repositories, nil
		}
	}
}

// missingExplicitRepositories reports entries of selectors.repositories that were not
// found among the organization's enumerated repositories. A typo, rename, or a
// repository the token cannot see would otherwise be silently dropped: exclusionReason
// treats an allowlist as "not explicitly included" for every repository it doesn't
// match, so a wholly unmatched entry never surfaces as anything but a normal exclusion.
func missingExplicitRepositories(allowlist []string, repos []apiRepository) []string {
	if len(allowlist) == 0 {
		return nil
	}
	enumerated := make(map[string]bool, len(repos))
	for _, repo := range repos {
		enumerated[repo.FullName] = true
	}
	var missing []string
	for _, name := range allowlist {
		if !enumerated[name] {
			missing = append(missing, name)
		}
	}
	return missing
}

func (s *InventoryService) enrich(ctx context.Context, raw apiRepository) model.Repository {
	repo := repositoryFromAPI(raw)
	base := "/repos/" + escapeFullName(raw.FullName)
	s.collectActionsControls(ctx, base, &repo)
	s.collectDependencyControls(ctx, base, &repo)
	s.collectBranchGovernance(ctx, base, raw.DefaultBranch, &repo)
	repo.SecurityMD = s.securityPolicyExists(ctx, base, raw.DefaultBranch)
	return repo
}

func (s *InventoryService) collectDependencyControls(ctx context.Context, base string, repo *model.Repository) {
	repo.DependencyGraph = s.probeEndpoint(ctx, base+"/dependency-graph/sbom", "dependency_graph/sbom", nil)
	repo.DependabotAlerts = s.probeEndpoint(ctx, base+"/vulnerability-alerts", "vulnerability_alerts", nil)
	repo.DependabotSecurityUpdates = s.probeEndpoint(ctx, base+"/automated-security-fixes", "automated_security_fixes", nil)
}

func repositoryFromAPI(raw apiRepository) model.Repository {
	visibility := raw.Visibility
	if visibility == "" && raw.Private {
		visibility = "private"
	}
	if visibility == "" {
		visibility = "public"
	}
	return model.Repository{
		ID:            raw.ID,
		FullName:      raw.FullName,
		HTMLURL:       raw.HTMLURL,
		Visibility:    visibility,
		Archived:      raw.Archived,
		Disabled:      raw.Disabled,
		Fork:          raw.Fork,
		Template:      raw.IsTemplate,
		DefaultBranch: raw.DefaultBranch,
	}
}

func (s *InventoryService) collectActionsControls(ctx context.Context, base string, repo *model.Repository) {
	actions := observe(s, "actions_permissions", func() (struct {
		Enabled            bool   `json:"enabled"`
		AllowedActions     string `json:"allowed_actions"`
		SHAPinningRequired *bool  `json:"sha_pinning_required"`
	}, error) {
		var response struct {
			Enabled            bool   `json:"enabled"`
			AllowedActions     string `json:"allowed_actions"`
			SHAPinningRequired *bool  `json:"sha_pinning_required"`
		}
		err := s.client.Get(ctx, base+"/actions/permissions", &response)
		return response, err
	})
	if actions.State != model.Available {
		repo.ActionsEnabled = model.Observed[bool]{State: actions.State, Source: actions.Source, Reason: actions.Reason}
		repo.AllowedActions = model.Observed[string]{State: actions.State, Source: actions.Source, Reason: actions.Reason}
		repo.SHAPinningEnforced = model.Observed[bool]{State: actions.State, Source: actions.Source, Reason: actions.Reason}
	} else {
		repo.ActionsEnabled = model.Observed[bool]{State: model.Available, Value: actions.Value.Enabled, Source: actions.Source}
		repo.AllowedActions = model.Observed[string]{State: model.Available, Value: actions.Value.AllowedActions, Source: actions.Source}
		if actions.Value.SHAPinningRequired == nil {
			repo.SHAPinningEnforced = model.Observed[bool]{State: model.Unknown, Source: "actions_permissions", Reason: "field unavailable"}
		} else {
			repo.SHAPinningEnforced = model.Observed[bool]{
				State: model.Available, Value: *actions.Value.SHAPinningRequired, Source: actions.Source,
			}
		}
	}
	var workflowPermissions struct {
		DefaultWorkflowPermissions string `json:"default_workflow_permissions"`
	}
	repo.DefaultWorkflowPermissions = observe(s, "workflow_permissions", func() (string, error) {
		if err := s.client.Get(ctx, base+"/actions/permissions/workflow", &workflowPermissions); err != nil {
			return "", err
		}
		return workflowPermissions.DefaultWorkflowPermissions, nil
	})
	var forkApproval struct {
		ApprovalPolicy string `json:"approval_policy"`
	}
	repo.ForkPRApproval = observe(s, "fork_pr_approval", func() (bool, error) {
		if err := s.client.Get(ctx, base+"/actions/permissions/fork-pr-contributor-approval", &forkApproval); err != nil {
			return false, err
		}
		return forkApproval.ApprovalPolicy != "first_time_contributors_new_to_github", nil
	})
}

func (s *InventoryService) collectBranchGovernance(ctx context.Context, base, branch string, repo *model.Repository) {
	rulesSource := "rules_branches"
	var effectiveRules []struct {
		Type string `json:"type"`
	}
	rulesErr := s.client.Get(ctx, base+"/rules/branches/"+pathEscape(branch), &effectiveRules)
	ruleTypes := map[string]bool{}
	if rulesErr == nil {
		for _, rule := range effectiveRules {
			ruleTypes[rule.Type] = true
		}
		repo.Ruleset = model.Observed[bool]{State: model.Available, Value: len(effectiveRules) > 0, Source: rulesSource}
	} else {
		s.notePermissionFailure(rulesErr)
		state, reason := ErrorState(rulesErr)
		repo.Ruleset = model.Observed[bool]{State: model.Availability(state), Source: rulesSource, Reason: reason}
	}
	var protection struct {
		RequiredPullRequestReviews any `json:"required_pull_request_reviews"`
		RequiredStatusChecks       any `json:"required_status_checks"`
		AllowForcePushes           *struct {
			Enabled bool `json:"enabled"`
		} `json:"allow_force_pushes"`
		AllowDeletions *struct {
			Enabled bool `json:"enabled"`
		} `json:"allow_deletions"`
	}
	protectionSource := "branch_protection"
	var classicProtection, classicPullRequests, classicChecks, classicForcePush, classicDeletion model.Observed[bool]
	protectionErr := s.client.Get(ctx, base+"/branches/"+pathEscape(branch)+"/protection", &protection)
	var protectionAPIErr *APIError
	if errors.As(protectionErr, &protectionAPIErr) && protectionAPIErr.StatusCode == 404 {
		absent := model.Observed[bool]{State: model.Available, Value: false, Source: protectionSource}
		classicProtection, classicPullRequests, classicChecks = absent, absent, absent
		classicForcePush, classicDeletion = absent, absent
	} else if protectionErr != nil {
		s.notePermissionFailure(protectionErr)
		state, reason := ErrorState(protectionErr)
		unknown := model.Observed[bool]{State: model.Availability(state), Source: protectionSource, Reason: reason}
		classicProtection, classicPullRequests, classicChecks = unknown, unknown, unknown
		classicForcePush, classicDeletion = unknown, unknown
	} else {
		classicProtection = model.Observed[bool]{State: model.Available, Value: true, Source: protectionSource}
		classicPullRequests = model.Observed[bool]{State: model.Available, Value: protection.RequiredPullRequestReviews != nil, Source: protectionSource}
		classicChecks = model.Observed[bool]{State: model.Available, Value: protection.RequiredStatusChecks != nil, Source: protectionSource}
		if protection.AllowForcePushes == nil {
			classicForcePush = model.Observed[bool]{State: model.Unknown, Source: protectionSource, Reason: "field unavailable"}
		} else {
			classicForcePush = model.Observed[bool]{State: model.Available, Value: !protection.AllowForcePushes.Enabled, Source: protectionSource}
		}
		if protection.AllowDeletions == nil {
			classicDeletion = model.Observed[bool]{State: model.Unknown, Source: protectionSource, Reason: "field unavailable"}
		} else {
			classicDeletion = model.Observed[bool]{State: model.Available, Value: !protection.AllowDeletions.Enabled, Source: protectionSource}
		}
	}
	// GitHub enforces the union of effective rulesets and classic branch
	// protection. Merge both sources so either can prove a control is active.
	repo.BranchProtection = mergeControl(rulesErr, len(ruleTypes) > 0, classicProtection)
	repo.RequiredPullRequests = mergeControl(rulesErr, ruleTypes["pull_request"], classicPullRequests)
	repo.RequiredChecks = mergeControl(rulesErr, ruleTypes["required_status_checks"], classicChecks)
	repo.ForcePushRestricted = mergeControl(rulesErr, ruleTypes["non_fast_forward"], classicForcePush)
	repo.DeletionRestricted = mergeControl(rulesErr, ruleTypes["deletion"], classicDeletion)
}

type jsonObject map[string]any

// mergeControl combines a boolean policy control derived from GitHub's effective
// rules-for-branch evaluation (rulesErr/ruleTypePresent) with the equivalent control
// derived from classic branch protection (classic). Either mechanism enforcing the
// control is sufficient, matching GitHub's own behavior of enforcing the union of
// whatever rulesets and branch protection both require.
func mergeControl(rulesErr error, ruleTypePresent bool, classic model.Observed[bool]) model.Observed[bool] {
	if rulesErr == nil {
		if ruleTypePresent {
			return model.Observed[bool]{State: model.Available, Value: true, Source: "rules_branches"}
		}
		return classic
	}
	if classic.State == model.Available && classic.Value {
		return classic
	}
	state, reason := ErrorState(rulesErr)
	return model.Observed[bool]{State: model.Availability(state), Source: "rules_branches", Reason: "ruleset evaluation unavailable: " + reason}
}

func observe[T any](
	service *InventoryService, source string, fetch func() (T, error),
) model.Observed[T] {
	value, err := fetch()
	if err == nil {
		return model.Observed[T]{State: model.Available, Value: value, Source: source}
	}
	service.notePermissionFailure(err)
	state, reason := ErrorState(err)
	return model.Observed[T]{State: model.Availability(state), Source: source, Reason: reason}
}

// probeEndpoint treats success as present/enabled and 404 as absent/disabled.
// Other failures remain unknown or unsupported instead of being mistaken for a
// disabled control. response may be nil when the body is not needed.
func (s *InventoryService) probeEndpoint(ctx context.Context, path, source string, response any) model.Observed[bool] {
	err := s.client.Get(ctx, path, response)
	if err == nil {
		return model.Observed[bool]{State: model.Available, Value: true, Source: source}
	}
	var apiErr *APIError
	if errors.As(err, &apiErr) && apiErr.StatusCode == 404 {
		return model.Observed[bool]{State: model.Available, Value: false, Source: source}
	}
	s.notePermissionFailure(err)
	state, reason := ErrorState(err)
	return model.Observed[bool]{State: model.Availability(state), Source: source, Reason: reason}
}

// securityMDPaths lists the repository locations GitHub itself accepts a security
// policy at, checked as a fallback when the community profile API is unavailable or
// reports no policy.
var securityMDPaths = []string{"SECURITY.md", ".github/SECURITY.md", "docs/SECURITY.md"}

// securityPolicyExists uses GitHub's authoritative community profile when it
// finds a policy, then checks every supported repository path on a miss or 404.
func (s *InventoryService) securityPolicyExists(ctx context.Context, base, branch string) model.Observed[bool] {
	var profile struct {
		Files struct {
			Security *jsonObject `json:"security"`
		} `json:"files"`
	}
	err := s.client.Get(ctx, base+"/community/profile", &profile)
	switch {
	case err == nil && profile.Files.Security != nil:
		return model.Observed[bool]{State: model.Available, Value: true, Source: "community/profile"}
	case err == nil:
		return s.anyContentExists(ctx, base, branch, securityMDPaths, "security_md")
	default:
		var apiErr *APIError
		if errors.As(err, &apiErr) && apiErr.StatusCode == 404 {
			return s.anyContentExists(ctx, base, branch, securityMDPaths, "security_md")
		}
		s.notePermissionFailure(err)
		state, reason := ErrorState(err)
		return model.Observed[bool]{State: model.Availability(state), Source: "community/profile", Reason: reason}
	}
}

func (s *InventoryService) anyContentExists(ctx context.Context, base, branch string, paths []string, source string) model.Observed[bool] {
	for _, candidate := range paths {
		var content jsonObject
		result := s.probeEndpoint(ctx, base+"/contents/"+candidate+"?ref="+pathEscape(branch), source, &content)
		if result.State != model.Available {
			return result
		}
		if result.Value {
			return result
		}
	}
	return model.Observed[bool]{State: model.Available, Value: false, Source: source}
}

func (s *InventoryService) exclusionReason(repo model.Repository) string {
	selectors := s.cfg.Selectors
	if selectors.ExcludeArchived && repo.Archived {
		return "archived"
	}
	if selectors.ExcludeDisabled && repo.Disabled {
		return "disabled"
	}
	if selectors.ExcludeForks && repo.Fork {
		return "fork"
	}
	if len(selectors.Repositories) > 0 && !slices.Contains(selectors.Repositories, repo.FullName) {
		return "not explicitly included"
	}
	if slices.Contains(selectors.Exclude, repo.FullName) {
		return "explicitly excluded"
	}
	return ""
}

func escapeFullName(fullName string) string {
	parts := strings.Split(fullName, "/")
	if len(parts) != 2 {
		return pathEscape(fullName)
	}
	return pathEscape(parts[0]) + "/" + pathEscape(parts[1])
}
