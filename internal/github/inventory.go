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
}

type apiRepository struct {
	ID                  int64    `json:"id"`
	FullName            string   `json:"full_name"`
	HTMLURL             string   `json:"html_url"`
	Visibility          string   `json:"visibility"`
	Private             bool     `json:"private"`
	Archived            bool     `json:"archived"`
	Disabled            bool     `json:"disabled"`
	Fork                bool     `json:"fork"`
	IsTemplate          bool     `json:"is_template"`
	DefaultBranch       string   `json:"default_branch"`
	Topics              []string `json:"topics"`
	SecurityAndAnalysis map[string]struct {
		Status string `json:"status"`
	} `json:"security_and_analysis"`
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

func (s *InventoryService) Run(ctx context.Context) (model.Inventory, error) {
	inventory := model.Inventory{
		SchemaVersion: model.InventorySchemaVersion,
		Organization:  s.cfg.Organization,
		GitHubHost:    s.cfg.GitHub.WebURL,
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
		reason, propertiesUnknown := s.exclusionReason(repo)
		if propertiesUnknown {
			inventory.Complete = false
			inventory.Errors = append(inventory.Errors, model.RunError{
				Repository: repo.FullName, Component: "selectors", Kind: "custom_properties_unknown",
				Message: "custom properties unavailable; selection based on selectors.custom_properties could not be verified",
			})
		}
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
	sort.Slice(inventory.Repositories, func(i, j int) bool {
		return inventory.Repositories[i].FullName < inventory.Repositories[j].FullName
	})
	sort.Slice(inventory.Exclusions, func(i, j int) bool {
		return inventory.Exclusions[i].Repository < inventory.Exclusions[j].Repository
	})
	if !inventory.Complete {
		if installationErr != nil {
			return inventory, fmt.Errorf("verify installation coverage: %w", installationErr)
		}
		return inventory, fmt.Errorf("repository enumeration incomplete")
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
	s.collectCustomProperties(ctx, base, &repo)
	s.collectActionsControls(ctx, base, &repo)
	s.collectBranchGovernance(ctx, base, raw.DefaultBranch, &repo)
	s.collectCodeSecurity(ctx, base, raw, &repo)
	repo.SecurityMD = s.securityPolicyExists(ctx, base, raw.DefaultBranch)
	return repo
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
		Topics:        sortedStrings(raw.Topics),
	}
}

func (s *InventoryService) collectCustomProperties(ctx context.Context, base string, repo *model.Repository) {
	repo.CustomProperties = getObserved("properties/values", func() (map[string]any, error) {
		var properties []struct {
			PropertyName string `json:"property_name"`
			Value        any    `json:"value"`
		}
		if err := s.client.Get(ctx, base+"/properties/values", &properties); err != nil {
			return nil, err
		}
		values := make(map[string]any, len(properties))
		for _, property := range properties {
			value, valid := normalizeCustomPropertyValue(property.Value)
			if !valid {
				return nil, fmt.Errorf("unsupported custom property value")
			}
			values[property.PropertyName] = value
		}
		return values, nil
	})
}

func (s *InventoryService) collectActionsControls(ctx context.Context, base string, repo *model.Repository) {
	var actions struct {
		Enabled            bool   `json:"enabled"`
		AllowedActions     string `json:"allowed_actions"`
		SHAPinningRequired *bool  `json:"sha_pinning_required"`
	}
	if err := s.client.Get(ctx, base+"/actions/permissions", &actions); err != nil {
		state, reason := ErrorState(err)
		repo.ActionsEnabled = model.Observed[bool]{State: model.Availability(state), Source: "actions_permissions", Reason: reason}
		repo.AllowedActions = model.Observed[string]{State: model.Availability(state), Source: "actions_permissions", Reason: reason}
		repo.SHAPinningEnforced = model.Observed[bool]{State: model.Availability(state), Source: "actions_permissions", Reason: reason}
	} else {
		repo.ActionsEnabled = model.Observed[bool]{State: model.Available, Value: actions.Enabled, Source: "actions_permissions"}
		repo.AllowedActions = model.Observed[string]{State: model.Available, Value: actions.AllowedActions, Source: "actions_permissions"}
		if actions.SHAPinningRequired == nil {
			repo.SHAPinningEnforced = model.Observed[bool]{State: model.Unknown, Source: "actions_permissions", Reason: "field unavailable"}
		} else {
			repo.SHAPinningEnforced = model.Observed[bool]{State: model.Available, Value: *actions.SHAPinningRequired, Source: "actions_permissions"}
		}
	}
	var workflowPermissions struct {
		DefaultWorkflowPermissions string `json:"default_workflow_permissions"`
	}
	repo.DefaultWorkflowPermissions = getObserved("workflow_permissions", func() (string, error) {
		if err := s.client.Get(ctx, base+"/actions/permissions/workflow", &workflowPermissions); err != nil {
			return "", err
		}
		return workflowPermissions.DefaultWorkflowPermissions, nil
	})
	var forkApproval struct {
		ApprovalPolicy string `json:"approval_policy"`
	}
	repo.ForkPRApproval = getObserved("fork_pr_approval", func() (bool, error) {
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

func (s *InventoryService) collectCodeSecurity(ctx context.Context, base string, raw apiRepository, repo *model.Repository) {
	repo.SecretScanning = observedSecurity(raw, "secret_scanning")
	repo.PushProtection = observedSecurity(raw, "secret_scanning_push_protection")
	repo.DependencyGraph = s.probeEndpoint(ctx, base+"/dependency-graph/sbom", "dependency_graph/sbom", nil)
	repo.DependabotSecurityUpdates = s.probeEndpoint(ctx, base+"/automated-security-fixes", "automated_security_fixes", nil)
	var securityConfig struct {
		Configuration struct {
			Name string `json:"name"`
		} `json:"configuration"`
	}
	repo.CodeSecurityConfiguration = getObserved("code_security_configuration", func() (string, error) {
		if err := s.client.Get(ctx, base+"/code-security-configuration", &securityConfig); err != nil {
			return "", err
		}
		return securityConfig.Configuration.Name, nil
	})
	var defaultSetup struct {
		State string `json:"state"`
	}
	repo.CodeQL = getObserved("codeql_default_setup", func() (bool, error) {
		if err := s.client.Get(ctx, base+"/code-scanning/default-setup", &defaultSetup); err != nil {
			return false, err
		}
		return defaultSetup.State == "configured", nil
	})
	var alert []jsonObject
	repo.DependabotAlerts = getObserved("dependabot_alerts", func() (bool, error) {
		err := s.client.Get(ctx, base+"/dependabot/alerts?per_page=1", &alert)
		return err == nil, err
	})
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

func observedSecurity(raw apiRepository, key string) model.Observed[bool] {
	item, ok := raw.SecurityAndAnalysis[key]
	if !ok {
		return model.Observed[bool]{State: model.Unknown, Source: "GET repository", Reason: "field unavailable"}
	}
	return model.Observed[bool]{State: model.Available, Value: item.Status == "enabled", Source: "GET repository"}
}

func getObserved[T any](source string, getter func() (T, error)) model.Observed[T] {
	value, err := getter()
	if err == nil {
		return model.Observed[T]{State: model.Available, Value: value, Source: source}
	}
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

func (s *InventoryService) exclusionReason(repo model.Repository) (reason string, propertiesUnknown bool) {
	selectors := s.cfg.Selectors
	if selectors.ExcludeArchived && repo.Archived {
		return "archived", false
	}
	if selectors.ExcludeDisabled && repo.Disabled {
		return "disabled", false
	}
	if selectors.ExcludeForks && repo.Fork {
		return "fork", false
	}
	if len(selectors.Repositories) > 0 && !slices.Contains(selectors.Repositories, repo.FullName) {
		return "not explicitly included", false
	}
	if slices.Contains(selectors.Exclude, repo.FullName) {
		return "explicitly excluded", false
	}
	if len(selectors.Visibilities) > 0 && !slices.Contains(selectors.Visibilities, repo.Visibility) {
		return "visibility", false
	}
	if len(selectors.IncludeTopics) > 0 && !intersects(repo.Topics, selectors.IncludeTopics) {
		return "required topic missing", false
	}
	if intersects(repo.Topics, selectors.ExcludeTopics) {
		return "excluded topic", false
	}
	if len(selectors.CustomProperties) > 0 {
		if repo.CustomProperties.State != model.Available {
			// The custom-properties API call failed, so repo.CustomProperties holds no
			// reliable data. Treating missing keys as mismatches here would silently
			// exclude the repository from the audit instead of surfacing the gap.
			return "", true
		}
		for key, expected := range selectors.CustomProperties {
			matches, valid := customPropertyMatches(repo.CustomProperties.Value[key], expected)
			if !valid {
				return "", true
			}
			if !matches {
				return "custom property " + key, false
			}
		}
	}
	return "", false
}

func escapeFullName(fullName string) string {
	parts := strings.Split(fullName, "/")
	if len(parts) != 2 {
		return pathEscape(fullName)
	}
	return pathEscape(parts[0]) + "/" + pathEscape(parts[1])
}

func sortedStrings(values []string) []string {
	result := slices.Clone(values)
	sort.Strings(result)
	return result
}

func intersects(left, right []string) bool {
	for _, value := range left {
		if slices.Contains(right, value) {
			return true
		}
	}
	return false
}

func normalizeCustomPropertyValue(value any) (any, bool) {
	switch typed := value.(type) {
	case nil, string:
		return typed, true
	case []any:
		values := make([]string, len(typed))
		for i, item := range typed {
			text, ok := item.(string)
			if !ok {
				return nil, false
			}
			values[i] = text
		}
		sort.Strings(values)
		return values, true
	case []string:
		return sortedStrings(typed), true
	default:
		return nil, false
	}
}

func customPropertyMatches(value any, expected string) (matches, valid bool) {
	switch typed := value.(type) {
	case nil:
		return false, true
	case string:
		return typed == expected, true
	case []string:
		return slices.Contains(typed, expected), true
	default:
		return false, false
	}
}
