package github

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/dceoy/segh/internal/config"
	"github.com/dceoy/segh/internal/logging"
	"github.com/dceoy/segh/internal/model"
)

var usesPattern = regexp.MustCompile(`(?m)^\s*(?:-\s*)?uses:\s*["']?([^@"'\s]+)@([^"'\s#]+)(?:["']?\s*#\s*([A-Za-z0-9_.+/-]+))?`)
var fullSHAPattern = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)

type InventoryService struct {
	cfg    config.Config
	client *Client
	log    *logging.Logger
}

type apiRepository struct {
	ID                  int64    `json:"id"`
	FullName            string   `json:"full_name"`
	HTMLURL             string   `json:"html_url"`
	CloneURL            string   `json:"clone_url"`
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

func NewInventoryService(cfg config.Config, client *Client, log *logging.Logger) *InventoryService {
	return &InventoryService{cfg: cfg, client: client, log: log}
}

func (s *InventoryService) Run(ctx context.Context) (model.Inventory, error) {
	inventory := model.Inventory{
		SchemaVersion: model.InventorySchemaVersion,
		Organization:  s.cfg.Organization,
		GitHubHost:    s.cfg.GitHub.WebURL,
		GeneratedAt:   time.Now().UTC(),
		Complete:      true,
	}
	repos, err := s.listRepositories(ctx)
	if err != nil {
		inventory.Complete = false
		inventory.Errors = append(inventory.Errors, model.RunError{Component: "inventory", Kind: "enumeration", Message: err.Error()})
		return inventory, err
	}
	inventory.Total = len(repos)

	concurrency := s.cfg.Execution.Concurrency
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
		if reason := s.exclusionReason(repo); reason == "" {
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
		return inventory, fmt.Errorf("repository enumeration incomplete")
	}
	return inventory, nil
}

func (s *InventoryService) listRepositories(ctx context.Context) ([]apiRepository, error) {
	var all []apiRepository
	for page := 1; ; page++ {
		var batch []apiRepository
		path := fmt.Sprintf("/orgs/%s/repos?per_page=100&page=%d&type=all&sort=full_name&direction=asc", pathEscape(s.cfg.Organization), page)
		if err := s.client.Get(ctx, path, &batch); err != nil {
			return nil, err
		}
		all = append(all, batch...)
		if len(batch) < 100 {
			return all, nil
		}
	}
}

func (s *InventoryService) enrich(ctx context.Context, raw apiRepository) model.Repository {
	visibility := raw.Visibility
	if visibility == "" {
		if raw.Private {
			visibility = "private"
		} else {
			visibility = "public"
		}
	}
	repo := model.Repository{
		ID:               raw.ID,
		FullName:         raw.FullName,
		HTMLURL:          raw.HTMLURL,
		CloneURL:         raw.CloneURL,
		Visibility:       visibility,
		Archived:         raw.Archived,
		Disabled:         raw.Disabled,
		Fork:             raw.Fork,
		Template:         raw.IsTemplate,
		DefaultBranch:    raw.DefaultBranch,
		Topics:           sortedStrings(raw.Topics),
		Capabilities:     map[string]model.Availability{},
		CustomProperties: map[string]string{},
	}
	repo.SecretScanning = observedSecurity(raw, "secret_scanning")
	repo.PushProtection = observedSecurity(raw, "secret_scanning_push_protection")
	repo.DependencyGraph = observedSecurity(raw, "dependency_graph")
	repo.DependabotSecurityUpdates = observedSecurity(raw, "dependabot_security_updates")
	base := "/repos/" + escapeFullName(raw.FullName)

	var branch struct {
		Commit struct {
			SHA string `json:"sha"`
		} `json:"commit"`
	}
	repo.DefaultBranchSHA = s.getObservedString(ctx, base+"/branches/"+pathEscape(raw.DefaultBranch), "default_branch", func() (string, error) {
		if err := s.client.Get(ctx, base+"/branches/"+pathEscape(raw.DefaultBranch), &branch); err != nil {
			return "", err
		}
		return branch.Commit.SHA, nil
	})

	var languages map[string]int64
	if err := s.client.Get(ctx, base+"/languages", &languages); err == nil {
		repo.Languages = languages
	} else {
		repo.Capabilities["languages"] = stateFor(err)
	}
	var properties []struct {
		PropertyName string `json:"property_name"`
		Value        any    `json:"value"`
	}
	if err := s.client.Get(ctx, base+"/properties/values", &properties); err == nil {
		for _, property := range properties {
			repo.CustomProperties[property.PropertyName] = fmt.Sprint(property.Value)
		}
	} else {
		repo.Capabilities["custom_properties"] = stateFor(err)
	}

	var actions struct {
		Enabled            bool   `json:"enabled"`
		AllowedActions     string `json:"allowed_actions"`
		SHAPinningRequired *bool  `json:"sha_pinning_required"`
	}
	repo.ActionsEnabled = s.getObservedBool(ctx, base+"/actions/permissions", "actions_permissions", func() (bool, error) {
		if err := s.client.Get(ctx, base+"/actions/permissions", &actions); err != nil {
			return false, err
		}
		return actions.Enabled, nil
	})
	repo.AllowedActions = s.getObservedString(ctx, base+"/actions/permissions", "actions_permissions", func() (string, error) {
		if err := s.client.Get(ctx, base+"/actions/permissions", &actions); err != nil {
			return "", err
		}
		return actions.AllowedActions, nil
	})
	if err := s.client.Get(ctx, base+"/actions/permissions", &actions); err != nil {
		state, reason := ErrorState(err)
		repo.SHAPinningEnforced = model.Observed[bool]{State: model.Availability(state), Source: "actions_permissions", Reason: reason}
	} else if actions.SHAPinningRequired == nil {
		repo.SHAPinningEnforced = model.Observed[bool]{State: model.Unknown, Source: "actions_permissions", Reason: "field unavailable"}
	} else {
		repo.SHAPinningEnforced = model.Observed[bool]{State: model.Available, Value: *actions.SHAPinningRequired, Source: "actions_permissions"}
	}
	var workflowPermissions struct {
		DefaultWorkflowPermissions   string `json:"default_workflow_permissions"`
		CanApprovePullRequestReviews bool   `json:"can_approve_pull_request_reviews"`
	}
	repo.DefaultWorkflowPermissions = s.getObservedString(ctx, base+"/actions/permissions/workflow", "workflow_permissions", func() (string, error) {
		if err := s.client.Get(ctx, base+"/actions/permissions/workflow", &workflowPermissions); err != nil {
			return "", err
		}
		return workflowPermissions.DefaultWorkflowPermissions, nil
	})
	var forkApproval struct {
		ApprovalPolicy string `json:"approval_policy"`
	}
	repo.ForkPRApproval = s.getObservedBool(ctx, base+"/actions/permissions/fork-pr-contributor-approval", "fork_pr_approval", func() (bool, error) {
		if err := s.client.Get(ctx, base+"/actions/permissions/fork-pr-contributor-approval", &forkApproval); err != nil {
			return false, err
		}
		return forkApproval.ApprovalPolicy != "first_time_contributors_new_to_github", nil
	})
	var rulesets []jsonObject
	repo.Ruleset = s.getObservedBool(ctx, base+"/rulesets?includes_parents=true", "rulesets", func() (bool, error) {
		if err := s.client.Get(ctx, base+"/rulesets?includes_parents=true", &rulesets); err != nil {
			return false, err
		}
		return len(rulesets) > 0, nil
	})
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
	protectionErr := s.client.Get(ctx, base+"/branches/"+pathEscape(raw.DefaultBranch)+"/protection", &protection)
	var protectionAPIErr *APIError
	if errors.As(protectionErr, &protectionAPIErr) && protectionAPIErr.StatusCode == 404 {
		repo.BranchProtection = model.Observed[bool]{State: model.Available, Value: false, Source: protectionSource}
		repo.RequiredPullRequests = model.Observed[bool]{State: model.Available, Value: false, Source: protectionSource}
		repo.RequiredChecks = model.Observed[bool]{State: model.Available, Value: false, Source: protectionSource}
		repo.ForcePushRestricted = model.Observed[bool]{State: model.Available, Value: false, Source: protectionSource}
		repo.DeletionRestricted = model.Observed[bool]{State: model.Available, Value: false, Source: protectionSource}
	} else if protectionErr != nil {
		state, reason := ErrorState(protectionErr)
		unknown := model.Observed[bool]{State: model.Availability(state), Source: protectionSource, Reason: reason}
		repo.BranchProtection, repo.RequiredPullRequests, repo.RequiredChecks = unknown, unknown, unknown
		repo.ForcePushRestricted, repo.DeletionRestricted = unknown, unknown
	} else {
		repo.BranchProtection = model.Observed[bool]{State: model.Available, Value: true, Source: protectionSource}
		repo.RequiredPullRequests = model.Observed[bool]{State: model.Available, Value: protection.RequiredPullRequestReviews != nil, Source: protectionSource}
		repo.RequiredChecks = model.Observed[bool]{State: model.Available, Value: protection.RequiredStatusChecks != nil, Source: protectionSource}
		if protection.AllowForcePushes == nil {
			repo.ForcePushRestricted = model.Observed[bool]{State: model.Unknown, Source: protectionSource, Reason: "field unavailable"}
		} else {
			repo.ForcePushRestricted = model.Observed[bool]{State: model.Available, Value: !protection.AllowForcePushes.Enabled, Source: protectionSource}
		}
		if protection.AllowDeletions == nil {
			repo.DeletionRestricted = model.Observed[bool]{State: model.Unknown, Source: protectionSource, Reason: "field unavailable"}
		} else {
			repo.DeletionRestricted = model.Observed[bool]{State: model.Available, Value: !protection.AllowDeletions.Enabled, Source: protectionSource}
		}
	}
	var securityConfig struct {
		Name string `json:"name"`
	}
	repo.CodeSecurityConfiguration = s.getObservedString(ctx, base+"/code-security-configuration", "code_security_configuration", func() (string, error) {
		if err := s.client.Get(ctx, base+"/code-security-configuration", &securityConfig); err != nil {
			return "", err
		}
		return securityConfig.Name, nil
	})
	var defaultSetup struct {
		State string `json:"state"`
	}
	repo.CodeQL = s.getObservedBool(ctx, base+"/code-scanning/default-setup", "codeql_default_setup", func() (bool, error) {
		if err := s.client.Get(ctx, base+"/code-scanning/default-setup", &defaultSetup); err != nil {
			return false, err
		}
		return defaultSetup.State == "configured", nil
	})
	var alert []jsonObject
	repo.DependabotAlerts = s.getObservedBool(ctx, base+"/dependabot/alerts?per_page=1", "dependabot_alerts", func() (bool, error) {
		err := s.client.Get(ctx, base+"/dependabot/alerts?per_page=1", &alert)
		return err == nil, err
	})
	repo.SecurityMD = s.contentExists(ctx, base+"/contents/SECURITY.md?ref="+pathEscape(raw.DefaultBranch), "security_md")
	repo.RenovateConfigured = s.anyContentExists(ctx, base, raw.DefaultBranch, []string{
		"renovate.json", "renovate.json5", ".github/renovate.json", ".github/renovate.json5",
	}, "renovate_config")
	repo.FullSHAPinning, repo.ActionPinningStatus = s.workflowPinning(ctx, base, raw.DefaultBranch)
	return repo
}

type jsonObject map[string]any

func observedSecurity(raw apiRepository, key string) model.Observed[bool] {
	item, ok := raw.SecurityAndAnalysis[key]
	if !ok {
		return model.Observed[bool]{State: model.Unknown, Source: "GET repository", Reason: "field unavailable"}
	}
	return model.Observed[bool]{State: model.Available, Value: item.Status == "enabled", Source: "GET repository"}
}

func (s *InventoryService) getObservedBool(_ context.Context, _ string, source string, getter func() (bool, error)) model.Observed[bool] {
	value, err := getter()
	if err == nil {
		return model.Observed[bool]{State: model.Available, Value: value, Source: source}
	}
	state, reason := ErrorState(err)
	return model.Observed[bool]{State: model.Availability(state), Source: source, Reason: reason}
}

func (s *InventoryService) getObservedString(_ context.Context, _ string, source string, getter func() (string, error)) model.Observed[string] {
	value, err := getter()
	if err == nil {
		return model.Observed[string]{State: model.Available, Value: value, Source: source}
	}
	state, reason := ErrorState(err)
	return model.Observed[string]{State: model.Availability(state), Source: source, Reason: reason}
}

func (s *InventoryService) contentExists(ctx context.Context, path, source string) model.Observed[bool] {
	var content jsonObject
	err := s.client.Get(ctx, path, &content)
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

func (s *InventoryService) anyContentExists(ctx context.Context, base, branch string, paths []string, source string) model.Observed[bool] {
	for _, candidate := range paths {
		result := s.contentExists(ctx, base+"/contents/"+candidate+"?ref="+pathEscape(branch), source)
		if result.State != model.Available {
			return result
		}
		if result.Value {
			return result
		}
	}
	return model.Observed[bool]{State: model.Available, Value: false, Source: source}
}

func (s *InventoryService) workflowPinning(ctx context.Context, base, branch string) (model.Observed[bool], model.Observed[string]) {
	var files []struct {
		Name string `json:"name"`
		Type string `json:"type"`
	}
	source := "contents/.github/workflows"
	err := s.client.Get(ctx, base+"/contents/.github/workflows?ref="+pathEscape(branch), &files)
	var apiErr *APIError
	if errors.As(err, &apiErr) && apiErr.StatusCode == 404 {
		return model.Observed[bool]{State: model.Available, Value: true, Source: source, Reason: "no workflows"},
			model.Observed[string]{State: model.Available, Value: "no_actions", Source: source}
	}
	if err != nil {
		state, reason := ErrorState(err)
		return model.Observed[bool]{State: model.Availability(state), Source: source, Reason: reason},
			model.Observed[string]{State: model.Availability(state), Source: source, Reason: reason}
	}
	actionCount, resolvedCount, staleCount := 0, 0, 0
	for _, file := range files {
		if file.Type != "file" || (!strings.HasSuffix(file.Name, ".yml") && !strings.HasSuffix(file.Name, ".yaml")) {
			continue
		}
		var item struct {
			Content  string `json:"content"`
			Encoding string `json:"encoding"`
			Size     int64  `json:"size"`
		}
		if err := s.client.Get(ctx, base+"/contents/.github/workflows/"+pathEscape(file.Name)+"?ref="+pathEscape(branch), &item); err != nil {
			state, reason := ErrorState(err)
			return model.Observed[bool]{State: model.Availability(state), Source: source, Reason: reason},
				model.Observed[string]{State: model.Availability(state), Source: source, Reason: reason}
		}
		if item.Encoding != "base64" || item.Size > 1<<20 {
			return model.Observed[bool]{State: model.Unknown, Source: source, Reason: "workflow content unavailable or too large"},
				model.Observed[string]{State: model.Unknown, Source: source, Reason: "workflow content unavailable or too large"}
		}
		decoded, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(item.Content, "\n", ""))
		if err != nil {
			return model.Observed[bool]{State: model.Unknown, Source: source, Reason: "invalid workflow encoding"},
				model.Observed[string]{State: model.Unknown, Source: source, Reason: "invalid workflow encoding"}
		}
		for _, match := range usesPattern.FindAllSubmatch(decoded, -1) {
			actionCount++
			action, ref := string(match[1]), string(match[2])
			if strings.HasPrefix(action, "./") || strings.HasPrefix(action, "docker://") {
				actionCount--
				continue
			}
			if !fullSHAPattern.MatchString(ref) {
				return model.Observed[bool]{State: model.Available, Value: false, Source: source, Reason: file.Name + " contains a mutable action reference"},
					model.Observed[string]{State: model.Available, Value: "unpinned", Source: source, Reason: file.Name}
			}
			if len(match) > 3 && len(match[3]) > 0 {
				if current, ok := s.resolveActionTag(ctx, action, string(match[3])); ok {
					resolvedCount++
					if !strings.EqualFold(current, ref) {
						staleCount++
					}
				}
			}
		}
	}
	status := "pinned_freshness_unknown"
	switch {
	case actionCount == 0:
		status = "no_actions"
	case staleCount > 0:
		status = "pinned_stale"
	case resolvedCount == actionCount:
		status = "pinned_current"
	}
	return model.Observed[bool]{State: model.Available, Value: true, Source: source},
		model.Observed[string]{State: model.Available, Value: status, Source: source}
}

func (s *InventoryService) resolveActionTag(ctx context.Context, action, tag string) (string, bool) {
	parts := strings.Split(action, "/")
	if len(parts) < 2 {
		return "", false
	}
	base := "/repos/" + pathEscape(parts[0]) + "/" + pathEscape(parts[1])
	var ref struct {
		Object struct {
			Type string `json:"type"`
			SHA  string `json:"sha"`
		} `json:"object"`
	}
	if err := s.client.Get(ctx, base+"/git/ref/tags/"+pathEscape(tag), &ref); err != nil {
		return "", false
	}
	if ref.Object.Type == "commit" {
		return ref.Object.SHA, true
	}
	if ref.Object.Type != "tag" {
		return "", false
	}
	var annotated struct {
		Object struct {
			Type string `json:"type"`
			SHA  string `json:"sha"`
		} `json:"object"`
	}
	if err := s.client.Get(ctx, base+"/git/tags/"+pathEscape(ref.Object.SHA), &annotated); err != nil || annotated.Object.Type != "commit" {
		return "", false
	}
	return annotated.Object.SHA, true
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
	if len(selectors.Visibilities) > 0 && !slices.Contains(selectors.Visibilities, repo.Visibility) {
		return "visibility"
	}
	if len(selectors.IncludeTopics) > 0 && !intersects(repo.Topics, selectors.IncludeTopics) {
		return "required topic missing"
	}
	if intersects(repo.Topics, selectors.ExcludeTopics) {
		return "excluded topic"
	}
	for key, expected := range selectors.CustomProperties {
		if repo.CustomProperties[key] != expected {
			return "custom property " + key
		}
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

func stateFor(err error) model.Availability {
	state, _ := ErrorState(err)
	return model.Availability(state)
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
