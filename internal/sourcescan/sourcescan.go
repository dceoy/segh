package sourcescan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/dceoy/segh/internal/config"
	gh "github.com/dceoy/segh/internal/github"
	"github.com/dceoy/segh/internal/model"
)

const (
	maxEvidenceBytes = 64 << 20
	maxMatrixTargets = 256
)

type Planner struct {
	cfg    config.Config
	client gh.API
	now    func() time.Time
}

func NewPlanner(cfg config.Config, client gh.API) *Planner {
	return &Planner{cfg: cfg, client: client, now: time.Now}
}

func (p *Planner) Run(ctx context.Context, inventory model.Inventory) (model.SourceScanManifest, error) {
	manifest := model.SourceScanManifest{
		SchemaVersion:  model.SourceScanSchemaVersion,
		Organization:   p.cfg.Organization,
		GitHubHost:     p.client.Hostname(),
		GeneratedAt:    p.now().UTC(),
		Enabled:        p.cfg.SourceScan.Enabled,
		Complete:       true,
		Concurrency:    p.cfg.SourceScan.Concurrency,
		TimeoutMinutes: int((time.Duration(p.cfg.SourceScan.Timeout) + time.Minute - 1) / time.Minute),
		Repositories:   []model.SourceScanRepository{},
	}
	if inventory.SchemaVersion != model.SchemaVersion || inventory.Organization != p.cfg.Organization ||
		inventory.GitHubHost == "" || inventory.GitHubHost != p.client.Hostname() {
		return manifest, fmt.Errorf("inventory identity does not match the configuration")
	}
	if !p.cfg.SourceScan.Enabled {
		return manifest, nil
	}
	if !inventory.Complete {
		manifest.Complete = false
		manifest.Errors = append(manifest.Errors, model.RunError{
			Component: "source_scan_plan", Kind: "inventory_incomplete",
			Message: "the authoritative repository inventory is incomplete",
		})
	}

	var resolutionErrors []error
	for _, repository := range inventory.Repositories {
		resolved, err := p.resolve(ctx, repository)
		manifest.Repositories = append(manifest.Repositories, resolved)
		if err != nil {
			resolutionErrors = append(resolutionErrors, err)
			manifest.Complete = false
			manifest.Errors = append(manifest.Errors, model.RunError{
				Repository: resolved.FullName,
				Component:  "source_scan_plan",
				Kind:       "commit_resolution",
				Message:    err.Error(),
			})
		}
	}
	if ctx.Err() != nil {
		manifest.Complete = false
		manifest.Errors = append(manifest.Errors, model.RunError{
			Component: "source_scan_plan", Kind: "timeout", Message: ctx.Err().Error(),
		})
	}
	sort.Slice(manifest.Repositories, func(i, j int) bool {
		return manifest.Repositories[i].FullName < manifest.Repositories[j].FullName
	})
	sort.Slice(manifest.Errors, func(i, j int) bool {
		left, right := manifest.Errors[i], manifest.Errors[j]
		if left.Repository != right.Repository {
			return left.Repository < right.Repository
		}
		if left.Kind != right.Kind {
			return left.Kind < right.Kind
		}
		return left.Message < right.Message
	})
	resolvedRepositories := 0
	for index := range manifest.Repositories {
		if manifest.Repositories[index].CommitSHA == "" {
			continue
		}
		resolvedRepositories++
		if resolvedRepositories <= maxMatrixTargets {
			manifest.Repositories[index].Scheduled = true
		}
	}
	if resolvedRepositories > maxMatrixTargets {
		manifest.Complete = false
		manifest.Errors = append(manifest.Errors, model.RunError{
			Component: "source_scan_plan", Kind: "matrix_limit",
			Message: fmt.Sprintf("%d resolved repositories exceed the bounded matrix limit of %d", resolvedRepositories, maxMatrixTargets),
		})
		sort.Slice(manifest.Errors, func(i, j int) bool {
			left, right := manifest.Errors[i], manifest.Errors[j]
			if left.Repository != right.Repository {
				return left.Repository < right.Repository
			}
			if left.Kind != right.Kind {
				return left.Kind < right.Kind
			}
			return left.Message < right.Message
		})
	}
	if !manifest.Complete {
		return manifest, errors.Join(
			fmt.Errorf("source scan planning coverage is incomplete"),
			errors.Join(resolutionErrors...),
		)
	}
	return manifest, nil
}

func (p *Planner) resolve(ctx context.Context, repository model.Repository) (model.SourceScanRepository, error) {
	selected := model.SourceScanRepository{
		ID: repository.ID, FullName: repository.FullName, Visibility: repository.Visibility,
		DefaultBranch: repository.DefaultBranch,
	}
	owner, name, ok := strings.Cut(repository.FullName, "/")
	selected.Owner = owner
	selected.Name = name
	if !ok || owner == "" || name == "" || strings.Contains(name, "/") {
		return selected, fmt.Errorf("repository full name is invalid")
	}
	if repository.ID <= 0 || repository.DefaultBranch == "" {
		return selected, fmt.Errorf("repository identity or default branch is missing")
	}
	var commit struct {
		SHA string `json:"sha"`
	}
	apiPath := "/repos/" + url.PathEscape(owner) + "/" + url.PathEscape(name) +
		"/commits/" + url.PathEscape(repository.DefaultBranch)
	if err := p.client.Get(ctx, apiPath, &commit); err != nil {
		return selected, fmt.Errorf("resolve default-branch commit: %w", err)
	}
	if !isFullSHA(commit.SHA) {
		return selected, fmt.Errorf("resolved commit is not a full lowercase SHA")
	}
	selected.CommitSHA = commit.SHA
	return selected, nil
}

func Summarize(manifest model.SourceScanManifest, resultsDirectory string, now time.Time) (model.SourceScanSummary, error) {
	summary := model.SourceScanSummary{
		SchemaVersion: model.SourceScanSchemaVersion,
		Organization:  manifest.Organization, GeneratedAt: now.UTC(), Complete: manifest.Complete,
		Counts:       model.SourceScanCounts{Selected: len(manifest.Repositories)},
		Repositories: []model.RepositoryScanStatus{}, Errors: append([]model.RunError(nil), manifest.Errors...),
	}
	if manifest.SchemaVersion != model.SourceScanSchemaVersion || manifest.Organization == "" {
		return summary, fmt.Errorf("scan manifest identity is invalid")
	}
	expected := make(map[int64]model.SourceScanRepository, len(manifest.Repositories))
	selectedIDs := make(map[int64]bool, len(manifest.Repositories))
	expectedNames := make(map[string]bool, len(manifest.Repositories))
	for _, repository := range manifest.Repositories {
		if repository.ID <= 0 || selectedIDs[repository.ID] || expectedNames[repository.FullName] ||
			repository.Owner == "" || repository.Name == "" ||
			repository.FullName != repository.Owner+"/"+repository.Name || repository.DefaultBranch == "" ||
			(repository.Scheduled && !isFullSHA(repository.CommitSHA)) ||
			(!repository.Scheduled && repository.CommitSHA != "" && !isFullSHA(repository.CommitSHA)) {
			return summary, fmt.Errorf("scan manifest contains an invalid or duplicate repository identity")
		}
		selectedIDs[repository.ID] = true
		expectedNames[repository.FullName] = true
		if repository.Scheduled {
			expected[repository.ID] = repository
		} else {
			summary.Counts.Incomplete++
			summary.Complete = false
		}
	}
	seen := make(map[int64]bool, len(expected))
	err := filepath.WalkDir(resultsDirectory, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || entry.Name() != "status.json" {
			return nil
		}
		var status model.RepositoryScanStatus
		if err := ReadJSON(path, &status); err != nil {
			summary.Complete = false
			summary.Counts.Errors++
			summary.Errors = append(summary.Errors, model.RunError{Component: "source_scan_summary", Kind: "invalid_status", Message: err.Error()})
			return nil //nolint:nilerr // The malformed status is retained as an aggregate runtime error.
		}
		repository, ok := expected[status.RepositoryID]
		if !ok || seen[status.RepositoryID] || !statusMatches(status, repository) {
			summary.Complete = false
			summary.Counts.Errors++
			summary.Errors = append(summary.Errors, model.RunError{Repository: status.Repository, Component: "source_scan_summary", Kind: "identity_mismatch", Message: "repository status does not uniquely match the scan manifest"})
			return nil
		}
		seen[status.RepositoryID] = true
		summary.Repositories = append(summary.Repositories, status)
		summary.Counts.Scanned++
		switch status.Result {
		case "pass":
			summary.Counts.Passed++
		case "findings":
			summary.Counts.Findings++
		case "incomplete":
			summary.Counts.Incomplete++
			summary.Complete = false
		default:
			summary.Counts.Errors++
			summary.Complete = false
		}
		return nil
	})
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return summary, fmt.Errorf("read repository scan evidence: %w", err)
	}
	for id, repository := range expected {
		if seen[id] {
			continue
		}
		summary.Complete = false
		summary.Counts.Incomplete++
		summary.Errors = append(summary.Errors, model.RunError{Repository: repository.FullName, Component: "source_scan_summary", Kind: "missing_status", Message: "repository scan did not produce status evidence"})
	}
	sort.Slice(summary.Repositories, func(i, j int) bool { return summary.Repositories[i].Repository < summary.Repositories[j].Repository })
	sort.Slice(summary.Errors, func(i, j int) bool {
		left, right := summary.Errors[i], summary.Errors[j]
		if left.Repository != right.Repository {
			return left.Repository < right.Repository
		}
		if left.Kind != right.Kind {
			return left.Kind < right.Kind
		}
		return left.Message < right.Message
	})
	return summary, nil
}

func Markdown(summary model.SourceScanSummary) string {
	var builder strings.Builder
	builder.WriteString("# Organization source scan\n\n")
	builder.WriteString("Coverage: **")
	if summary.Complete {
		builder.WriteString("complete")
	} else {
		builder.WriteString("incomplete")
	}
	builder.WriteString("**\n\n")
	builder.WriteString("| Selected | Scanned | Passed | Findings | Incomplete | Errors |\n")
	builder.WriteString("| ---: | ---: | ---: | ---: | ---: | ---: |\n")
	counts := summary.Counts
	builder.WriteString("| " + strconv.Itoa(counts.Selected) + " | " + strconv.Itoa(counts.Scanned) +
		" | " + strconv.Itoa(counts.Passed) + " | " + strconv.Itoa(counts.Findings) +
		" | " + strconv.Itoa(counts.Incomplete) + " | " + strconv.Itoa(counts.Errors) + " |\n")
	if len(summary.Errors) > 0 {
		builder.WriteString("\n## Coverage and runtime errors\n\n")
		limit := min(50, len(summary.Errors))
		for _, runErr := range summary.Errors[:limit] {
			label := runErr.Repository
			if label == "" {
				label = runErr.Component
			}
			builder.WriteString("- `" + strings.ReplaceAll(label, "`", "") + "`: " +
				strings.ReplaceAll(runErr.Kind, "`", "") + "\n")
		}
		if len(summary.Errors) > limit {
			builder.WriteString("- Additional errors are retained in `scan-summary.json`.\n")
		}
	}
	return builder.String()
}

func ReadJSON(path string, value any) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() > maxEvidenceBytes {
		return fmt.Errorf("evidence file must be regular and no larger than %d bytes", maxEvidenceBytes)
	}
	file, err := os.Open(path) // #nosec G304 -- the CLI operator explicitly selects the evidence path.
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	decoder := json.NewDecoder(io.LimitReader(file, maxEvidenceBytes+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("multiple JSON values are not allowed")
		}
		return err
	}
	return nil
}

func statusMatches(status model.RepositoryScanStatus, repository model.SourceScanRepository) bool {
	if status.SchemaVersion != model.SourceScanSchemaVersion || status.RepositoryID != repository.ID ||
		status.Repository != repository.FullName || status.DefaultBranch != repository.DefaultBranch ||
		status.CommitSHA != repository.CommitSHA || !isFullSHA(status.CommitSHA) {
		return false
	}
	return map[string]bool{"pass": true, "findings": true, "incomplete": true, "error": true}[status.Result]
}

func isFullSHA(value string) bool {
	if len(value) != 40 {
		return false
	}
	for _, char := range value {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return false
		}
	}
	return true
}
