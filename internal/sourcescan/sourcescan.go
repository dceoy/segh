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
	"sync"
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

func (p *Planner) Run(ctx context.Context, inventory model.Inventory) (model.SourceScanManifest, model.SourceScanMatrix, error) {
	manifest := model.SourceScanManifest{
		SchemaVersion: model.SourceScanSchemaVersion,
		Organization:  p.cfg.Organization,
		GitHubHost:    p.client.Hostname(),
		GeneratedAt:   p.now().UTC(),
		Enabled:       p.cfg.SourceScan.Enabled,
		Complete:      true,
		Repositories:  []model.SourceScanRepository{},
	}
	matrix := model.SourceScanMatrix{Include: []model.SourceScanMatrixEntry{}}
	if inventory.SchemaVersion != model.SchemaVersion || inventory.Organization != p.cfg.Organization ||
		inventory.GitHubHost == "" || inventory.GitHubHost != p.client.Hostname() {
		return manifest, matrix, fmt.Errorf("inventory identity does not match the configuration")
	}
	if !p.cfg.SourceScan.Enabled {
		return manifest, matrix, nil
	}
	if !inventory.Complete {
		manifest.Complete = false
		manifest.Errors = append(manifest.Errors, model.RunError{
			Component: "source_scan_plan", Kind: "inventory_incomplete",
			Message: "the authoritative repository inventory is incomplete",
		})
	}

	type result struct {
		repository model.SourceScanRepository
		err        error
	}
	jobs := make(chan model.Repository)
	results := make(chan result, len(inventory.Repositories))
	var workers sync.WaitGroup
	for range p.cfg.SourceScan.Concurrency {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for repository := range jobs {
				resolved, err := p.resolve(ctx, repository)
				results <- result{repository: resolved, err: err}
			}
		}()
	}
	go func() {
		defer close(results)
		for _, repository := range inventory.Repositories {
			select {
			case jobs <- repository:
			case <-ctx.Done():
				close(jobs)
				workers.Wait()
				return
			}
		}
		close(jobs)
		workers.Wait()
	}()

	var resolutionErrors []error
	for resolved := range results {
		if resolved.err != nil {
			resolutionErrors = append(resolutionErrors, resolved.err)
			manifest.Complete = false
			manifest.Errors = append(manifest.Errors, model.RunError{
				Repository: resolved.repository.FullName,
				Component:  "source_scan_plan",
				Kind:       "commit_resolution",
				Message:    resolved.err.Error(),
			})
			continue
		}
		manifest.Repositories = append(manifest.Repositories, resolved.repository)
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
	timeoutMinutes := int((time.Duration(p.cfg.SourceScan.Timeout) + time.Minute - 1) / time.Minute)
	matrixRepositories := manifest.Repositories
	if len(matrixRepositories) > maxMatrixTargets {
		manifest.Complete = false
		manifest.Errors = append(manifest.Errors, model.RunError{
			Component: "source_scan_plan", Kind: "matrix_limit",
			Message: fmt.Sprintf("%d selected repositories exceed the bounded matrix limit of %d", len(matrixRepositories), maxMatrixTargets),
		})
		matrixRepositories = matrixRepositories[:maxMatrixTargets]
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
	for _, repository := range matrixRepositories {
		owner, name, _ := strings.Cut(repository.FullName, "/")
		matrix.Include = append(matrix.Include, model.SourceScanMatrixEntry{
			ID: repository.ID, Owner: owner, Repository: name,
			FullName: repository.FullName, Visibility: repository.Visibility,
			DefaultBranch: repository.DefaultBranch, CommitSHA: repository.CommitSHA,
			TimeoutMinutes: timeoutMinutes, Concurrency: p.cfg.SourceScan.Concurrency,
		})
	}
	if !manifest.Complete {
		return manifest, matrix, errors.Join(
			fmt.Errorf("source scan planning coverage is incomplete"),
			errors.Join(resolutionErrors...),
		)
	}
	return manifest, matrix, nil
}

func (p *Planner) resolve(ctx context.Context, repository model.Repository) (model.SourceScanRepository, error) {
	selected := model.SourceScanRepository{
		ID: repository.ID, FullName: repository.FullName, Visibility: repository.Visibility,
		DefaultBranch: repository.DefaultBranch, SelectionReason: "selected by inventory selectors",
	}
	owner, name, ok := strings.Cut(repository.FullName, "/")
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
	expectedNames := make(map[string]bool, len(manifest.Repositories))
	for _, repository := range manifest.Repositories {
		if repository.ID <= 0 || expected[repository.ID].ID != 0 || expectedNames[repository.FullName] ||
			repository.FullName == "" || repository.DefaultBranch == "" || !isFullSHA(repository.CommitSHA) {
			return summary, fmt.Errorf("scan manifest contains an invalid or duplicate repository identity")
		}
		expected[repository.ID] = repository
		expectedNames[repository.FullName] = true
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
		status.Repository != repository.FullName || status.Visibility != repository.Visibility ||
		status.DefaultBranch != repository.DefaultBranch || status.CommitSHA != repository.CommitSHA ||
		!isFullSHA(status.CommitSHA) || len(status.Scanners) != 7 {
		return false
	}
	allowedResults := map[string]bool{"pass": true, "findings": true, "incomplete": true, "error": true}
	if !allowedResults[status.Result] {
		return false
	}
	expectedNames := map[string]bool{
		"content-validation": true, "zizmor": true, "actionlint": true,
		"shellcheck": true, "checkov": true, "trivy-vulnerability": true, "trivy-secret": true,
	}
	names := map[string]bool{}
	overall := "pass"
	for _, scanner := range status.Scanners {
		if scanner.Name == "" || scanner.Version == "" || scanner.ExitStatus < 0 || scanner.FindingCount < 0 ||
			!expectedNames[scanner.Name] || names[scanner.Name] ||
			!map[string]bool{"pass": true, "skipped": true, "findings": true, "incomplete": true, "error": true}[scanner.Result] {
			return false
		}
		names[scanner.Name] = true
		switch scanner.Result {
		case "pass", "skipped":
			if scanner.ExitStatus != 0 {
				return false
			}
		case "findings":
			if scanner.ExitStatus == 0 || scanner.FindingCount == 0 {
				return false
			}
			if overall == "pass" {
				overall = "findings"
			}
		case "incomplete":
			if scanner.ExitStatus == 0 {
				return false
			}
			if overall != "error" {
				overall = "incomplete"
			}
		case "error":
			if scanner.ExitStatus == 0 {
				return false
			}
			overall = "error"
		}
	}
	return status.Result == overall
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
