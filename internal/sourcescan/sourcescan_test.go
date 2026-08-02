package sourcescan

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/dceoy/segh/internal/config"
	"github.com/dceoy/segh/internal/model"
)

type fakeAPI struct {
	commits map[string]string
	errors  map[string]error
}

func (fakeAPI) Hostname() string { return "github.com" }

func (f fakeAPI) Get(_ context.Context, path string, out any) error {
	if err := f.errors[path]; err != nil {
		return err
	}
	data, ok := f.commits[path]
	if !ok {
		return os.ErrNotExist
	}
	return json.Unmarshal([]byte(`{"sha":"`+data+`"}`), out)
}

func TestPlannerResolvesAndSortsImmutableCommits(t *testing.T) {
	cfg := config.Default()
	cfg.Organization = "example"
	cfg.SourceScan.Enabled = true
	cfg.SourceScan.Concurrency = 2
	cfg.SourceScan.Timeout = config.Duration(91 * time.Second)
	client := fakeAPI{commits: map[string]string{
		"/repos/example/zeta/commits/main":     strings.Repeat("b", 40),
		"/repos/example/alpha/commits/release": strings.Repeat("a", 40),
	}}
	planner := NewPlanner(cfg, client)
	planner.now = func() time.Time { return time.Unix(10, 0) }
	inventory := model.Inventory{
		SchemaVersion: model.SchemaVersion, Organization: "example", GitHubHost: "github.com", Complete: true,
		Repositories: []model.Repository{
			{ID: 2, FullName: "example/zeta", Visibility: "private", DefaultBranch: "main"},
			{ID: 1, FullName: "example/alpha", Visibility: "public", DefaultBranch: "release"},
		},
	}
	manifest, matrix, err := planner.Run(context.Background(), inventory)
	if err != nil {
		t.Fatal(err)
	}
	if !manifest.Complete || len(manifest.Errors) != 0 || manifest.GeneratedAt != time.Unix(10, 0).UTC() {
		t.Fatalf("manifest = %#v", manifest)
	}
	wantNames := []string{"example/alpha", "example/zeta"}
	gotNames := []string{manifest.Repositories[0].FullName, manifest.Repositories[1].FullName}
	if !reflect.DeepEqual(gotNames, wantNames) {
		t.Fatalf("repository order = %v, want %v", gotNames, wantNames)
	}
	if matrix.Include[0].CommitSHA != strings.Repeat("a", 40) || matrix.Include[0].TimeoutMinutes != 2 ||
		matrix.Include[0].Concurrency != 2 || matrix.Include[0].Owner != "example" || matrix.Include[0].Repository != "alpha" {
		t.Fatalf("matrix = %#v", matrix)
	}
}

func TestPlannerKeepsResolvedRepositoriesWhenCoverageIsIncomplete(t *testing.T) {
	cfg := config.Default()
	cfg.Organization = "example"
	cfg.SourceScan.Enabled = true
	client := fakeAPI{commits: map[string]string{
		"/repos/example/good/commits/main": strings.Repeat("a", 40),
	}}
	inventory := model.Inventory{
		SchemaVersion: model.SchemaVersion, Organization: "example", GitHubHost: "github.com", Complete: false,
		Repositories: []model.Repository{
			{ID: 1, FullName: "example/good", DefaultBranch: "main"},
			{ID: 2, FullName: "example/missing", DefaultBranch: "main"},
		},
	}
	manifest, matrix, err := NewPlanner(cfg, client).Run(context.Background(), inventory)
	if err == nil || manifest.Complete || len(matrix.Include) != 1 || len(manifest.Errors) != 2 {
		t.Fatalf("manifest=%#v matrix=%#v err=%v", manifest, matrix, err)
	}
}

func TestDisabledPlannerMakesExplicitEmptyManifest(t *testing.T) {
	cfg := config.Default()
	cfg.Organization = "example"
	manifest, matrix, err := NewPlanner(cfg, fakeAPI{}).Run(context.Background(), model.Inventory{
		SchemaVersion: model.SchemaVersion, Organization: "example", GitHubHost: "github.com",
	})
	if err != nil || manifest.Enabled || !manifest.Complete || len(matrix.Include) != 0 {
		t.Fatalf("manifest=%#v matrix=%#v err=%v", manifest, matrix, err)
	}
}

func TestPlannerFailsClosedAtGitHubMatrixLimit(t *testing.T) {
	cfg := config.Default()
	cfg.Organization = "example"
	cfg.SourceScan.Enabled = true
	client := fakeAPI{commits: map[string]string{}}
	inventory := model.Inventory{SchemaVersion: model.SchemaVersion, Organization: "example", GitHubHost: "github.com", Complete: true}
	for index := 0; index < maxMatrixTargets+1; index++ {
		name := fmt.Sprintf("repo-%03d", index)
		fullName := "example/" + name
		inventory.Repositories = append(inventory.Repositories, model.Repository{ID: int64(index + 1), FullName: fullName, DefaultBranch: "main"})
		client.commits["/repos/example/"+name+"/commits/main"] = fmt.Sprintf("%040x", index+1)
	}
	manifest, matrix, err := NewPlanner(cfg, client).Run(context.Background(), inventory)
	if err == nil || manifest.Complete || len(manifest.Repositories) != maxMatrixTargets+1 ||
		len(matrix.Include) != maxMatrixTargets || manifest.Errors[0].Kind != "matrix_limit" {
		t.Fatalf("manifest complete=%v repositories=%d errors=%#v matrix=%d err=%v", manifest.Complete, len(manifest.Repositories), manifest.Errors, len(matrix.Include), err)
	}
}

func TestSummaryDistinguishesFindingsMissingAndRuntimeResults(t *testing.T) {
	manifest := model.SourceScanManifest{
		SchemaVersion: model.SourceScanSchemaVersion, Organization: "example", Complete: true,
		Repositories: []model.SourceScanRepository{
			{ID: 1, FullName: "example/findings", Visibility: "private", DefaultBranch: "main", CommitSHA: strings.Repeat("a", 40)},
			{ID: 2, FullName: "example/missing", Visibility: "private", DefaultBranch: "main", CommitSHA: strings.Repeat("b", 40)},
		},
	}
	dir := t.TempDir()
	status := validStatus(manifest.Repositories[0], "findings")
	writeJSON(t, filepath.Join(dir, "repository-scan-1", "status.json"), status)
	summary, err := Summarize(manifest, dir, time.Unix(20, 0))
	if err != nil {
		t.Fatal(err)
	}
	if summary.Complete || summary.Counts != (model.SourceScanCounts{Selected: 2, Scanned: 1, Findings: 1, Incomplete: 1}) || len(summary.Errors) != 1 {
		t.Fatalf("summary = %#v", summary)
	}
	if !strings.Contains(Markdown(summary), "| 2 | 1 | 0 | 1 | 1 | 0 |") {
		t.Fatalf("markdown = %q", Markdown(summary))
	}
}

func TestSummaryRejectsMismatchedOrMalformedStatusEvidence(t *testing.T) {
	repository := model.SourceScanRepository{ID: 1, FullName: "example/repo", Visibility: "private", DefaultBranch: "main", CommitSHA: strings.Repeat("a", 40)}
	manifest := model.SourceScanManifest{SchemaVersion: 1, Organization: "example", Complete: true, Repositories: []model.SourceScanRepository{repository}}
	for _, test := range []struct {
		name   string
		mutate func(*model.RepositoryScanStatus)
	}{
		{"commit", func(status *model.RepositoryScanStatus) { status.CommitSHA = strings.Repeat("b", 40) }},
		{"scanner", func(status *model.RepositoryScanStatus) { status.Scanners[0].Name = "unknown" }},
		{"result", func(status *model.RepositoryScanStatus) { status.Result = "success" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			status := validStatus(repository, "pass")
			test.mutate(&status)
			writeJSON(t, filepath.Join(dir, "status.json"), status)
			summary, err := Summarize(manifest, dir, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			if summary.Complete || summary.Counts.Errors != 1 || summary.Counts.Incomplete != 1 {
				t.Fatalf("summary = %#v", summary)
			}
		})
	}
}

func validStatus(repository model.SourceScanRepository, result string) model.RepositoryScanStatus {
	names := []string{"content-validation", "zizmor", "actionlint", "shellcheck", "checkov", "trivy-vulnerability", "trivy-secret"}
	status := model.RepositoryScanStatus{
		SchemaVersion: 1, RepositoryID: repository.ID, Repository: repository.FullName,
		Visibility: repository.Visibility, DefaultBranch: repository.DefaultBranch,
		CommitSHA: repository.CommitSHA, Result: result,
	}
	for _, name := range names {
		status.Scanners = append(status.Scanners, model.SourceScannerStatus{Name: name, Version: "1.0", Result: "pass"})
	}
	switch result {
	case "findings":
		status.Scanners[1].Result = "findings"
		status.Scanners[1].ExitStatus = 1
		status.Scanners[1].FindingCount = 1
	case "incomplete":
		status.Scanners[0].Result = "incomplete"
		status.Scanners[0].ExitStatus = 1
	case "error":
		status.Scanners[1].Result = "error"
		status.Scanners[1].ExitStatus = 2
	}
	return status
}

func writeJSON(t *testing.T, path string, value any) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
