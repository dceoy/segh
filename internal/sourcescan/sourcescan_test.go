package sourcescan

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
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

func TestPlannerResolvesSortsAndSchedulesImmutableCommits(t *testing.T) {
	cfg := config.Default()
	cfg.Organization = "example"
	cfg.SourceScan.Enabled = true
	cfg.SourceScan.Concurrency = 2
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
	manifest, err := planner.Run(context.Background(), inventory)
	if err != nil {
		t.Fatal(err)
	}
	repeated, err := planner.Run(context.Background(), inventory)
	if err != nil || !reflect.DeepEqual(manifest, repeated) {
		t.Fatalf("repeated manifest=%#v err=%v, first=%#v", repeated, err, manifest)
	}
	if !manifest.Complete || manifest.Concurrency != 2 ||
		manifest.GeneratedAt != time.Unix(10, 0).UTC() {
		t.Fatalf("manifest = %#v", manifest)
	}
	alpha := manifest.Repositories[0]
	if alpha.FullName != "example/alpha" || alpha.Owner != "example" || alpha.Name != "alpha" ||
		alpha.CommitSHA != strings.Repeat("a", 40) || !alpha.Scheduled {
		t.Fatalf("first repository = %#v", alpha)
	}
}

func TestPlannerPreservesFailedCommitResolutionAsIncompleteSelection(t *testing.T) {
	cfg := config.Default()
	cfg.Organization = "example"
	cfg.SourceScan.Enabled = true
	client := fakeAPI{commits: map[string]string{
		"/repos/example/good/commits/main": strings.Repeat("a", 40),
	}}
	manifest, err := NewPlanner(cfg, client).Run(context.Background(), model.Inventory{
		SchemaVersion: model.SchemaVersion, Organization: "example", GitHubHost: "github.com", Complete: true,
		Repositories: []model.Repository{
			{ID: 1, FullName: "example/good", DefaultBranch: "main"},
			{ID: 2, FullName: "example/missing", DefaultBranch: "main"},
		},
	})
	if err == nil || manifest.Complete || len(manifest.Repositories) != 2 || len(manifest.Errors) != 1 {
		t.Fatalf("manifest=%#v err=%v", manifest, err)
	}
	missing := manifest.Repositories[1]
	if missing.FullName != "example/missing" || missing.CommitSHA != "" || missing.Scheduled {
		t.Fatalf("failed selection = %#v", missing)
	}

	dir := t.TempDir()
	writeJSON(t, filepath.Join(dir, "repository-scan-1", "status.json"), validStatus(manifest.Repositories[0], "pass"))
	summary, summarizeErr := Summarize(manifest, dir, time.Unix(20, 0))
	if summarizeErr != nil {
		t.Fatal(summarizeErr)
	}
	want := model.SourceScanCounts{Selected: 2, Scanned: 1, Passed: 1, Incomplete: 1}
	if summary.Counts != want || summary.Complete {
		t.Fatalf("summary = %#v, want counts %#v", summary, want)
	}
}

func TestDisabledPlannerMakesExplicitEmptyManifest(t *testing.T) {
	cfg := config.Default()
	cfg.Organization = "example"
	manifest, err := NewPlanner(cfg, fakeAPI{}).Run(context.Background(), model.Inventory{
		SchemaVersion: model.SchemaVersion, Organization: "example", GitHubHost: "github.com",
	})
	if err != nil || manifest.Enabled || !manifest.Complete || len(manifest.Repositories) != 0 {
		t.Fatalf("manifest=%#v err=%v", manifest, err)
	}
}

func TestPlannerMarksMismatchedInventoryIdentityIncomplete(t *testing.T) {
	cfg := config.Default()
	cfg.Organization = "example"
	cfg.SourceScan.Enabled = true
	manifest, err := NewPlanner(cfg, fakeAPI{}).Run(context.Background(), model.Inventory{
		SchemaVersion: model.SchemaVersion, Organization: "other-org", GitHubHost: "github.com", Complete: true,
	})
	if err == nil || manifest.Complete || len(manifest.Repositories) != 0 ||
		len(manifest.Errors) != 1 || manifest.Errors[0].Kind != "invalid_inventory" {
		t.Fatalf("manifest = %#v err = %v", manifest, err)
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
	manifest, err := NewPlanner(cfg, client).Run(context.Background(), inventory)
	scheduled := 0
	for _, repository := range manifest.Repositories {
		if repository.Scheduled {
			scheduled++
		}
	}
	if err == nil || manifest.Complete || len(manifest.Repositories) != maxMatrixTargets+1 ||
		scheduled != maxMatrixTargets || manifest.Errors[0].Kind != "matrix_limit" {
		t.Fatalf("manifest complete=%v repositories=%d scheduled=%d errors=%#v err=%v", manifest.Complete, len(manifest.Repositories), scheduled, manifest.Errors, err)
	}
}

func TestSummaryDistinguishesFindingsMissingAndRuntimeResults(t *testing.T) {
	repositories := []model.SourceScanRepository{
		resolvedRepository(1, "findings", "a"),
		resolvedRepository(2, "missing", "b"),
	}
	manifest := model.SourceScanManifest{
		SchemaVersion: model.SourceScanSchemaVersion, Organization: "example", Complete: true,
		Repositories: repositories,
	}
	dir := t.TempDir()
	writeJSON(t, filepath.Join(dir, "repository-scan-1", "status.json"), validStatus(repositories[0], "findings"))
	summary, err := Summarize(manifest, dir, time.Unix(20, 0))
	if err != nil {
		t.Fatal(err)
	}
	if summary.Complete || summary.Counts != (model.SourceScanCounts{Selected: 2, Scanned: 1, Findings: 1, Incomplete: 1}) {
		t.Fatalf("summary = %#v", summary)
	}
	if !strings.Contains(Markdown(summary), "| 2 | 1 | 0 | 1 | 1 | 0 |") {
		t.Fatalf("markdown = %q", Markdown(summary))
	}
}

// TestSummaryParsesLiteralUpstreamStatusJSON writes the exact bytes
// dceoy/gha-for-devops's repository-security-scan composite action's
// record_status() produces (see its scan.sh), rather than round-tripping
// through this package's own upstreamStatus type, so a drift between the
// two schemas would show up as a real parsing failure here.
func TestSummaryParsesLiteralUpstreamStatusJSON(t *testing.T) {
	repository := resolvedRepository(7, "literal", "c")
	manifest := model.SourceScanManifest{
		SchemaVersion: model.SourceScanSchemaVersion, Organization: "example", Complete: true,
		Repositories: []model.SourceScanRepository{repository},
	}
	dir := t.TempDir()
	statusPath := filepath.Join(dir, "repository-scan-7", "status.json")
	if err := os.MkdirAll(filepath.Dir(statusPath), 0o700); err != nil {
		t.Fatal(err)
	}
	literal := `{"result":"pass","repository-id":"7","repository":"example/literal","default-branch":"main","commit-sha":"` +
		repository.CommitSHA + `"}` + "\n"
	if err := os.WriteFile(statusPath, []byte(literal), 0o600); err != nil {
		t.Fatal(err)
	}
	summary, err := Summarize(manifest, dir, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if summary.Counts != (model.SourceScanCounts{Selected: 1, Scanned: 1, Passed: 1}) || !summary.Complete {
		t.Fatalf("summary = %#v", summary)
	}
}

func TestSummaryRejectsInvalidDuplicateAndMismatchedStatusEvidence(t *testing.T) {
	repository := resolvedRepository(1, "repo", "a")
	manifest := model.SourceScanManifest{SchemaVersion: 1, Organization: "example", Complete: true, Repositories: []model.SourceScanRepository{repository}}
	for _, test := range []struct {
		name      string
		mutate    func(*upstreamStatus)
		malformed bool
		duplicate bool
	}{
		{"repository ID", func(status *upstreamStatus) { status.RepositoryID = "2" }, false, false},
		{"repository name", func(status *upstreamStatus) { status.Repository = "example/other" }, false, false},
		{"default branch", func(status *upstreamStatus) { status.DefaultBranch = "release" }, false, false},
		{"commit SHA", func(status *upstreamStatus) { status.CommitSHA = strings.Repeat("b", 40) }, false, false},
		{"unsupported result", func(status *upstreamStatus) { status.Result = "success" }, false, false},
		{"malformed JSON", nil, true, false},
		{"duplicate status", nil, false, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			statusPath := filepath.Join(dir, "repository-scan-1", "status.json")
			if test.malformed {
				if err := os.MkdirAll(filepath.Dir(statusPath), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(statusPath, []byte("{"), 0o600); err != nil {
					t.Fatal(err)
				}
			} else {
				status := validStatus(repository, "pass")
				if test.mutate != nil {
					test.mutate(&status)
				}
				writeJSON(t, statusPath, status)
				if test.duplicate {
					writeJSON(t, filepath.Join(dir, "duplicate", "status.json"), status)
				}
			}
			summary, err := Summarize(manifest, dir, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			if summary.Complete || summary.Counts.Errors != 1 {
				t.Fatalf("summary = %#v", summary)
			}
		})
	}
}

func TestSummaryMarksInvalidManifestIncomplete(t *testing.T) {
	repositories := []model.SourceScanRepository{
		resolvedRepository(1, "dup", "a"),
		resolvedRepository(1, "dup", "a"),
	}
	manifest := model.SourceScanManifest{
		SchemaVersion: model.SourceScanSchemaVersion, Organization: "example", Complete: true,
		Repositories: repositories,
	}
	summary, err := Summarize(manifest, t.TempDir(), time.Now())
	if err == nil || summary.Complete || summary.Counts.Errors != 1 || len(summary.Errors) != 1 || summary.Errors[0].Kind != "invalid_manifest" {
		t.Fatalf("summary = %#v err = %v", summary, err)
	}
	if strings.Contains(Markdown(summary), "**complete**") {
		t.Fatalf("markdown reports complete despite invalid manifest: %q", Markdown(summary))
	}
}

func resolvedRepository(id int64, name, sha string) model.SourceScanRepository {
	return model.SourceScanRepository{
		ID: id, Owner: "example", Name: name, FullName: "example/" + name,
		DefaultBranch: "main", CommitSHA: strings.Repeat(sha, 40), Scheduled: true,
	}
}

// validStatus mirrors the exact status.json shape dceoy/gha-for-devops's
// repository-security-scan composite action writes: hyphenated keys, a
// string repository-id, and no schema version field.
func validStatus(repository model.SourceScanRepository, result string) upstreamStatus {
	return upstreamStatus{
		Result: result, RepositoryID: strconv.FormatInt(repository.ID, 10), Repository: repository.FullName,
		DefaultBranch: repository.DefaultBranch, CommitSHA: repository.CommitSHA,
	}
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
