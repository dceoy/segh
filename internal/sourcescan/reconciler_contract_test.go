package sourcescan

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/dceoy/segh/internal/model"
)

func TestReconcilerDeterministicallyBoundsMissingEvidenceOutput(t *testing.T) {
	const repositoryCount = 52
	repositories := make([]model.SourceScanRepository, 0, repositoryCount)
	for index := 0; index < repositoryCount; index++ {
		name := fmt.Sprintf("repo-%03d", index)
		repositories = append(repositories, model.SourceScanRepository{
			ID:            int64(index + 1),
			Owner:         "example",
			Name:          name,
			FullName:      "example/" + name,
			DefaultBranch: "main",
			CommitSHA:     fmt.Sprintf("%040x", index+1),
			Scheduled:     true,
		})
	}
	manifest := model.SourceScanManifest{
		SchemaVersion: model.SourceScanSchemaVersion,
		Organization:  "example",
		Complete:      true,
		Repositories:  repositories,
	}

	summary, err := Summarize(manifest, t.TempDir(), time.Unix(20, 0))
	if err != nil {
		t.Fatal(err)
	}
	wantCounts := model.SourceScanCounts{Selected: repositoryCount, Incomplete: repositoryCount}
	if summary.Complete || summary.Counts != wantCounts {
		t.Fatalf("summary complete=%v counts=%#v, want incomplete counts %#v", summary.Complete, summary.Counts, wantCounts)
	}
	if len(summary.Errors) != repositoryCount {
		t.Fatalf("errors = %d, want %d", len(summary.Errors), repositoryCount)
	}
	for index, runErr := range summary.Errors {
		wantRepository := fmt.Sprintf("example/repo-%03d", index)
		if runErr.Repository != wantRepository || runErr.Kind != "missing_status" {
			t.Fatalf("error %d = %#v, want repository %q missing_status", index, runErr, wantRepository)
		}
	}

	markdown := Markdown(summary)
	if got := strings.Count(markdown, "`: missing_status\n"); got != 50 {
		t.Fatalf("rendered missing-status entries = %d, want 50\n%s", got, markdown)
	}
	if !strings.Contains(markdown, "`example/repo-049`: missing_status") ||
		strings.Contains(markdown, "`example/repo-050`: missing_status") ||
		!strings.Contains(markdown, "Additional errors are retained in `scan-summary.json`.") {
		t.Fatalf("bounded markdown output is not deterministic:\n%s", markdown)
	}
}
