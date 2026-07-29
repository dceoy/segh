package merge

import (
	"testing"
	"time"

	"github.com/dceoy/segh/internal/model"
)

func TestScansMergesPartialRuns(t *testing.T) {
	now := time.Now()
	runs := []model.ScanRun{
		{SchemaVersion: 1, ConfigDigest: "same", RunID: "run", StartedAt: now, FinishedAt: now.Add(time.Second),
			Repositories: []model.RepositoryExecution{{Repository: "org/a"}},
			Results:      []model.ScannerResult{{Repository: "org/a", Scanner: "zizmor"}}},
		{SchemaVersion: 1, ConfigDigest: "same", RunID: "run", StartedAt: now, FinishedAt: now.Add(2 * time.Second),
			Repositories: []model.RepositoryExecution{{Repository: "org/b"}},
			Errors:       []model.RunError{{Repository: "org/b", Component: "trivy"}}},
	}
	merged, err := Scans(runs)
	if err != nil {
		t.Fatal(err)
	}
	if merged.Selected != 2 || len(merged.Errors) != 1 || len(merged.Results) != 1 {
		t.Fatalf("unexpected merged run: %#v", merged)
	}
}

func TestScansRejectsDifferentConfig(t *testing.T) {
	_, err := Scans([]model.ScanRun{
		{SchemaVersion: 1, ConfigDigest: "a"},
		{SchemaVersion: 1, ConfigDigest: "b"},
	})
	if err == nil {
		t.Fatal("expected digest mismatch")
	}
}
