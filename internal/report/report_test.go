package report

import (
	"strings"
	"testing"

	"github.com/dceoy/segh/internal/model"
)

func TestBuildMarksPartialCoverage(t *testing.T) {
	inventory := &model.Inventory{Selected: 2, Complete: true}
	audit := &model.Audit{Counts: map[string]int{"unknown": 1}}
	scan := &model.ScanRun{Results: []model.ScannerResult{{Status: model.ScannerFailed}}}
	result := Build(inventory, audit, scan, []model.Publication{{Status: model.PublicationUnsupported}}, -1, -1, 0)
	AddTrend(&result, model.ScanRun{Results: []model.ScannerResult{{Findings: 3}}})
	if result.Summary.Coverage != "partial" || result.Summary.Repositories != 2 {
		t.Fatalf("summary = %#v", result.Summary)
	}
	markdown := Markdown(result)
	if !strings.Contains(markdown, "Coverage: partial") || !strings.Contains(markdown, "unsupported=1") {
		t.Fatalf("markdown = %s", markdown)
	}
	if result.Trend == nil || result.Trend.Delta != -3 {
		t.Fatalf("trend = %#v", result.Trend)
	}
}

func TestBuildMarksPartialCoverageOnScanRunErrorsWithoutFailedResults(t *testing.T) {
	scan := &model.ScanRun{
		Selected:     2,
		Repositories: []model.RepositoryExecution{{Repository: "a/b", Status: "complete"}},
		Errors:       []model.RunError{{Component: "clone", Kind: "runtime", Message: "boom"}},
		Results:      []model.ScannerResult{{Status: model.ScannerClean}},
	}
	result := Build(nil, nil, scan, nil, -1, -1, 0)
	if result.Summary.Coverage != "partial" {
		t.Fatalf("coverage = %s, want partial", result.Summary.Coverage)
	}
}

func TestBuildMarksPartialCoverageOnIncompleteRepositoryCoverage(t *testing.T) {
	scan := &model.ScanRun{
		Selected:     2,
		Repositories: []model.RepositoryExecution{{Repository: "a/b", Status: "complete"}},
		Results:      []model.ScannerResult{{Status: model.ScannerClean}},
	}
	result := Build(nil, nil, scan, nil, -1, -1, 0)
	if result.Summary.Coverage != "partial" {
		t.Fatalf("coverage = %s, want partial", result.Summary.Coverage)
	}
}

func TestBuildMarksPartialCoverageWhenMergedScanIsMissingAWholeBatch(t *testing.T) {
	// Simulates merge.Scans output after one of two matrix batches failed to
	// produce a scan.json: Selected is self-consistent with Repositories, so
	// only comparing against an independently supplied expected count catches
	// the gap.
	scan := &model.ScanRun{
		Selected:     2,
		Repositories: []model.RepositoryExecution{{Repository: "a/b", Status: "complete"}, {Repository: "a/c", Status: "complete"}},
		Results:      []model.ScannerResult{{Repository: "a/b", Status: model.ScannerClean}, {Repository: "a/c", Status: model.ScannerClean}},
	}
	result := Build(nil, nil, scan, nil, 4, -1, 0)
	if result.Summary.Coverage != "partial" {
		t.Fatalf("coverage = %s, want partial", result.Summary.Coverage)
	}
}

func TestBuildMarksPartialCoverageWhenNoScanArtifactsAreAvailable(t *testing.T) {
	result := Build(nil, nil, nil, nil, 4, -1, 0)
	if result.Summary.Coverage != "partial" {
		t.Fatalf("coverage = %s, want partial", result.Summary.Coverage)
	}
}

func TestBuildDoesNotRequireScanWhenExpectedRepositoriesIsZero(t *testing.T) {
	inventory := &model.Inventory{Selected: 0, Complete: true}
	result := Build(inventory, nil, nil, nil, 0, -1, 0)
	if result.Summary.Coverage != "complete" {
		t.Fatalf("coverage = %s, want complete", result.Summary.Coverage)
	}
}

func TestBuildDoesNotRequireScanWhenNotExpected(t *testing.T) {
	inventory := &model.Inventory{Selected: 4, Complete: true}
	audit := &model.Audit{Counts: map[string]int{"pass": 4}}
	result := Build(inventory, audit, nil, nil, -1, -1, 0)
	if result.Summary.Coverage != "complete" {
		t.Fatalf("coverage = %s, want complete", result.Summary.Coverage)
	}
}

func TestBuildDoesNotFlagATargetedRunScopedBelowInventorySelected(t *testing.T) {
	// A workflow_dispatch run targeting a repository subset via `batch
	// --repository` scans fewer repositories than the full org inventory
	// selects. The expected count must come from the batch plan, not
	// inventory.Selected, or every targeted run would be misreported.
	inventory := &model.Inventory{Selected: 50, Complete: true}
	scan := &model.ScanRun{
		Selected:     2,
		Repositories: []model.RepositoryExecution{{Repository: "a/b", Status: "complete"}, {Repository: "a/c", Status: "complete"}},
		Results:      []model.ScannerResult{{Repository: "a/b", Status: model.ScannerClean}, {Repository: "a/c", Status: model.ScannerClean}},
	}
	result := Build(inventory, nil, scan, nil, 2, -1, 0)
	if result.Summary.Coverage != "complete" {
		t.Fatalf("coverage = %s, want complete", result.Summary.Coverage)
	}
}

func TestBuildMarksPartialCoverageWhenPublicationBatchArtifactIsMissing(t *testing.T) {
	publications := []model.Publication{{Status: model.PublicationSucceeded}}
	result := Build(nil, nil, nil, publications, -1, 2, 1)
	if result.Summary.Coverage != "partial" {
		t.Fatalf("coverage = %s, want partial", result.Summary.Coverage)
	}
}

func TestBuildDoesNotRequirePublicationArtifactsWhenPublicationIsNotExpected(t *testing.T) {
	result := Build(nil, nil, nil, nil, -1, -1, 0)
	if result.Summary.Coverage != "complete" {
		t.Fatalf("coverage = %s, want complete", result.Summary.Coverage)
	}
}

func TestBuildIncludesDeterministicFindingGroupsWithArtifactReferences(t *testing.T) {
	scan := &model.ScanRun{Results: []model.ScannerResult{
		{
			Repository: "org/z",
			Scanner:    "trivy",
			ResultPath: "segh-results/sarif/org-z/trivy.sarif",
			FindingSummaries: []model.FindingSummary{
				{RuleID: "B", Severity: "high", Count: 2},
			},
		},
		{
			Repository: "org/a",
			Scanner:    "zizmor",
			ResultPath: "segh-results/sarif/org-a/zizmor.sarif",
			FindingSummaries: []model.FindingSummary{
				{RuleID: "A", Severity: "medium", Count: 1},
			},
		},
	}}
	result := Build(nil, nil, scan, nil, -1, -1, 0)
	if len(result.Findings) != 2 {
		t.Fatalf("findings = %#v", result.Findings)
	}
	if result.Findings[0].Repository != "org/a" || result.Findings[1].Count != 2 {
		t.Fatalf("findings are not deterministically ordered: %#v", result.Findings)
	}
	markdown := Markdown(result)
	if !strings.Contains(markdown, "## Normalized finding groups") ||
		!strings.Contains(markdown, "`segh-results/sarif/org-z/trivy.sarif`") {
		t.Fatalf("markdown = %s", markdown)
	}
}
