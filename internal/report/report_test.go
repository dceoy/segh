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
	result := Build(inventory, audit, scan, []model.Publication{{Status: model.PublicationUnsupported}})
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
	result := Build(nil, nil, scan, nil)
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
	result := Build(nil, nil, scan, nil)
	if result.Summary.Coverage != "partial" {
		t.Fatalf("coverage = %s, want partial", result.Summary.Coverage)
	}
}
