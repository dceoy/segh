package report

import (
	"strings"
	"testing"

	"github.com/dceoy/segh/internal/model"
)

func TestBuildMarksIncompleteNativeCoveragePartial(t *testing.T) {
	inventory := &model.Inventory{Selected: 2, Complete: true}
	audit := &model.Audit{Counts: map[string]int{"unknown": 1}}
	result := Build(inventory, audit)
	if result.Summary.Coverage != "partial" || result.Summary.Repositories != 2 {
		t.Fatalf("summary = %#v", result.Summary)
	}
	if markdown := Markdown(result); !strings.Contains(markdown, "Coverage: partial") ||
		!strings.Contains(markdown, "unknown=1") {
		t.Fatalf("markdown = %s", markdown)
	}
}

func TestBuildDoesNotRequireScannerResults(t *testing.T) {
	inventory := &model.Inventory{Selected: 4, Complete: true}
	audit := &model.Audit{Counts: map[string]int{"pass": 4}}
	result := Build(inventory, audit)
	if result.Summary.Coverage != "complete" {
		t.Fatalf("coverage = %s, want complete", result.Summary.Coverage)
	}
}
