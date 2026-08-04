package report

import (
	"strings"
	"testing"

	"github.com/dceoy/segh/internal/model"
)

func TestMarkdownUsesCanonicalAuditSummaryAndEscapesRows(t *testing.T) {
	inventory := model.Inventory{Total: 3, Selected: 2, Excluded: 1}
	audit := model.Audit{
		Coverage:     "partial",
		PolicyCounts: map[string]int{"unknown": 1},
		Results: []model.PolicyResult{{
			Repository: "example/repo|line\nbreak", PolicyID: "repository.test",
			Status: model.PolicyUnknown, Severity: "high", Remediation: "<review>",
		}},
	}
	markdown := Markdown(inventory, audit)
	for _, want := range []string{
		"Repositories: 2 selected, 1 excluded, 3 total",
		"Coverage: partial",
		"unknown=1",
		"example/repo\\|line break",
		"&lt;review&gt;",
	} {
		if !strings.Contains(markdown, want) {
			t.Fatalf("Markdown() missing %q:\n%s", want, markdown)
		}
	}
}

func TestMarkdownRendersWarningAndNoticeRowsAlongsideCounts(t *testing.T) {
	inventory := model.Inventory{Total: 1, Selected: 1}
	audit := model.Audit{
		Coverage:     "complete",
		PolicyCounts: map[string]int{"warning": 1, "notice": 1},
		Results: []model.PolicyResult{
			{Repository: "example/app", PolicyID: "dependencies.lock_file", Status: model.PolicyWarning, Severity: "warning", Remediation: "commit a lock file"},
			{Repository: "example/lib", PolicyID: "dependencies.lock_file", Status: model.PolicyNotice, Severity: "notice", Remediation: "consider a lock file"},
		},
	}
	markdown := Markdown(inventory, audit)
	for _, want := range []string{"warning=1", "notice=1", "example/app", "example/lib", "commit a lock file", "consider a lock file"} {
		if !strings.Contains(markdown, want) {
			t.Fatalf("Markdown() missing %q:\n%s", want, markdown)
		}
	}
}
