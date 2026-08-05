package sourcescan

import (
	"fmt"
	"strings"
	"testing"

	"github.com/dceoy/segh/internal/model"
)

func TestMarkdownLimitsRenderedErrorsToFifty(t *testing.T) {
	summary := model.SourceScanSummary{Errors: make([]model.RunError, 51)}
	for index := range summary.Errors {
		summary.Errors[index] = model.RunError{
			Repository: fmt.Sprintf("example/repo-%02d", index),
			Kind:       fmt.Sprintf("error-%02d", index),
		}
	}

	markdown := Markdown(summary)
	if got := strings.Count(markdown, "\n- `example/repo-"); got != 50 {
		t.Fatalf("rendered error entries = %d, want 50\n%s", got, markdown)
	}
	if !strings.Contains(markdown, "error-49\n") {
		t.Fatalf("markdown does not contain the fiftieth error entry:\n%s", markdown)
	}
	if strings.Contains(markdown, "error-50") {
		t.Fatalf("markdown contains an error entry beyond the limit:\n%s", markdown)
	}
	if !strings.Contains(markdown, "- Additional errors are retained in `scan-summary.json`.\n") {
		t.Fatalf("markdown does not contain the truncation notice:\n%s", markdown)
	}
}
