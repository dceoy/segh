package report

import (
	"strings"
	"testing"

	"github.com/dceoy/segh/internal/model"
)

func TestMarkdownOrdersRetainedPolicyCounts(t *testing.T) {
	audit := model.Audit{
		Coverage: "partial",
		PolicyCounts: map[string]int{
			string(model.PolicyExempt):      5,
			string(model.PolicyUnsupported): 4,
			string(model.PolicyUnknown):     3,
			string(model.PolicyFail):        2,
			string(model.PolicyPass):        1,
		},
	}
	markdown := Markdown(model.Inventory{}, audit)
	want := "Policy: pass=1, fail=2, unknown=3, unsupported=4, exempt=5"
	if !strings.Contains(markdown, want) {
		t.Fatalf("Markdown() missing ordered retained counts %q:\n%s", want, markdown)
	}
}
