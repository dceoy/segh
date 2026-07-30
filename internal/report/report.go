package report

import (
	"fmt"
	"html"
	"strings"

	"github.com/dceoy/segh/internal/model"
)

func Markdown(inventory model.Inventory, audit model.Audit) string {
	var builder strings.Builder
	builder.WriteString("# segh organization security report\n\n")
	fmt.Fprintf(&builder, "- Repositories: %d selected, %d excluded, %d total\n",
		inventory.Selected, inventory.Excluded, inventory.Total)
	fmt.Fprintf(&builder, "- Coverage: %s\n", audit.Coverage)
	writePolicyCounts(&builder, audit.PolicyCounts)
	builder.WriteString("\n## Policy violations and incomplete checks\n\n")
	builder.WriteString("| Repository | Policy | Status | Severity | Remediation |\n")
	builder.WriteString("|---|---|---|---|---|\n")
	rows := 0
	for _, item := range audit.Results {
		if item.Status == model.PolicyPass || item.Status == model.PolicyExempt {
			continue
		}
		fmt.Fprintf(&builder, "| %s | `%s` | %s | %s | %s |\n",
			cell(item.Repository), cell(item.PolicyID), item.Status, cell(item.Severity), cell(item.Remediation))
		rows++
	}
	if rows == 0 {
		builder.WriteString("| — | — | pass | — | No policy violations |\n")
	}
	return builder.String()
}

func writePolicyCounts(builder *strings.Builder, counts map[string]int) {
	keys := []string{"pass", "fail", "unknown", "unsupported", "exempt"}
	values := make([]string, 0, len(keys))
	for _, key := range keys {
		if value, ok := counts[key]; ok {
			values = append(values, fmt.Sprintf("%s=%d", key, value))
		}
	}
	if len(values) > 0 {
		fmt.Fprintf(builder, "- Policy: %s\n", strings.Join(values, ", "))
	}
}

func cell(value string) string {
	value = strings.ReplaceAll(value, "|", "\\|")
	value = strings.ReplaceAll(value, "\r", " ")
	value = strings.ReplaceAll(value, "\n", " ")
	if len(value) > 300 {
		return html.EscapeString(value[:300]) + "…"
	}
	return html.EscapeString(value)
}
