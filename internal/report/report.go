package report

import (
	"fmt"
	"html"
	"strings"

	"github.com/dceoy/segh/internal/model"
	"github.com/dceoy/segh/internal/policy"
)

type Consolidated struct {
	SchemaVersion int              `json:"schema_version"`
	Inventory     *model.Inventory `json:"inventory,omitempty"`
	Audit         *model.Audit     `json:"audit,omitempty"`
	Summary       Summary          `json:"summary"`
}

type Summary struct {
	Repositories int            `json:"repositories"`
	Policy       map[string]int `json:"policy"`
	Coverage     string         `json:"coverage"`
}

func Build(inventory *model.Inventory, audit *model.Audit) Consolidated {
	result := Consolidated{
		SchemaVersion: model.ReportSchemaVersion,
		Inventory:     inventory,
		Audit:         audit,
		Summary: Summary{
			Policy:   map[string]int{},
			Coverage: "complete",
		},
	}
	if inventory != nil {
		result.Summary.Repositories = inventory.Selected
		if !inventory.Complete {
			result.Summary.Coverage = "partial"
		}
	}
	if audit != nil {
		for key, value := range audit.Counts {
			result.Summary.Policy[key] = value
		}
		if policy.Partial(*audit) {
			result.Summary.Coverage = "partial"
		}
	}
	return result
}

func Markdown(result Consolidated) string {
	var builder strings.Builder
	builder.WriteString("# segh organization security report\n\n")
	fmt.Fprintf(&builder, "- Repositories: %d\n", result.Summary.Repositories)
	fmt.Fprintf(&builder, "- Coverage: %s\n", result.Summary.Coverage)
	writePolicyCounts(&builder, result.Summary.Policy)

	if result.Audit != nil {
		builder.WriteString("\n## Policy violations and incomplete checks\n\n")
		builder.WriteString("| Repository | Policy | Status | Severity | Remediation |\n")
		builder.WriteString("|---|---|---|---|---|\n")
		rows := 0
		for _, item := range result.Audit.Results {
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
