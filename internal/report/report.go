package report

import (
	"fmt"
	"html"
	"sort"
	"strings"

	"github.com/dceoy/segh/internal/model"
	"github.com/dceoy/segh/internal/policy"
)

type Consolidated struct {
	SchemaVersion int                 `json:"schema_version"`
	Inventory     *model.Inventory    `json:"inventory,omitempty"`
	Audit         *model.Audit        `json:"audit,omitempty"`
	Scan          *model.ScanRun      `json:"scan,omitempty"`
	Findings      []FindingGroup      `json:"findings,omitempty"`
	Publications  []model.Publication `json:"publications,omitempty"`
	Summary       Summary             `json:"summary"`
	Trend         *Trend              `json:"trend,omitempty"`
}

type FindingGroup struct {
	Repository string `json:"repository"`
	Scanner    string `json:"scanner"`
	RuleID     string `json:"rule_id"`
	Severity   string `json:"severity"`
	Count      int    `json:"count"`
	Artifact   string `json:"artifact"`
}

type Summary struct {
	Repositories int            `json:"repositories"`
	Policy       map[string]int `json:"policy"`
	Scanners     map[string]int `json:"scanners"`
	Publication  map[string]int `json:"publication"`
	Coverage     string         `json:"coverage"`
}

type Trend struct {
	PreviousFindings int `json:"previous_findings"`
	CurrentFindings  int `json:"current_findings"`
	Delta            int `json:"delta"`
}

// Build assembles a consolidated report. expectedRepositories is the number
// of distinct repositories the caller expects the scan stage to have covered.
// expectedPublicationBatches and observedPublicationBatches independently
// reconcile publication-stage artifacts with the batch plan. Pass -1 for an
// expected count when that stage is not expected for this run.
func Build(
	inventory *model.Inventory,
	audit *model.Audit,
	scan *model.ScanRun,
	publications []model.Publication,
	expectedRepositories, expectedPublicationBatches, observedPublicationBatches int,
) Consolidated {
	result := Consolidated{
		SchemaVersion: model.ReportSchemaVersion,
		Inventory:     inventory,
		Audit:         audit,
		Scan:          scan,
		Publications:  publications,
		Summary: Summary{
			Policy:      map[string]int{},
			Scanners:    map[string]int{},
			Publication: map[string]int{},
			Coverage:    "complete",
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
	if scan != nil {
		for _, scanner := range scan.Results {
			result.Summary.Scanners[string(scanner.Status)]++
			for _, finding := range scanner.FindingSummaries {
				result.Findings = append(result.Findings, FindingGroup{
					Repository: scanner.Repository,
					Scanner:    scanner.Scanner,
					RuleID:     finding.RuleID,
					Severity:   finding.Severity,
					Count:      finding.Count,
					Artifact:   scanner.ResultPath,
				})
			}
			if scanner.Status == model.ScannerFailed {
				result.Summary.Coverage = "partial"
			}
		}
		if len(scan.Errors) > 0 || len(scan.Repositories) < scan.Selected {
			result.Summary.Coverage = "partial"
		}
		if expectedRepositories >= 0 && scannedRepositories(scan.Repositories) < expectedRepositories {
			result.Summary.Coverage = "partial"
		}
	} else if expectedRepositories > 0 {
		result.Summary.Coverage = "partial"
	}
	for _, publication := range publications {
		result.Summary.Publication[string(publication.Status)]++
		if publication.Status != model.PublicationSucceeded && publication.Status != model.PublicationRetained {
			result.Summary.Coverage = "partial"
		}
	}
	if expectedPublicationBatches >= 0 && observedPublicationBatches < expectedPublicationBatches {
		result.Summary.Coverage = "partial"
	}
	sort.Slice(result.Findings, func(i, j int) bool {
		if result.Findings[i].Repository != result.Findings[j].Repository {
			return result.Findings[i].Repository < result.Findings[j].Repository
		}
		if result.Findings[i].Scanner != result.Findings[j].Scanner {
			return result.Findings[i].Scanner < result.Findings[j].Scanner
		}
		if result.Findings[i].RuleID != result.Findings[j].RuleID {
			return result.Findings[i].RuleID < result.Findings[j].RuleID
		}
		return result.Findings[i].Severity < result.Findings[j].Severity
	})
	return result
}

// scannedRepositories counts distinct repositories actually present in a scan
// run. A merged run's own Selected field is derived from this same set, so it
// cannot detect a matrix batch that failed to produce a scan.json at all;
// comparing against an independently supplied expected count can.
func scannedRepositories(executions []model.RepositoryExecution) int {
	seen := map[string]struct{}{}
	for _, execution := range executions {
		seen[execution.Repository] = struct{}{}
	}
	return len(seen)
}

func AddTrend(result *Consolidated, previous model.ScanRun) {
	if result.Scan == nil {
		return
	}
	trend := &Trend{}
	for _, item := range previous.Results {
		trend.PreviousFindings += item.Findings
	}
	for _, item := range result.Scan.Results {
		trend.CurrentFindings += item.Findings
	}
	trend.Delta = trend.CurrentFindings - trend.PreviousFindings
	result.Trend = trend
}

func Markdown(result Consolidated) string {
	var builder strings.Builder
	builder.WriteString("# segh organization security report\n\n")
	fmt.Fprintf(&builder, "- Repositories: %d\n", result.Summary.Repositories)
	fmt.Fprintf(&builder, "- Coverage: %s\n", result.Summary.Coverage)
	writeCounts(&builder, "Policy", result.Summary.Policy)
	writeCounts(&builder, "Scanners", result.Summary.Scanners)
	writeCounts(&builder, "SARIF publication", result.Summary.Publication)
	if result.Trend != nil {
		fmt.Fprintf(&builder, "- Finding trend: previous=%d, current=%d, delta=%+d\n",
			result.Trend.PreviousFindings, result.Trend.CurrentFindings, result.Trend.Delta)
	}

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
	if result.Scan != nil {
		builder.WriteString("\n## Scanner execution\n\n")
		builder.WriteString("| Repository | Scanner | Status | Findings | Duration |\n")
		builder.WriteString("|---|---|---|---:|---:|\n")
		results := append([]model.ScannerResult(nil), result.Scan.Results...)
		sort.Slice(results, func(i, j int) bool {
			if results[i].Repository != results[j].Repository {
				return results[i].Repository < results[j].Repository
			}
			return results[i].Scanner < results[j].Scanner
		})
		for _, item := range results {
			fmt.Fprintf(&builder, "| %s | %s | %s | %d | %d ms |\n",
				cell(item.Repository), cell(item.Scanner), item.Status, item.Findings, item.DurationMS)
		}
	}
	if len(result.Findings) > 0 {
		builder.WriteString("\n## Normalized finding groups\n\n")
		builder.WriteString("| Repository | Scanner | Rule | Severity | Count | Raw artifact |\n")
		builder.WriteString("|---|---|---|---|---:|---|\n")
		for _, item := range result.Findings {
			fmt.Fprintf(&builder, "| %s | %s | `%s` | %s | %d | `%s` |\n",
				cell(item.Repository), cell(item.Scanner), cell(item.RuleID), cell(item.Severity), item.Count, cell(item.Artifact))
		}
	}
	if len(result.Publications) > 0 {
		builder.WriteString("\n## SARIF publication\n\n")
		builder.WriteString("| Repository | Scanner | Category | Status |\n")
		builder.WriteString("|---|---|---|---|\n")
		for _, item := range result.Publications {
			fmt.Fprintf(&builder, "| %s | %s | `%s` | %s |\n",
				cell(item.Repository), cell(item.Scanner), cell(item.Category), item.Status)
		}
	}
	return builder.String()
}

func writeCounts(builder *strings.Builder, label string, counts map[string]int) {
	if len(counts) == 0 {
		return
	}
	keys := make([]string, 0, len(counts))
	for key := range counts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	values := make([]string, 0, len(keys))
	for _, key := range keys {
		values = append(values, fmt.Sprintf("%s=%d", key, counts[key]))
	}
	fmt.Fprintf(builder, "- %s: %s\n", label, strings.Join(values, ", "))
}

func cell(value string) string {
	value = strings.ReplaceAll(value, "|", "\\|")
	value = strings.ReplaceAll(value, "\r", " ")
	value = strings.ReplaceAll(value, "\n", " ")
	if len(value) > 300 {
		return value[:300] + "…"
	}
	return html.EscapeString(value)
}
