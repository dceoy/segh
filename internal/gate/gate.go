package gate

import (
	"fmt"
	"html"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/dceoy/segh/internal/config"
	"github.com/dceoy/segh/internal/sarif"
)

type Result struct {
	NewFindings      []sarif.Finding `json:"new_findings"`
	BlockingFindings []sarif.Finding `json:"blocking_findings"`
	BaselineCount    int             `json:"baseline_count"`
	CurrentCount     int             `json:"current_count"`
	ReportOnly       bool            `json:"report_only"`
}

func Compare(currentPaths, baselinePaths []string, cfg config.PullRequest) (Result, error) {
	current, err := load(currentPaths)
	if err != nil {
		return Result{}, fmt.Errorf("load current findings: %w", err)
	}
	baseline, err := load(baselinePaths)
	if err != nil {
		return Result{}, fmt.Errorf("load baseline findings: %w", err)
	}
	known := make(map[string]struct{}, len(baseline))
	for _, finding := range baseline {
		known[finding.Fingerprint] = struct{}{}
	}
	result := Result{BaselineCount: len(baseline), CurrentCount: len(current), ReportOnly: cfg.ReportOnly}
	for _, finding := range current {
		if _, exists := known[finding.Fingerprint]; exists {
			continue
		}
		result.NewFindings = append(result.NewFindings, finding)
		if blocking(finding, cfg.Thresholds) {
			result.BlockingFindings = append(result.BlockingFindings, finding)
		}
	}
	return result, nil
}

func (r Result) Failed() bool {
	return !r.ReportOnly && len(r.BlockingFindings) > 0
}

func Markdown(result Result) string {
	var builder strings.Builder
	builder.WriteString("# segh pull-request security gate\n\n")
	fmt.Fprintf(&builder, "- Current findings: %d\n", result.CurrentCount)
	fmt.Fprintf(&builder, "- Baseline findings: %d\n", result.BaselineCount)
	fmt.Fprintf(&builder, "- New findings: %d\n", len(result.NewFindings))
	fmt.Fprintf(&builder, "- New blocking findings: %d\n", len(result.BlockingFindings))
	fmt.Fprintf(&builder, "- Mode: %s\n", map[bool]string{true: "report-only", false: "enforcing"}[result.ReportOnly])
	if len(result.NewFindings) == 0 {
		return builder.String()
	}
	builder.WriteString("\n| Scanner | Rule | Severity | Location | Blocking | Message |\n")
	builder.WriteString("|---|---|---|---|---|---|\n")
	blocked := map[string]struct{}{}
	for _, finding := range result.BlockingFindings {
		blocked[finding.Fingerprint] = struct{}{}
	}
	for _, finding := range result.NewFindings {
		_, isBlocked := blocked[finding.Fingerprint]
		location := finding.URI
		if finding.Line > 0 {
			location += fmt.Sprintf(":%d", finding.Line)
		}
		fmt.Fprintf(&builder, "| %s | `%s` | %s | %s | %t | %s |\n",
			cell(finding.Scanner), cell(finding.RuleID), finding.Severity, cell(location), isBlocked, cell(finding.Message))
	}
	return builder.String()
}

func Annotations(result Result) []string {
	blocked := map[string]struct{}{}
	for _, finding := range result.BlockingFindings {
		blocked[finding.Fingerprint] = struct{}{}
	}
	annotations := make([]string, 0, len(result.NewFindings))
	for _, finding := range result.NewFindings {
		level := "warning"
		if _, isBlocked := blocked[finding.Fingerprint]; isBlocked {
			level = "error"
		}
		parameters := ""
		if safeAnnotationPath(finding.URI) {
			parameters = " file=" + commandProperty(finding.URI)
			if finding.Line > 0 {
				parameters += fmt.Sprintf(",line=%d", finding.Line)
			}
			if finding.Column > 0 {
				parameters += fmt.Sprintf(",col=%d", finding.Column)
			}
		}
		message := finding.Scanner + "/" + finding.RuleID + ": " + finding.Message
		annotations = append(annotations, "::"+level+parameters+"::"+commandData(message))
	}
	return annotations
}

func load(paths []string) ([]sarif.Finding, error) {
	var expanded []string
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		if !info.IsDir() {
			expanded = append(expanded, path)
			continue
		}
		err = filepath.WalkDir(path, func(current string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !entry.IsDir() && strings.HasSuffix(strings.ToLower(entry.Name()), ".sarif") {
				expanded = append(expanded, current)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	sort.Strings(expanded)
	var findings []sarif.Finding
	for _, path := range expanded {
		log, err := sarif.Read(path)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		findings = append(findings, sarif.Findings(log)...)
	}
	return findings, nil
}

func blocking(finding sarif.Finding, thresholds map[string]config.GateThreshold) bool {
	threshold, ok := thresholds[finding.Scanner]
	if !ok {
		threshold, ok = thresholds["default"]
	}
	if !ok {
		return false
	}
	if len(threshold.Rules) > 0 && !slices.Contains(threshold.Rules, finding.RuleID) {
		return false
	}
	return severityRank(finding.Severity) >= severityRank(threshold.MinimumSeverity)
}

func severityRank(value string) int {
	switch strings.ToLower(value) {
	case "critical":
		return 5
	case "high", "error":
		return 4
	case "medium", "warning":
		return 3
	case "low", "note":
		return 2
	default:
		return 1
	}
}

func safeAnnotationPath(value string) bool {
	if value == "" || filepath.IsAbs(value) {
		return false
	}
	clean := filepath.Clean(filepath.FromSlash(value))
	return clean != ".." && !strings.HasPrefix(clean, ".."+string(filepath.Separator))
}

func commandProperty(value string) string {
	replacer := strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A", ":", "%3A", ",", "%2C")
	return replacer.Replace(value)
}

func commandData(value string) string {
	if len(value) > 4096 {
		value = value[:4096] + "…"
	}
	replacer := strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A")
	return replacer.Replace(value)
}

func cell(value string) string {
	value = strings.NewReplacer("|", "\\|", "\r", " ", "\n", " ").Replace(value)
	if len(value) > 300 {
		value = value[:300] + "…"
	}
	return html.EscapeString(value)
}
