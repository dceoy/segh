package sarif

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

type Log struct {
	Version string `json:"version"`
	Runs    []Run  `json:"runs"`
}

type Run struct {
	Tool    Tool     `json:"tool"`
	Results []Result `json:"results"`
}

type Tool struct {
	Driver Driver `json:"driver"`
}

type Driver struct {
	Name            string `json:"name"`
	SemanticVersion string `json:"semanticVersion,omitempty"`
	Rules           []Rule `json:"rules,omitempty"`
}

type Rule struct {
	ID         string         `json:"id"`
	Properties map[string]any `json:"properties,omitempty"`
}

type Result struct {
	RuleID              string            `json:"ruleId"`
	Level               string            `json:"level,omitempty"`
	Message             Message           `json:"message"`
	Locations           []Location        `json:"locations,omitempty"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
	Fingerprints        map[string]string `json:"fingerprints,omitempty"`
	Properties          map[string]any    `json:"properties,omitempty"`
}

type Message struct {
	Text string `json:"text"`
}

type Location struct {
	PhysicalLocation PhysicalLocation `json:"physicalLocation"`
}

type PhysicalLocation struct {
	ArtifactLocation ArtifactLocation `json:"artifactLocation"`
	Region           Region           `json:"region"`
}

type ArtifactLocation struct {
	URI string `json:"uri"`
}

type Region struct {
	StartLine   int `json:"startLine,omitempty"`
	StartColumn int `json:"startColumn,omitempty"`
}

type Finding struct {
	Scanner     string `json:"scanner"`
	RuleID      string `json:"rule_id"`
	Severity    string `json:"severity"`
	Message     string `json:"message"`
	URI         string `json:"uri,omitempty"`
	Line        int    `json:"line,omitempty"`
	Column      int    `json:"column,omitempty"`
	Fingerprint string `json:"fingerprint"`
}

func Read(path string) (Log, error) {
	info, err := os.Stat(path)
	if err != nil {
		return Log{}, fmt.Errorf("stat SARIF: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() > 50<<20 {
		return Log{}, fmt.Errorf("SARIF exceeds 50 MiB")
	}
	data, err := os.ReadFile(path) // #nosec G304 -- the CLI operator selected a regular, size-bounded SARIF artifact.
	if err != nil {
		return Log{}, fmt.Errorf("read SARIF: %w", err)
	}
	var log Log
	if err := json.Unmarshal(data, &log); err != nil {
		return Log{}, fmt.Errorf("decode SARIF: %w", err)
	}
	if log.Version == "" || len(log.Runs) == 0 {
		return Log{}, fmt.Errorf("invalid SARIF: version and at least one run are required")
	}
	return log, nil
}

func Findings(log Log) []Finding {
	var findings []Finding
	for _, run := range log.Runs {
		rules := map[string]Rule{}
		for _, rule := range run.Tool.Driver.Rules {
			rules[rule.ID] = rule
		}
		for _, result := range run.Results {
			finding := Finding{
				Scanner:  normalizeScanner(run.Tool.Driver.Name),
				RuleID:   result.RuleID,
				Severity: severity(result, rules[result.RuleID]),
				Message:  result.Message.Text,
			}
			if len(result.Locations) > 0 {
				physical := result.Locations[0].PhysicalLocation
				finding.URI = filepath.ToSlash(filepath.Clean(physical.ArtifactLocation.URI))
				if finding.URI == "." {
					finding.URI = ""
				}
				finding.Line = physical.Region.StartLine
				finding.Column = physical.Region.StartColumn
			}
			finding.Fingerprint = fingerprint(result, finding)
			findings = append(findings, finding)
		}
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Scanner != findings[j].Scanner {
			return findings[i].Scanner < findings[j].Scanner
		}
		if findings[i].RuleID != findings[j].RuleID {
			return findings[i].RuleID < findings[j].RuleID
		}
		return findings[i].Fingerprint < findings[j].Fingerprint
	})
	return findings
}

func CountFile(path string) (int, error) {
	log, err := Read(path)
	if err != nil {
		return 0, err
	}
	return len(Findings(log)), nil
}

func fingerprint(result Result, finding Finding) string {
	values := make([]string, 0, len(result.PartialFingerprints)+len(result.Fingerprints))
	for key, value := range result.PartialFingerprints {
		values = append(values, key+"="+value)
	}
	for key, value := range result.Fingerprints {
		values = append(values, key+"="+value)
	}
	sort.Strings(values)
	if len(values) == 0 {
		values = []string{
			finding.Scanner, finding.RuleID, finding.URI,
			strconv.Itoa(finding.Line), strings.TrimSpace(finding.Message),
		}
	}
	sum := sha256.Sum256([]byte(strings.Join(values, "\x00")))
	return hex.EncodeToString(sum[:])
}

func severity(result Result, rule Rule) string {
	for _, properties := range []map[string]any{result.Properties, rule.Properties} {
		for _, key := range []string{"security-severity", "security_severity", "severity"} {
			if value, ok := properties[key]; ok {
				if numeric, err := strconv.ParseFloat(fmt.Sprint(value), 64); err == nil {
					switch {
					case numeric >= 9:
						return "critical"
					case numeric >= 7:
						return "high"
					case numeric >= 4:
						return "medium"
					default:
						return "low"
					}
				}
				value := strings.ToLower(fmt.Sprint(value))
				switch value {
				case "critical", "high", "medium", "low", "error", "warning", "note", "none":
					return value
				}
			}
		}
	}
	switch strings.ToLower(result.Level) {
	case "error":
		return "high"
	case "warning":
		return "medium"
	case "note":
		return "low"
	default:
		return "none"
	}
}

func normalizeScanner(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	switch {
	case strings.Contains(name, "zizmor"):
		return "zizmor"
	case strings.Contains(name, "trivy"):
		return "trivy"
	case strings.Contains(name, "scorecard"):
		return "scorecard"
	case strings.Contains(name, "semgrep"):
		return "semgrep"
	default:
		return name
	}
}
