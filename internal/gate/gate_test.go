package gate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dceoy/segh/internal/config"
	"github.com/dceoy/segh/internal/sarif"
)

func TestCompareGatesOnlyNewFindings(t *testing.T) {
	dir := t.TempDir()
	baseline := filepath.Join(dir, "baseline.sarif")
	current := filepath.Join(dir, "current.sarif")
	writeSARIF(t, baseline, []sarif.Result{fixtureResult("existing", "base", "warning")})
	writeSARIF(t, current, []sarif.Result{
		fixtureResult("existing", "base", "warning"),
		fixtureResult("new-high", "new", "error"),
	})
	cfg := config.PullRequest{
		ReportOnly: false,
		Thresholds: map[string]config.GateThreshold{
			"zizmor": {MinimumSeverity: "high"},
		},
	}
	result, err := Compare([]string{current}, []string{baseline}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.NewFindings) != 1 || len(result.BlockingFindings) != 1 || !result.Failed() {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestReportOnlyAndAnnotationEscaping(t *testing.T) {
	result := Result{
		ReportOnly: true,
		NewFindings: []sarif.Finding{{
			Scanner: "zizmor", RuleID: "rule", Message: "bad\n::error::injection",
			URI: "../escape", Line: 1, Fingerprint: "x",
		}},
		BlockingFindings: []sarif.Finding{{Fingerprint: "x"}},
	}
	if result.Failed() {
		t.Fatal("report-only must not fail")
	}
	annotation := Annotations(result)[0]
	if strings.Contains(annotation, "\n") || strings.Contains(annotation, "file=") {
		t.Fatalf("unsafe annotation: %q", annotation)
	}
}

func writeSARIF(t *testing.T, path string, results []sarif.Result) {
	t.Helper()
	log := sarif.Log{Version: "2.1.0", Runs: []sarif.Run{{
		Tool: sarif.Tool{Driver: sarif.Driver{Name: "zizmor"}}, Results: results,
	}}}
	data, err := json.Marshal(log)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func fixtureResult(rule, fingerprint, level string) sarif.Result {
	return sarif.Result{
		RuleID: rule, Level: level, Message: sarif.Message{Text: rule},
		PartialFingerprints: map[string]string{"id": fingerprint},
	}
}
