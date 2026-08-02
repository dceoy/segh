// Package workflows pins the trust boundaries of the security-critical
// GitHub Actions workflows that cannot be exercised against themselves.
package workflows

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const organizationAuditWorkflowPath = "../../.github/workflows/organization-audit.yml"

func TestBindScannerEvidenceClassifiesZizmorSeverityExitCodesAsFindings(t *testing.T) {
	job := loadWorkflow(t, organizationAuditWorkflowPath).Jobs["source-scan"]
	step, ok := findStep(job.Steps, "Bind scanner evidence to the planned repository identity")
	if !ok {
		t.Fatal("missing Bind scanner evidence step")
	}

	// Zizmor v1.28.0 encodes its highest finding severity in its exit code
	// (11-14), unlike every other scanner here, which only ever exits 0 or
	// 1. A finding must classify as "findings", not "error".
	if result := runBindScannerEvidence(t, step.Run, 13); result != "findings" {
		t.Fatalf("zizmor status 13 (medium finding) classified as %q, want findings", result)
	}
	if result := runBindScannerEvidence(t, step.Run, 14); result != "findings" {
		t.Fatalf("zizmor status 14 (high finding) classified as %q, want findings", result)
	}
	// A genuine Zizmor runtime failure (any status outside 0 and 11-14)
	// must still classify as an error.
	if result := runBindScannerEvidence(t, step.Run, 2); result != "error" {
		t.Fatalf("zizmor status 2 (runtime failure) classified as %q, want error", result)
	}
}

// runBindScannerEvidence executes the workflow's evidence-binding step
// against fixture evidence where every scanner but zizmor passes cleanly,
// and zizmor exits with zizmorStatus. It returns the resulting status.json
// "result" field.
func runBindScannerEvidence(t *testing.T, script string, zizmorStatus int) string {
	t.Helper()
	workspace := t.TempDir()
	results := filepath.Join(workspace, "security-results")
	if err := os.MkdirAll(results, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(results, "preflight.status"), []byte("0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	scanners := []string{"zizmor", "actionlint", "shellcheck", "checkov", "trivy-vulnerability", "trivy-secret"}
	for _, scanner := range scanners {
		status := "0\n"
		if scanner == "zizmor" {
			status = strconv.Itoa(zizmorStatus) + "\n"
		}
		if err := os.WriteFile(filepath.Join(results, scanner+".status"), []byte(status), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(results, scanner+".json"), []byte("[]\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(results, scanner+".txt"), []byte("no findings\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(results, scanner+".log"), []byte(""), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	command := exec.CommandContext(context.Background(), "bash", "-c", script) // #nosec G204 -- script is the repository-owned workflow step.
	command.Dir = workspace
	command.Env = append(os.Environ(),
		"REPOSITORY_ID=1",
		"REPOSITORY=example/repo",
		"DEFAULT_BRANCH=main",
		"COMMIT_SHA="+strings.Repeat("a", 40),
	)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("bind scanner evidence step: %v\n%s", err, output)
	}

	var status struct {
		Result string `json:"result"`
	}
	data, err := os.ReadFile(filepath.Join(results, "status.json")) // #nosec G304 -- fixed test-owned path.
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &status); err != nil {
		t.Fatalf("parse status.json: %v\n%s", err, data)
	}
	return status.Result
}
