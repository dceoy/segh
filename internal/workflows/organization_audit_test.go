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
	step := bindScannerEvidenceStep(t)

	// Zizmor v1.28.0 encodes its highest finding severity in its exit code
	// (11-14), unlike every other scanner here, which only ever exits 0 or
	// 1. A finding must classify as "findings", not "error".
	if result := runBindScannerEvidence(t, step, 13); result != "findings" {
		t.Fatalf("zizmor status 13 (medium finding) classified as %q, want findings", result)
	}
	if result := runBindScannerEvidence(t, step, 14); result != "findings" {
		t.Fatalf("zizmor status 14 (high finding) classified as %q, want findings", result)
	}
	// A genuine Zizmor runtime failure (any status outside 0 and 11-14)
	// must still classify as an error.
	if result := runBindScannerEvidence(t, step, 2); result != "error" {
		t.Fatalf("zizmor status 2 (runtime failure) classified as %q, want error", result)
	}
}

func TestBindScannerEvidenceTreatsUpstreamNotRunEvidenceAsError(t *testing.T) {
	step := bindScannerEvidenceStep(t)

	// The pinned upstream scanner uses plain exit status 1 for both
	// ordinary findings and runtime paths where the scanner never actually
	// evaluated the target (e.g. unable to extract composite-action shell
	// blocks). Those carry a JSON object with result "not-run" instead of a
	// findings array, and must classify as an error, not a clean findings
	// verdict.
	result := runBindScannerEvidenceWithFixture(t, step, func(results string) {
		writeCleanScannerFixtures(t, results, 0)
		mustWriteFile(t, filepath.Join(results, "shellcheck.status"), "1\n")
		mustWriteFile(t, filepath.Join(results, "shellcheck.json"),
			`{"scanner":"shellcheck","result":"not-run","reason":"unable to inspect composite action shell blocks"}`+"\n")
		mustWriteFile(t, filepath.Join(results, "shellcheck.txt"),
			"Failed: unable to inspect composite action shell blocks.\n")
	})
	if result != "error" {
		t.Fatalf("status-1 not-run scanner evidence classified as %q, want error", result)
	}
}

func TestBindScannerEvidenceTreatsEmptyArrayAtNonZeroStatusAsError(t *testing.T) {
	step := bindScannerEvidenceStep(t)

	// actionlint and shellcheck also fall back to the "[]" placeholder
	// evidence used for a clean skip (no applicable files) when they never
	// actually evaluated the target: actionlint on a JSON Lines-to-array
	// conversion failure, shellcheck when a tracked file cannot be read
	// while probing for shebangs. Both force exit status 1 without ever
	// writing a real finding payload; a genuine finding is always a
	// non-empty array (actionlint) or a findings object (shellcheck's
	// json1), so a bare empty array at a non-zero status is never a
	// legitimate finding and must classify as an error.
	for _, scanner := range []string{"actionlint", "shellcheck"} {
		t.Run(scanner, func(t *testing.T) {
			result := runBindScannerEvidenceWithFixture(t, step, func(results string) {
				writeCleanScannerFixtures(t, results, 0)
				mustWriteFile(t, filepath.Join(results, scanner+".status"), "1\n")
				mustWriteFile(t, filepath.Join(results, scanner+".json"), "[]\n")
				mustWriteFile(t, filepath.Join(results, scanner+".txt"), "Failed: unable to evaluate the target.\n")
			})
			if result != "error" {
				t.Fatalf("status-1 empty-array evidence for %s classified as %q, want error", scanner, result)
			}
		})
	}
}

func TestBindScannerEvidenceTreatsPreflightOperationalFailureAsError(t *testing.T) {
	step := bindScannerEvidenceStep(t)

	// The pinned upstream scanner redirects "git ls-files" straight into
	// tracked-files.index, so the file exists (empty) even when entering or
	// enumerating the checkout fails outright, before any content-based
	// preflight status is ever set. A non-zero preflight.status alongside an
	// empty index therefore means preflight failed operationally (e.g.
	// could not enter or enumerate the checkout), not that tracked content
	// was merely incomplete, and must classify as an error rather than
	// "incomplete".
	result := runBindScannerEvidenceWithFixture(t, step, func(results string) {
		writeCleanScannerFixtures(t, results, 0)
		mustWriteFile(t, filepath.Join(results, "preflight.status"), "1\n")
		mustWriteFile(t, filepath.Join(results, "tracked-files.index"), "")
	})
	if result != "error" {
		t.Fatalf("preflight operational failure classified as %q, want error", result)
	}
}

func TestBindScannerEvidenceTreatsPreflightContentIncompleteAsIncomplete(t *testing.T) {
	step := bindScannerEvidenceStep(t)

	// A non-zero preflight.status alongside a populated tracked-files.index
	// means preflight actually enumerated the checkout and rejected
	// specific tracked content (a submodule gitlink, an LFS pointer, or an
	// unremovable symlink); that is genuinely incomplete coverage, not an
	// operational failure, and must still classify as "incomplete".
	result := runBindScannerEvidenceWithFixture(t, step, func(results string) {
		writeCleanScannerFixtures(t, results, 0)
		mustWriteFile(t, filepath.Join(results, "preflight.status"), "1\n")
		mustWriteFile(t, filepath.Join(results, "tracked-files.index"), "160000 submodule\x00commit\tvendor/lib\x00")
	})
	if result != "incomplete" {
		t.Fatalf("preflight content-incomplete failure classified as %q, want incomplete", result)
	}
}

func bindScannerEvidenceStep(t *testing.T) string {
	t.Helper()
	job := loadWorkflow(t, organizationAuditWorkflowPath).Jobs["source-scan"]
	step, ok := findStep(job.Steps, "Bind scanner evidence to the planned repository identity")
	if !ok {
		t.Fatal("missing Bind scanner evidence step")
	}
	return step.Run
}

// runBindScannerEvidence executes the workflow's evidence-binding step
// against fixture evidence where every scanner but zizmor passes cleanly,
// and zizmor exits with zizmorStatus. It returns the resulting status.json
// "result" field.
func runBindScannerEvidence(t *testing.T, script string, zizmorStatus int) string {
	t.Helper()
	return runBindScannerEvidenceWithFixture(t, script, func(results string) {
		writeCleanScannerFixtures(t, results, zizmorStatus)
	})
}

// runBindScannerEvidenceWithFixture executes the workflow's evidence-binding
// step against a results directory populated by fixture, and returns the
// resulting status.json "result" field.
func runBindScannerEvidenceWithFixture(t *testing.T, script string, fixture func(results string)) string {
	t.Helper()
	workspace := t.TempDir()
	results := filepath.Join(workspace, "security-results")
	if err := os.MkdirAll(results, 0o700); err != nil {
		t.Fatal(err)
	}
	fixture(results)

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

// writeCleanScannerFixtures writes a successful preflight (including the
// tracked-files.index the real scanner only produces after entering and
// enumerating the target checkout) and clean evidence for every scanner
// except zizmor, which exits zizmorStatus.
func writeCleanScannerFixtures(t *testing.T, results string, zizmorStatus int) {
	t.Helper()
	mustWriteFile(t, filepath.Join(results, "preflight.status"), "0\n")
	mustWriteFile(t, filepath.Join(results, "tracked-files.index"), "")
	scanners := []string{"zizmor", "actionlint", "shellcheck", "checkov", "trivy-vulnerability", "trivy-secret"}
	for _, scanner := range scanners {
		status := "0\n"
		if scanner == "zizmor" {
			status = strconv.Itoa(zizmorStatus) + "\n"
		}
		mustWriteFile(t, filepath.Join(results, scanner+".status"), status)
		mustWriteFile(t, filepath.Join(results, scanner+".json"), "[]\n")
		mustWriteFile(t, filepath.Join(results, scanner+".txt"), "no findings\n")
		mustWriteFile(t, filepath.Join(results, scanner+".log"), "")
	}
}

func mustWriteFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
