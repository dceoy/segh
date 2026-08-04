package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dceoy/segh/internal/model"
)

func TestAuditWritesGovernanceEvidence(t *testing.T) {
	dir := t.TempDir()
	installFixtureAPI(t, "")
	t.Setenv("GH_TOKEN", "test-token")
	t.Setenv("GH_HOST", "GHES.EXAMPLE")
	t.Setenv("SEGH_GITHUB_INSTALLATION_ID", "7")
	inventoryPath := filepath.Join(dir, "inventory.json")
	auditPath := filepath.Join(dir, "audit.json")
	markdownPath := filepath.Join(dir, "report.md")
	var stdout, stderr bytes.Buffer
	err := Run(context.Background(), []string{
		"audit",
		"--config", writeConfig(t, false, false),
		"--inventory-output", inventoryPath,
		"--audit-output", auditPath,
		"--markdown-output", markdownPath,
	}, "test", &stdout, &stderr)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{inventoryPath, auditPath, markdownPath} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("%s was not written: %v", path, err)
		}
	}
	var inventory model.Inventory
	readJSON(t, inventoryPath, &inventory)
	if inventory.SchemaVersion != model.SchemaVersion || inventory.GitHubHost != "ghes.example" ||
		len(inventory.Repositories) != 1 {
		t.Fatalf("inventory = %#v", inventory)
	}
	var audit model.Audit
	readJSON(t, auditPath, &audit)
	if audit.SchemaVersion != model.SchemaVersion || audit.Coverage != "complete" ||
		audit.RepositoryCounts != (model.RepositoryCounts{Total: 1, Selected: 1}) ||
		audit.PolicyCounts[string(model.PolicyPass)] != 1 {
		t.Fatalf("audit = %#v", audit)
	}
}

func TestAuditReusesInventoryToWriteImmutableSourceScanManifest(t *testing.T) {
	dir := t.TempDir()
	installFixtureAPI(t, "")
	t.Setenv("GH_TOKEN", "test-token")
	t.Setenv("SEGH_GITHUB_INSTALLATION_ID", "7")
	manifestPath := filepath.Join(dir, "scan-manifest.json")
	var stdout, stderr bytes.Buffer
	err := Run(context.Background(), []string{
		"audit",
		"--config", writeConfig(t, false, true),
		"--inventory-output", filepath.Join(dir, "inventory.json"),
		"--audit-output", filepath.Join(dir, "audit.json"),
		"--markdown-output", filepath.Join(dir, "report.md"),
		"--scan-manifest", manifestPath,
	}, "test", &stdout, &stderr)
	if err != nil {
		t.Fatal(err)
	}
	var manifest model.SourceScanManifest
	readJSON(t, manifestPath, &manifest)
	if !manifest.Enabled || !manifest.Complete || len(manifest.Repositories) != 1 {
		t.Fatalf("manifest = %#v", manifest)
	}
	repository := manifest.Repositories[0]
	if repository.ID != 1 || repository.FullName != "example/repo" || repository.DefaultBranch != "main" ||
		repository.CommitSHA != strings.Repeat("a", 40) || !repository.Scheduled {
		t.Fatalf("repository = %#v", repository)
	}
}

func TestIncompleteCoveragePrecedesPolicyViolations(t *testing.T) {
	dir := t.TempDir()
	installFixtureAPI(t, "dependency_graph")
	t.Setenv("GH_TOKEN", "test-token")
	t.Setenv("SEGH_GITHUB_INSTALLATION_ID", "7")
	var stdout, stderr bytes.Buffer
	err := Run(context.Background(), []string{
		"audit",
		"--config", writeConfig(t, true, false),
		"--inventory-output", filepath.Join(dir, "inventory.json"),
		"--audit-output", filepath.Join(dir, "audit.json"),
		"--markdown-output", filepath.Join(dir, "report.md"),
	}, "test", &stdout, &stderr)
	if err == nil || ExitCode(err) != exitIncomplete {
		t.Fatalf("err=%v code=%d", err, ExitCode(err))
	}
	var audit model.Audit
	readJSON(t, filepath.Join(dir, "audit.json"), &audit)
	if audit.PolicyCounts[string(model.PolicyUnknown)] != 1 ||
		audit.PolicyCounts[string(model.PolicyFail)] != 1 ||
		audit.Coverage != "partial" {
		t.Fatalf("audit = %#v", audit)
	}
}

func TestRepositoryPermissionFailuresUseAuthenticationExitCode(t *testing.T) {
	for _, endpoint := range []string{"actions_permissions", "branch_protection", "community_profile"} {
		t.Run(endpoint, func(t *testing.T) {
			dir := t.TempDir()
			installFixtureAPI(t, endpoint)
			t.Setenv("GH_TOKEN", "test-token")
			t.Setenv("SEGH_GITHUB_INSTALLATION_ID", "7")
			var stdout, stderr bytes.Buffer
			err := Run(context.Background(), []string{
				"audit",
				"--config", writeConfig(t, false, false),
				"--inventory-output", filepath.Join(dir, "inventory.json"),
				"--audit-output", filepath.Join(dir, "audit.json"),
				"--markdown-output", filepath.Join(dir, "report.md"),
			}, "test", &stdout, &stderr)
			if err == nil || ExitCode(err) != exitAuth {
				t.Fatalf("err=%v code=%d", err, ExitCode(err))
			}
		})
	}
}

func TestAuditOutputFailureUsesRuntimeExitCode(t *testing.T) {
	dir := t.TempDir()
	inventoryPath := filepath.Join(dir, "inventory")
	if err := os.Mkdir(inventoryPath, 0o700); err != nil {
		t.Fatal(err)
	}
	installFixtureAPI(t, "")
	t.Setenv("SEGH_GITHUB_INSTALLATION_ID", "7")
	var stdout, stderr bytes.Buffer
	err := Run(context.Background(), []string{
		"audit",
		"--config", writeConfig(t, false, false),
		"--inventory-output", inventoryPath,
		"--audit-output", filepath.Join(dir, "audit.json"),
		"--markdown-output", filepath.Join(dir, "report.md"),
	}, "test", &stdout, &stderr)
	if err == nil || ExitCode(err) != exitRuntime {
		t.Fatalf("err=%v code=%d", err, ExitCode(err))
	}
}

func TestIntegratedPlanningFailuresClassifyExitCode(t *testing.T) {
	for _, test := range []struct {
		name     string
		endpoint string
		wantCode int
	}{
		{"repository not found", "commit_resolution_missing", exitIncomplete},
		{"github server error", "commit_resolution_runtime", exitRuntime},
		{"permission denied", "commit_resolution_forbidden", exitAuth},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			installFixtureAPI(t, test.endpoint)
			t.Setenv("GH_TOKEN", "test-token")
			t.Setenv("SEGH_GITHUB_INSTALLATION_ID", "7")
			var stdout, stderr bytes.Buffer
			err := Run(context.Background(), []string{
				"audit",
				"--config", writeConfig(t, false, true),
				"--inventory-output", filepath.Join(dir, "inventory.json"),
				"--audit-output", filepath.Join(dir, "audit.json"),
				"--markdown-output", filepath.Join(dir, "report.md"),
				"--scan-manifest", filepath.Join(dir, "scan-manifest.json"),
			}, "test", &stdout, &stderr)
			if err == nil || ExitCode(err) != test.wantCode {
				t.Fatalf("err=%v code=%d, want %d", err, ExitCode(err), test.wantCode)
			}
		})
	}
}
