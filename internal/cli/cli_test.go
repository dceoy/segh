package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	gh "github.com/dceoy/segh/internal/github"
	"github.com/dceoy/segh/internal/model"
)

func TestHelpAndVersion(t *testing.T) {
	for _, test := range []struct {
		args []string
		want string
	}{
		{[]string{"--help"}, "segh audit --config segh.yaml"},
		{[]string{"--version"}, "test-version"},
	} {
		var stdout, stderr bytes.Buffer
		if err := Run(context.Background(), test.args, "test-version", &stdout, &stderr); err != nil {
			t.Fatalf("%v: %v", test.args, err)
		}
		if !strings.Contains(stdout.String(), test.want) {
			t.Fatalf("%v output = %q", test.args, stdout.String())
		}
	}
}

func TestAuditValidateOnlyDoesNotRequireCredentials(t *testing.T) {
	t.Setenv("GH_TOKEN", "")
	t.Setenv("SEGH_GITHUB_INSTALLATION_ID", "")
	var stdout, stderr bytes.Buffer
	err := Run(context.Background(), []string{
		"audit", "--config", writeConfig(t, false, false), "--validate-only",
	}, "test", &stdout, &stderr)
	if err != nil || stdout.String() != "configuration is valid\n" {
		t.Fatalf("err=%v stdout=%q", err, stdout.String())
	}
}

func TestAuditCollectsInventoryOnceAndWritesManifest(t *testing.T) {
	dir := t.TempDir()
	calls := installFixtureAPI(t, "")
	t.Setenv("SEGH_GITHUB_INSTALLATION_ID", "7")
	inventoryPath := filepath.Join(dir, "inventory.json")
	auditPath := filepath.Join(dir, "audit.json")
	markdownPath := filepath.Join(dir, "report.md")
	manifestPath := filepath.Join(dir, "scan-manifest.json")
	var stdout, stderr bytes.Buffer
	err := Run(context.Background(), []string{
		"audit",
		"--config", writeConfig(t, false, true),
		"--inventory-output", inventoryPath,
		"--audit-output", auditPath,
		"--markdown-output", markdownPath,
		"--scan-manifest", manifestPath,
	}, "test", &stdout, &stderr)
	if err != nil {
		t.Fatal(err)
	}
	if calls["organization_repositories"] != 1 {
		t.Fatalf("organization repository collection calls = %d", calls["organization_repositories"])
	}
	for _, path := range []string{inventoryPath, auditPath, markdownPath, manifestPath} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("%s was not written: %v", path, err)
		}
	}
	var manifest model.SourceScanManifest
	readJSON(t, manifestPath, &manifest)
	if !manifest.Enabled || !manifest.Complete || len(manifest.Repositories) != 1 {
		t.Fatalf("manifest = %#v", manifest)
	}
	repository := manifest.Repositories[0]
	if repository.ID != 1 || repository.FullName != "example/repo" ||
		repository.DefaultBranch != "main" || repository.CommitSHA != strings.Repeat("a", 40) ||
		!repository.Scheduled {
		t.Fatalf("repository = %#v", repository)
	}
}

func TestIntegratedPlanningExitClassifications(t *testing.T) {
	for _, test := range []struct {
		name     string
		failure  string
		wantCode int
	}{
		{"unresolved default branch", "commit_resolution_missing", exitIncomplete},
		{"scanner target API runtime error", "commit_resolution_runtime", exitRuntime},
		{"inaccessible repository", "commit_resolution_forbidden", exitAuth},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			installFixtureAPI(t, test.failure)
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

func TestAuditCoveragePrecedesGovernanceFindings(t *testing.T) {
	dir := t.TempDir()
	installFixtureAPI(t, "dependency_graph")
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
}

func TestAuditReconciliationPreservesSourceScanExitClassifications(t *testing.T) {
	for _, test := range []struct {
		result   string
		wantCode int
	}{
		{"pass", exitSuccess},
		{"findings", exitFindings},
		{"incomplete", exitIncomplete},
		{"error", exitRuntime},
	} {
		t.Run(test.result, func(t *testing.T) {
			dir := t.TempDir()
			repository := model.SourceScanRepository{
				ID: 1, Owner: "example", Name: "repo", FullName: "example/repo",
				DefaultBranch: "main", CommitSHA: strings.Repeat("a", 40), Scheduled: true,
			}
			manifestPath := filepath.Join(dir, "scan-manifest.json")
			writeJSON(t, manifestPath, model.SourceScanManifest{
				SchemaVersion: model.SourceScanSchemaVersion,
				Organization:  "example", GitHubHost: "github.com", Enabled: true, Complete: true,
				Concurrency: 1, Repositories: []model.SourceScanRepository{repository},
			})
			writeJSON(t, filepath.Join(dir, "repository-scans", "repository-scan-1", "status.json"), map[string]string{
				"result": test.result, "repository-id": "1", "repository": "example/repo",
				"default-branch": "main", "commit-sha": repository.CommitSHA,
			})
			t.Setenv("GH_TOKEN", "")
			t.Setenv("SEGH_GITHUB_INSTALLATION_ID", "")
			var stdout, stderr bytes.Buffer
			err := Run(context.Background(), []string{
				"audit", "--reconcile-source-scan",
				"--scan-manifest", manifestPath,
				"--scan-results", filepath.Join(dir, "repository-scans"),
				"--scan-summary-output", filepath.Join(dir, "scan-summary.json"),
				"--scan-markdown-output", filepath.Join(dir, "scan-report.md"),
			}, "test", &stdout, &stderr)
			if ExitCode(err) != test.wantCode {
				t.Fatalf("err=%v code=%d, want %d", err, ExitCode(err), test.wantCode)
			}
		})
	}
}

func writeConfig(t *testing.T, requireRuleset, sourceScan bool) string {
	t.Helper()
	repositoryPolicy := ""
	if requireRuleset {
		repositoryPolicy = "\n  repository:\n    require_ruleset: true"
	}
	source := ""
	if sourceScan {
		source = "source_scan:\n  enabled: true\n  concurrency: 1\n"
	}
	data := "version: 5\norganization: example\ninventory:\n  concurrency: 1\n  timeout: 1m\n" + source +
		"policies:\n  dependencies:\n    dependency_graph: true" + repositoryPolicy + "\n"
	path := filepath.Join(t.TempDir(), "segh.yaml")
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func installFixtureAPI(t *testing.T, failure string) map[string]int {
	t.Helper()
	previous := newGitHubAPI
	calls := map[string]int{}
	newGitHubAPI = func() (gh.API, error) {
		return fixtureAPI{failure: failure, calls: calls}, nil
	}
	t.Cleanup(func() { newGitHubAPI = previous })
	return calls
}

type fixtureAPI struct {
	failure string
	calls   map[string]int
}

func (fixtureAPI) Hostname() string { return "ghes.example" }

func (f fixtureAPI) Get(_ context.Context, apiPath string, out any) error {
	var data string
	switch {
	case strings.Contains(apiPath, "/orgs/example/installations?"):
		data = `{"installations":[{"id":7,"repository_selection":"all","account":{"login":"example"}}]}`
	case strings.Contains(apiPath, "/installation/repositories?"):
		data = `{"total_count":1,"repositories":[{"full_name":"example/repo"}]}`
	case strings.Contains(apiPath, "/orgs/example/repos?"):
		f.calls["organization_repositories"]++
		data = `[{"id":1,"full_name":"example/repo","default_branch":"main"}]`
	case strings.HasSuffix(apiPath, "/actions/permissions/workflow"):
		data = `{"default_workflow_permissions":"read"}`
	case strings.HasSuffix(apiPath, "/actions/permissions/fork-pr-contributor-approval"):
		data = `{"approval_policy":"all_external_contributors"}`
	case strings.HasSuffix(apiPath, "/actions/permissions"):
		data = `{"enabled":true,"allowed_actions":"all","sha_pinning_required":true}`
	case strings.HasSuffix(apiPath, "/dependency-graph/sbom"):
		if f.failure == "dependency_graph" {
			return &gh.APIError{StatusCode: 400, Message: "bad request"}
		}
		data = `{"sbom":{}}`
	case strings.HasSuffix(apiPath, "/vulnerability-alerts"):
		return nil
	case strings.HasSuffix(apiPath, "/automated-security-fixes"):
		data = `{"enabled":true,"paused":false}`
	case strings.Contains(apiPath, "/rules/branches/main"):
		data = `[]`
	case strings.Contains(apiPath, "/branches/main/protection"):
		return &gh.APIError{StatusCode: 404, Message: "not found"}
	case strings.HasSuffix(apiPath, "/community/profile"):
		data = `{"files":{"security":{}}}`
	case strings.Contains(apiPath, "/commits/"):
		switch f.failure {
		case "commit_resolution_missing":
			return &gh.APIError{StatusCode: 404, Message: "not found"}
		case "commit_resolution_runtime":
			return &gh.APIError{StatusCode: 500, Message: "internal server error"}
		case "commit_resolution_forbidden":
			return &gh.APIError{StatusCode: 403, Message: "forbidden"}
		default:
			data = `{"sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`
		}
	default:
		return &gh.APIError{StatusCode: 404, Message: "not found"}
	}
	if out == nil || data == "" {
		return nil
	}
	return json.Unmarshal([]byte(data), out)
}

func writeJSON(t *testing.T, path string, value any) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func readJSON(t *testing.T, path string, value any) {
	t.Helper()
	data, err := os.ReadFile(path) // #nosec G304 -- the path is created inside the test directory.
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, value); err != nil {
		t.Fatal(err)
	}
}
