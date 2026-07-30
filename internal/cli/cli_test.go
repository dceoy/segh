package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dceoy/segh/internal/config"
	"github.com/dceoy/segh/internal/model"
	"github.com/dceoy/segh/internal/policy"
)

func TestHelpAndVersionDoNotRequireConfiguration(t *testing.T) {
	for _, test := range []struct {
		args []string
		want string
	}{
		{[]string{"--help"}, "GitHub security governance audit"},
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

func TestRemovedCommandsAndFlagsAreRejected(t *testing.T) {
	for _, args := range [][]string{
		{"validate"},
		{"inventory"},
		{"report"},
		{"--config", "segh.yaml", "audit"},
		{"audit", "--github-web-url", "https://github.com"},
	} {
		var stdout, stderr bytes.Buffer
		err := Run(context.Background(), args, "test", &stdout, &stderr)
		if err == nil || ExitCode(err) != exitUsage {
			t.Fatalf("%v: err=%v code=%d", args, err, ExitCode(err))
		}
	}
}

func TestAuditValidateOnlyDoesNotRequireCredentials(t *testing.T) {
	t.Setenv("GH_TOKEN", "")
	t.Setenv("SEGH_GITHUB_INSTALLATION_ID", "")
	configPath := writeConfig(t, false, false)
	var stdout, stderr bytes.Buffer
	err := Run(context.Background(), []string{
		"audit", "--config", configPath, "--validate-only",
	}, "test", &stdout, &stderr)
	if err != nil {
		t.Fatal(err)
	}
	if stdout.String() != "configuration is valid\n" {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestAuditRequiresInstallationIDAfterConfigurationValidation(t *testing.T) {
	t.Setenv("SEGH_GITHUB_INSTALLATION_ID", "")
	var stdout, stderr bytes.Buffer
	err := Run(context.Background(), []string{
		"audit", "--config", writeConfig(t, false, false),
	}, "test", &stdout, &stderr)
	if err == nil || ExitCode(err) != exitAuth ||
		!strings.Contains(err.Error(), "SEGH_GITHUB_INSTALLATION_ID must be a positive integer") {
		t.Fatalf("err=%v code=%d", err, ExitCode(err))
	}
}

func TestAuditWritesOnlyThreeVersionFourArtifacts(t *testing.T) {
	dir := t.TempDir()
	workingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(workingDirectory); err != nil {
			t.Error(err)
		}
	})
	installFakeGitHubCLI(t, "")
	t.Setenv("GH_TOKEN", "test-token")
	t.Setenv("GH_HOST", "GHES.EXAMPLE")
	t.Setenv("SEGH_GITHUB_INSTALLATION_ID", "7")
	var stdout, stderr bytes.Buffer
	err = Run(context.Background(), []string{
		"audit",
		"--config", writeConfig(t, false, false),
	}, "test", &stdout, &stderr)
	if err != nil {
		t.Fatal(err)
	}
	resultsDir := filepath.Join(dir, "segh-results")
	for _, name := range []string{"inventory.json", "audit.json", "report.md"} {
		if _, err := os.Stat(filepath.Join(resultsDir, name)); err != nil {
			t.Fatalf("%s was not written: %v", name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(resultsDir, "report.json")); !os.IsNotExist(err) {
		t.Fatalf("report.json must not be written: %v", err)
	}
	var inventory model.Inventory
	readJSON(t, filepath.Join(resultsDir, "inventory.json"), &inventory)
	if inventory.SchemaVersion != 4 || inventory.GitHubHost != "ghes.example" ||
		inventory.Repositories[0].CustomProperties.State != model.Available {
		t.Fatalf("inventory = %#v", inventory)
	}
	var audit model.Audit
	readJSON(t, filepath.Join(resultsDir, "audit.json"), &audit)
	if audit.SchemaVersion != 4 || audit.Coverage != "complete" ||
		audit.RepositoryCounts != (model.RepositoryCounts{Total: 1, Selected: 1}) ||
		audit.PolicyCounts[string(model.PolicyPass)] != 1 {
		t.Fatalf("audit = %#v", audit)
	}
}

func TestIncompleteCoveragePrecedesPolicyViolations(t *testing.T) {
	dir := t.TempDir()
	installFakeGitHubCLI(t, "dependency_graph")
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

func TestOrganizationCollectionPermissionFailuresUseAuthenticationExitCode(t *testing.T) {
	for _, test := range []struct {
		name                 string
		forbiddenEndpoint    string
		customPropertyFilter bool
	}{
		{"custom properties", "custom_properties", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			installFakeGitHubCLI(t, test.forbiddenEndpoint)
			t.Setenv("GH_TOKEN", "test-token")
			t.Setenv("SEGH_GITHUB_INSTALLATION_ID", "7")
			var stdout, stderr bytes.Buffer
			err := Run(context.Background(), []string{
				"audit",
				"--config", writeConfig(t, false, test.customPropertyFilter),
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

func TestValidateArtifactsRejectsTamperingAndHostMismatch(t *testing.T) {
	cfg := config.Default()
	cfg.Organization = "example"
	enabled := true
	cfg.Policies.Dependencies.DependencyGraph = &enabled
	inventory := validInventory(cfg)
	audit := policy.New(cfg, time.Now()).Evaluate(inventory)
	if err := validateArtifacts(inventory, audit, cfg, "github.com"); err != nil {
		t.Fatal(err)
	}
	tampered := audit
	tampered.Results = append([]model.PolicyResult(nil), audit.Results...)
	tampered.Results[0].Evidence = "fabricated"
	if err := validateArtifacts(inventory, tampered, cfg, "github.com"); err == nil {
		t.Fatal("tampered evidence was accepted")
	}
	if err := validateArtifacts(inventory, audit, cfg, "github.example"); err == nil {
		t.Fatal("mismatched effective host was accepted")
	}
}

func writeConfig(t *testing.T, requireRuleset, customPropertyFilter bool) string {
	t.Helper()
	repositoryPolicy := ""
	if requireRuleset {
		repositoryPolicy = "\n  repository:\n    require_ruleset: true"
	}
	selectors := ""
	if customPropertyFilter {
		selectors = "selectors:\n  custom_properties:\n    tier: critical\n"
	}
	data := "version: 4\norganization: example\ninventory:\n  concurrency: 1\n  timeout: 1m\n" +
		selectors + "policies:\n  dependencies:\n    dependency_graph: true" + repositoryPolicy + "\n"
	path := filepath.Join(t.TempDir(), "segh.yaml")
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func installFakeGitHubCLI(t *testing.T, forbiddenEndpoint string) {
	t.Helper()
	dir := t.TempDir()
	script := filepath.Join(dir, "gh")
	customPropertiesResult := `printf '%s' '[[{"repository_id":1,"repository_full_name":"example/repo","properties":[]}]]'`
	if forbiddenEndpoint == "custom_properties" {
		customPropertiesResult = `printf '%s' 'gh: Forbidden (HTTP 403)' >&2; exit 1`
	}
	dependencyGraphResult := `printf '%s' '{"sbom":{}}'`
	if forbiddenEndpoint == "dependency_graph" {
		dependencyGraphResult = `printf '%s' 'gh: Forbidden (HTTP 403)' >&2; exit 1`
	}
	body := `#!/bin/sh
case "$*" in
  *"/orgs/example/installations?"*)
    printf '%s' '{"installations":[{"id":7,"repository_selection":"all","account":{"login":"example"}}]}'
    ;;
  *"/installation/repositories?"*)
    printf '%s' '{"total_count":1,"repositories":[{"full_name":"example/repo"}]}'
    ;;
  *"/orgs/example/repos?"*)
    printf '%s' '[{"id":1,"full_name":"example/repo","default_branch":"main"}]'
    ;;
  *"/orgs/example/properties/values?"*)
    ` + customPropertiesResult + `
    ;;
  *"/repos/example/repo/actions/permissions/workflow")
    printf '%s' '{"default_workflow_permissions":"read"}'
    ;;
  *"/repos/example/repo/actions/permissions/fork-pr-contributor-approval")
    printf '%s' '{"approval_policy":"all_external_contributors"}'
    ;;
  *"/repos/example/repo/actions/permissions")
    printf '%s' '{"enabled":true,"allowed_actions":"all","sha_pinning_required":true}'
    ;;
  *"/repos/example/repo/dependency-graph/sbom")
    ` + dependencyGraphResult + `
    ;;
  *"/repos/example/repo/vulnerability-alerts")
    exit 0
    ;;
  *"/repos/example/repo/automated-security-fixes")
    printf '%s' '{"enabled":true,"paused":false}'
    ;;
  *"/repos/example/repo/rules/branches/main")
    printf '%s' '[]'
    ;;
  *"/repos/example/repo/branches/main/protection")
    printf '%s' 'gh: Not Found (HTTP 404)' >&2
    exit 1
    ;;
  *"/repos/example/repo/community/profile")
    printf '%s' '{"files":{"security":{}}}'
    ;;
  *)
    printf '%s' 'gh: Not Found (HTTP 404)' >&2
    exit 1
    ;;
esac
`
	if err := os.WriteFile(script, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	// #nosec G302 -- the temporary fixture must be executable.
	if err := os.Chmod(script, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func validInventory(cfg config.Config) model.Inventory {
	return model.Inventory{
		SchemaVersion: model.SchemaVersion,
		Organization:  cfg.Organization,
		GitHubHost:    "github.com",
		GeneratedAt:   time.Now().UTC(),
		Complete:      true,
		Total:         1,
		Selected:      1,
		Repositories: []model.Repository{{
			ID: 1, FullName: "example/repository",
			DependencyGraph: model.Observed[bool]{State: model.Available, Value: true},
		}},
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
