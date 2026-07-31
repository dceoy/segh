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
	installFixtureAPI(t, "")
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
			installFixtureAPI(t, test.forbiddenEndpoint)
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

func TestRepositoryPermissionFailuresUseAuthenticationExitCode(t *testing.T) {
	for _, test := range []struct {
		name              string
		forbiddenEndpoint string
	}{
		{"actions", "actions_permissions"},
		{"administration", "branch_protection"},
		{"contents", "community_profile"},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			installFixtureAPI(t, test.forbiddenEndpoint)
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

func installFixtureAPI(t *testing.T, forbiddenEndpoint string) {
	t.Helper()
	previous := newGitHubAPI
	newGitHubAPI = func() (gh.API, error) {
		return fixtureAPI{forbiddenEndpoint: forbiddenEndpoint}, nil
	}
	t.Cleanup(func() { newGitHubAPI = previous })
}

type fixtureAPI struct {
	forbiddenEndpoint string
}

func (fixtureAPI) Hostname() string {
	return "ghes.example"
}

func (f fixtureAPI) Get(_ context.Context, apiPath string, out any) error {
	var data string
	switch {
	case strings.Contains(apiPath, "/orgs/example/installations?"):
		data = `{"installations":[{"id":7,"repository_selection":"all","account":{"login":"example"}}]}`
	case strings.Contains(apiPath, "/installation/repositories?"):
		data = `{"total_count":1,"repositories":[{"full_name":"example/repo"}]}`
	case strings.Contains(apiPath, "/orgs/example/repos?"):
		data = `[{"id":1,"full_name":"example/repo","default_branch":"main"}]`
	case strings.Contains(apiPath, "/orgs/example/properties/values?"):
		if f.forbiddenEndpoint == "custom_properties" {
			return &gh.APIError{StatusCode: 403, Message: "forbidden"}
		}
		data = `[{"repository_id":1,"repository_full_name":"example/repo","properties":[]}]`
	case strings.HasSuffix(apiPath, "/actions/permissions/workflow"):
		data = `{"default_workflow_permissions":"read"}`
	case strings.HasSuffix(apiPath, "/actions/permissions/fork-pr-contributor-approval"):
		data = `{"approval_policy":"all_external_contributors"}`
	case strings.HasSuffix(apiPath, "/actions/permissions"):
		if f.forbiddenEndpoint == "actions_permissions" {
			return &gh.APIError{StatusCode: 403, Message: "forbidden"}
		}
		data = `{"enabled":true,"allowed_actions":"all","sha_pinning_required":true}`
	case strings.HasSuffix(apiPath, "/dependency-graph/sbom"):
		if f.forbiddenEndpoint == "dependency_graph" {
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
		if f.forbiddenEndpoint == "branch_protection" {
			return &gh.APIError{StatusCode: 403, Message: "forbidden"}
		}
		return &gh.APIError{StatusCode: 404, Message: "not found"}
	case strings.HasSuffix(apiPath, "/community/profile"):
		if f.forbiddenEndpoint == "community_profile" {
			return &gh.APIError{StatusCode: 403, Message: "forbidden"}
		}
		data = `{"files":{"security":{}}}`
	default:
		return &gh.APIError{StatusCode: 404, Message: "not found"}
	}
	if out == nil || data == "" {
		return nil
	}
	if err := json.Unmarshal([]byte(data), out); err != nil {
		return err
	}
	return nil
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
