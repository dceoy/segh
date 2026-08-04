package cli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	gh "github.com/dceoy/segh/internal/github"
)

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
	case strings.Contains(apiPath, "/commits/"):
		switch f.forbiddenEndpoint {
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
