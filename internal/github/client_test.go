package github

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dceoy/segh/internal/config"
	"github.com/dceoy/segh/internal/logging"
)

func TestClientDelegatesPaginationAndHostnameToGitHubCLI(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "gh")
	body := "#!/bin/sh\nprintf '%s\\n' \"$*\" > \"$GH_TEST_ARGS\"\nprintf '%s' '[[{\"id\":1,\"full_name\":\"org/repo\"}]]'\n"
	if err := os.WriteFile(script, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	// #nosec G302 -- this temporary test fixture must be executable.
	if err := os.Chmod(script, 0o700); err != nil {
		t.Fatal(err)
	}
	argsPath := filepath.Join(dir, "args")
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("GH_TOKEN", "test-token")
	t.Setenv("GH_TEST_ARGS", argsPath)
	cfg := config.Default()
	cfg.Organization = "org"
	cfg.GitHub.WebURL = "https://github.example"
	client, err := NewClient(cfg, logging.New(os.Stderr))
	if err != nil {
		t.Fatal(err)
	}
	var pages [][]apiRepository
	if err := client.GetPaginated(context.Background(), "/orgs/org/repos?per_page=100", &pages); err != nil {
		t.Fatal(err)
	}
	args, err := os.ReadFile(argsPath) // #nosec G304 -- argsPath is created inside this test's unique temporary directory.
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(args), "api --hostname github.example --method GET --paginate --slurp") {
		t.Fatalf("args = %q", args)
	}
	if len(pages) != 1 || len(pages[0]) != 1 {
		t.Fatalf("pages = %#v", pages)
	}
}

func TestClientMapsGitHubCLIHTTPError(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "gh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nprintf '%s' 'gh: Not Found (HTTP 404)' >&2\nexit 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// #nosec G302 -- this temporary test fixture must be executable.
	if err := os.Chmod(script, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("GH_TOKEN", "test-token")
	cfg := config.Default()
	cfg.Organization = "org"
	client, err := NewClient(cfg, logging.New(os.Stderr))
	if err != nil {
		t.Fatal(err)
	}
	err = client.Get(context.Background(), "/missing", &struct{}{})
	state, _ := ErrorState(err)
	if state != "unsupported" {
		t.Fatalf("err = %v, state = %s", err, state)
	}
}

func TestClientRequiresExternalToken(t *testing.T) {
	t.Setenv("GH_TOKEN", "")
	cfg := config.Default()
	cfg.Organization = "org"
	if _, err := NewClient(cfg, logging.New(os.Stderr)); err == nil {
		t.Fatal("expected GH_TOKEN requirement")
	}
}

func TestReplaceEnvironmentOverridesEnterpriseToken(t *testing.T) {
	environment := replaceEnvironment(
		[]string{"PATH=/bin", "GH_ENTERPRISE_TOKEN=stale", "OTHER=value"},
		"GH_ENTERPRISE_TOKEN",
		"current",
	)
	var matches []string
	for _, item := range environment {
		if strings.HasPrefix(item, "GH_ENTERPRISE_TOKEN=") {
			matches = append(matches, item)
		}
	}
	if len(matches) != 1 || matches[0] != "GH_ENTERPRISE_TOKEN=current" {
		t.Fatalf("enterprise token entries = %#v", matches)
	}
}
