package github

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dceoy/segh/internal/config"
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
	client, err := NewClient(cfg)
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
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	err = client.Get(context.Background(), "/missing", &struct{}{})
	state, _ := ErrorState(err)
	if state != "unsupported" {
		t.Fatalf("err = %v, state = %s", err, state)
	}
}

func TestClientRetriesTransientGitHubCLIError(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "gh")
	body := `#!/bin/sh
count=0
test ! -f "$GH_TEST_COUNT" || count=$(cat "$GH_TEST_COUNT")
count=$((count + 1))
printf '%s' "$count" > "$GH_TEST_COUNT"
if test "$count" -eq 1; then
  printf '%s' 'gh: Service Unavailable (HTTP 503)' >&2
  exit 1
fi
printf '%s' '{"ok":true}'
`
	if err := os.WriteFile(script, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	// #nosec G302 -- this temporary test fixture must be executable.
	if err := os.Chmod(script, 0o700); err != nil {
		t.Fatal(err)
	}
	countPath := filepath.Join(dir, "count")
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("GH_TOKEN", "test-token")
	t.Setenv("GH_TEST_COUNT", countPath)
	cfg := config.Default()
	cfg.Organization = "org"
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	client.wait = func(context.Context, time.Duration) error { return nil }
	var response struct {
		OK bool `json:"ok"`
	}
	if err := client.Get(context.Background(), "/transient", &response); err != nil {
		t.Fatal(err)
	}
	count, err := os.ReadFile(countPath) // #nosec G304 -- countPath is created inside this test's unique temporary directory.
	if err != nil {
		t.Fatal(err)
	}
	if string(count) != "2" || !response.OK {
		t.Fatalf("attempts = %q, response = %#v", count, response)
	}
}

func TestClientDoesNotRetryPermanentGitHubCLIError(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "gh")
	body := `#!/bin/sh
count=0
test ! -f "$GH_TEST_COUNT" || count=$(cat "$GH_TEST_COUNT")
count=$((count + 1))
printf '%s' "$count" > "$GH_TEST_COUNT"
printf '%s' 'gh: Unauthorized (HTTP 401)' >&2
exit 1
`
	if err := os.WriteFile(script, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	// #nosec G302 -- this temporary test fixture must be executable.
	if err := os.Chmod(script, 0o700); err != nil {
		t.Fatal(err)
	}
	countPath := filepath.Join(dir, "count")
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("GH_TOKEN", "test-token")
	t.Setenv("GH_TEST_COUNT", countPath)
	cfg := config.Default()
	cfg.Organization = "org"
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	client.wait = func(context.Context, time.Duration) error {
		t.Fatal("permanent failures must not wait for a retry")
		return nil
	}
	if err := client.Get(context.Background(), "/permanent", &struct{}{}); err == nil {
		t.Fatal("expected API error")
	}
	count, err := os.ReadFile(countPath) // #nosec G304 -- countPath is created inside this test's unique temporary directory.
	if err != nil {
		t.Fatal(err)
	}
	if string(count) != "1" {
		t.Fatalf("attempts = %q, want 1", count)
	}
}

func TestClientRequiresExternalToken(t *testing.T) {
	t.Setenv("GH_TOKEN", "")
	cfg := config.Default()
	cfg.Organization = "org"
	if _, err := NewClient(cfg); err == nil {
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
