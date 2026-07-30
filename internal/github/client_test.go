package github

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestClientUsesHostnameAndAPIVersionHeaderPerRequest(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "gh")
	body := "#!/bin/sh\nprintf '%s\\n' \"$*\" > \"$GH_TEST_ARGS\"\nprintf '%s' '[{\"id\":1,\"full_name\":\"org/repo\"}]'\n"
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
	t.Setenv("GH_HOST", "GitHub.Example")
	t.Setenv("GH_TEST_ARGS", argsPath)
	client, err := NewClient()
	if err != nil {
		t.Fatal(err)
	}
	var page []apiRepository
	if err := client.Get(context.Background(), "/orgs/org/repos?per_page=100&page=1", &page); err != nil {
		t.Fatal(err)
	}
	args, err := os.ReadFile(argsPath) // #nosec G304 -- argsPath is created inside this test's unique temporary directory.
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(
		string(args),
		"api --hostname github.example --method GET --header X-GitHub-Api-Version: 2022-11-28 /orgs/org/repos?per_page=100&page=1",
	) {
		t.Fatalf("args = %q", args)
	}
	if client.Hostname() != "github.example" {
		t.Fatalf("hostname = %q", client.Hostname())
	}
	if len(page) != 1 {
		t.Fatalf("page = %#v", page)
	}
}

func TestClientUsesGitHubCLIPaginationForOrganizationCollections(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "gh")
	body := "#!/bin/sh\nprintf '%s\\n' \"$*\" > \"$GH_TEST_ARGS\"\nprintf '%s' '[[{\"repository_id\":1}]]'\n"
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
	t.Setenv("GH_HOST", "")
	t.Setenv("GH_TEST_ARGS", argsPath)
	client, err := NewClient()
	if err != nil {
		t.Fatal(err)
	}
	var values []customPropertyRepository
	if err := client.GetAll(context.Background(), "/orgs/org/properties/values?per_page=100", &values); err != nil {
		t.Fatal(err)
	}
	args, err := os.ReadFile(argsPath) // #nosec G304 -- argsPath is created inside this test's unique temporary directory.
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(args), "--paginate --slurp /orgs/org/properties/values?per_page=100") {
		t.Fatalf("args = %q", args)
	}
	if client.Hostname() != "github.com" || len(values) != 1 {
		t.Fatalf("hostname = %q, values = %#v", client.Hostname(), values)
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
	client, err := NewClient()
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
	client, err := NewClient()
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
	client, err := NewClient()
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

func TestRetryDelayUsesRateLimitFloor(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want time.Duration
	}{
		{
			name: "ordinary transient error",
			err:  &APIError{StatusCode: http.StatusServiceUnavailable},
			want: retryBaseDelay,
		},
		{
			name: "too many requests",
			err:  &APIError{StatusCode: http.StatusTooManyRequests},
			want: rateLimitRetryDelay,
		},
		{
			name: "secondary rate limit",
			err:  &APIError{StatusCode: http.StatusForbidden, Message: "secondary rate limit"},
			want: rateLimitRetryDelay,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := retryDelay(test.err, 1); got != test.want {
				t.Fatalf("retryDelay() = %s, want %s", got, test.want)
			}
		})
	}
}

func TestClientRequiresExternalToken(t *testing.T) {
	t.Setenv("GH_TOKEN", "")
	if _, err := NewClient(); err == nil {
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
