package github

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dceoy/segh/internal/config"
	"github.com/dceoy/segh/internal/logging"
	"github.com/dceoy/segh/internal/model"
)

func TestClientRetriesTransientFailure(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer token" {
			t.Errorf("missing authorization")
		}
		if calls.Add(1) == 1 {
			writer.WriteHeader(http.StatusServiceUnavailable)
			_, _ = io.WriteString(writer, `{"message":"retry"}`)
			return
		}
		_, _ = io.WriteString(writer, `{"ok":true}`)
	}))
	defer server.Close()
	cfg := config.Default()
	cfg.Organization = "org"
	cfg.GitHub.APIURL = server.URL
	cfg.Execution.MaxRetries = 1
	cfg.Execution.BaseRetryDelay = time.Millisecond
	client, err := NewClient(cfg, staticToken("token"), logging.New(io.Discard))
	if err != nil {
		t.Fatal(err)
	}
	var response struct {
		OK bool `json:"ok"`
	}
	if err := client.Get(context.Background(), "/test", &response); err != nil {
		t.Fatal(err)
	}
	if !response.OK || calls.Load() != 2 {
		t.Fatalf("response=%#v calls=%d", response, calls.Load())
	}
}

func TestRetryDelayUsesPrimaryRateLimitReset(t *testing.T) {
	client := &Client{baseDelay: time.Millisecond}
	now := time.Unix(1_700_000_000, 0)
	header := http.Header{
		"X-Ratelimit-Remaining": {"0"},
		"X-Ratelimit-Reset":     {strconv.FormatInt(now.Add(90*time.Second).Unix(), 10)},
	}

	if delay := client.retryDelay(0, http.StatusForbidden, header, now); delay != 91*time.Second {
		t.Fatalf("delay = %s, want 91s", delay)
	}
}

func TestRetryDelayUsesSecondaryRateLimitMinimumWithoutHeaders(t *testing.T) {
	client := &Client{baseDelay: time.Millisecond}
	if delay := client.retryDelay(0, http.StatusTooManyRequests, nil, time.Unix(1_700_000_000, 0)); delay < time.Minute {
		t.Fatalf("delay = %s, want at least 1m", delay)
	}
}

func TestRetryableStatusRecognizesSecondaryRateLimitMessage(t *testing.T) {
	if !retryableStatus(http.StatusForbidden, nil, "You have exceeded a secondary rate limit.") {
		t.Fatal("expected a secondary rate-limit response to be retryable")
	}
}

func TestRepositoryPagination(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		page := request.URL.Query().Get("page")
		writer.Header().Set("Content-Type", "application/json")
		if page == "1" {
			_, _ = io.WriteString(writer, "["+strings.Repeat(`{"id":1,"full_name":"org/repo"},`, 99)+`{"id":100,"full_name":"org/repo-100"}]`)
			return
		}
		_, _ = io.WriteString(writer, `[{"id":101,"full_name":"org/repo-101"}]`)
	}))
	defer server.Close()
	cfg := config.Default()
	cfg.Organization = "org"
	cfg.GitHub.APIURL = server.URL
	client, err := NewClient(cfg, staticToken("token"), logging.New(io.Discard))
	if err != nil {
		t.Fatal(err)
	}
	service := InventoryService{cfg: cfg, client: client, log: logging.New(io.Discard)}
	repositories, err := service.listRepositories(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(repositories) != 101 {
		t.Fatalf("repositories = %d", len(repositories))
	}
}

func TestClientPreservesGHESBasePathAndEscapedRef(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.EscapedPath() != "/api/v3/repos/org/repo/branches/feature%2Fx" {
			t.Errorf("path = %s", request.URL.EscapedPath())
		}
		_, _ = io.WriteString(writer, `{}`)
	}))
	defer server.Close()
	cfg := config.Default()
	cfg.Organization = "org"
	cfg.GitHub.APIURL = server.URL + "/api/v3"
	client, err := NewClient(cfg, staticToken("token"), logging.New(io.Discard))
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Get(context.Background(), "/repos/org/repo/branches/"+pathEscape("feature/x"), &struct{}{}); err != nil {
		t.Fatal(err)
	}
}

func TestErrorState(t *testing.T) {
	state, _ := ErrorState(&APIError{StatusCode: 404, Message: "missing"})
	if state != string(model.Unsupported) {
		t.Fatalf("state = %s", state)
	}
	state, _ = ErrorState(&APIError{StatusCode: 403, Message: "permission"})
	if state != string(model.Unknown) {
		t.Fatalf("state = %s", state)
	}
}

func TestExclusionReasons(t *testing.T) {
	cfg := config.Default()
	cfg.Selectors.ExcludeArchived = true
	cfg.Selectors.IncludeTopics = []string{"managed"}
	service := InventoryService{cfg: cfg}
	if reason, _ := service.exclusionReason(model.Repository{Archived: true}); reason != "archived" {
		t.Fatalf("reason = %s", reason)
	}
	if reason, _ := service.exclusionReason(model.Repository{Topics: []string{"managed"}}); reason != "" {
		t.Fatalf("unexpected reason = %s", reason)
	}
}

func TestExclusionReasonCustomPropertyMismatch(t *testing.T) {
	cfg := config.Default()
	cfg.Selectors.CustomProperties = map[string]string{"team": "platform"}
	service := InventoryService{cfg: cfg}
	repo := model.Repository{CustomProperties: map[string]string{"team": "other"}}
	if reason, unknown := service.exclusionReason(repo); reason != "custom property team" || unknown {
		t.Fatalf("reason = %q unknown = %v", reason, unknown)
	}
	repo.CustomProperties = map[string]string{"team": "platform"}
	if reason, unknown := service.exclusionReason(repo); reason != "" || unknown {
		t.Fatalf("expected inclusion, got reason = %q unknown = %v", reason, unknown)
	}
}

func TestExclusionReasonDoesNotExcludeOnUnknownCustomProperties(t *testing.T) {
	cfg := config.Default()
	cfg.Selectors.CustomProperties = map[string]string{"team": "platform"}
	service := InventoryService{cfg: cfg}
	repo := model.Repository{
		Capabilities: map[string]model.Availability{"custom_properties": model.Unknown},
	}
	reason, unknown := service.exclusionReason(repo)
	if reason != "" {
		t.Fatalf("expected no exclusion when custom properties are unverifiable, got %q", reason)
	}
	if !unknown {
		t.Fatal("expected propertiesUnknown = true")
	}
}

func TestWorkflowPattern(t *testing.T) {
	content := []byte(`
steps:
  - uses: actions/checkout@0123456789012345678901234567890123456789 # v7.0.1
  - uses: owner/action@main
`)
	matches := usesPattern.FindAllSubmatch(content, -1)
	if len(matches) != 2 || string(matches[0][3]) != "v7.0.1" || !strings.EqualFold(string(matches[1][2]), "main") {
		t.Fatalf("matches = %#v", matches)
	}
}
