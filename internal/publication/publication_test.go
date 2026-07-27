package publication

import (
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dceoy/segh/internal/config"
	gh "github.com/dceoy/segh/internal/github"
	"github.com/dceoy/segh/internal/logging"
	"github.com/dceoy/segh/internal/model"
)

func TestUploadSuccessUsesExactContextAndPolls(t *testing.T) {
	var posted map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch {
		case request.Method == http.MethodPost:
			if err := json.NewDecoder(request.Body).Decode(&posted); err != nil {
				t.Errorf("decode payload: %v", err)
			}
			writer.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(writer, `{"id":"123","url":"https://example.test/status"}`)
		case strings.HasSuffix(request.URL.Path, "/123"):
			_, _ = io.WriteString(writer, `{"processing_status":"complete"}`)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	publisher := testPublisher(t, server.URL)
	result := publisher.Upload(context.Background(), "org/repo", "zizmor", "segh/zizmor",
		strings.Repeat("a", 40), "refs/heads/main", sarifFixture(t))
	if result.Status != model.PublicationSucceeded || result.SARIFID != "123" {
		t.Fatalf("unexpected result: %#v", result)
	}
	if posted["commit_sha"] != strings.Repeat("a", 40) || posted["ref"] != "refs/heads/main" || posted["category"] != "segh/zizmor" {
		t.Fatalf("mismatched context: %#v", posted)
	}
	compressed, err := base64.StdEncoding.DecodeString(posted["sarif"].(string))
	if err != nil {
		t.Fatal(err)
	}
	reader, err := gzip.NewReader(strings.NewReader(string(compressed)))
	if err != nil {
		t.Fatal(err)
	}
	if data, _ := io.ReadAll(reader); !strings.Contains(string(data), `"version":"2.1.0"`) {
		t.Fatalf("unexpected SARIF payload: %s", data)
	}
}

func TestUploadRejectedUnsupportedAndAsyncFailure(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
		want   model.PublicationStatus
	}{
		{"rejected", http.StatusForbidden, `{"message":"forbidden"}`, model.PublicationRejected},
		{"unsupported", http.StatusNotFound, `{"message":"not found"}`, model.PublicationUnsupported},
		{"async failure", http.StatusAccepted, `{"id":"bad"}`, model.PublicationFailed},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				if request.Method == http.MethodPost {
					writer.WriteHeader(test.status)
					_, _ = io.WriteString(writer, test.body)
					return
				}
				_, _ = io.WriteString(writer, `{"processing_status":"failed","errors":["details not exposed"]}`)
			}))
			defer server.Close()
			publisher := testPublisher(t, server.URL)
			result := publisher.Upload(context.Background(), "org/repo", "trivy", "segh/trivy",
				strings.Repeat("b", 40), "refs/heads/main", sarifFixture(t))
			if result.Status != test.want {
				t.Fatalf("status = %s, want %s (%#v)", result.Status, test.want, result)
			}
		})
	}
}

func TestUploadRejectsMismatchedContextBeforeRequest(t *testing.T) {
	publisher := &Publisher{}
	result := publisher.Upload(context.Background(), "../repo", "trivy", "bad category!",
		"short", "main", "missing")
	if result.Status != model.PublicationRejected {
		t.Fatalf("status = %s", result.Status)
	}
}

func testPublisher(t *testing.T, serverURL string) *Publisher {
	t.Helper()
	cfg := config.Default()
	cfg.Organization = "org"
	cfg.GitHub.APIURL = serverURL
	cfg.Execution.MaxRetries = 0
	client, err := gh.NewClient(cfg, testToken("token"), logging.New(io.Discard))
	if err != nil {
		t.Fatal(err)
	}
	return &Publisher{client: client, pollTimeout: time.Second}
}

type testToken string

func (token testToken) Token(context.Context) (string, error) { return string(token), nil }

func sarifFixture(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "result.sarif")
	if err := os.WriteFile(path, []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"test"}},"results":[]}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
