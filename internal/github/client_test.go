package github

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestClientSendsAuthenticatedVersionedRequest(t *testing.T) {
	client := newTestClient(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.RequestURI() != "/orgs/org/repos?per_page=100&page=1" {
			t.Errorf("request URI = %q", request.URL.RequestURI())
		}
		if got := request.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Errorf("Authorization = %q", got)
		}
		if got := request.Header.Get("X-GitHub-Api-Version"); got != githubAPIVersion {
			t.Errorf("X-GitHub-Api-Version = %q", got)
		}
		_, _ = io.WriteString(writer, `[{"id":1,"full_name":"org/repo"}]`)
	}), "github.example")
	var repositories []apiRepository
	if err := client.Get(
		context.Background(), "/orgs/org/repos?per_page=100&page=1", &repositories,
	); err != nil {
		t.Fatal(err)
	}
	if client.Hostname() != "github.example" || len(repositories) != 1 {
		t.Fatalf("hostname = %q, repositories = %#v", client.Hostname(), repositories)
	}
}

func TestAPIBaseURLSupportsGitHubAndEnterpriseHosts(t *testing.T) {
	tests := []struct {
		host string
		want string
	}{
		{"github.com", "https://api.github.com"},
		{"octocorp.ghe.com", "https://api.octocorp.ghe.com"},
		{"api.octocorp.ghe.com", "https://api.octocorp.ghe.com"},
		{"github.example", "https://github.example/api/v3"},
		{"github.example:8443", "https://github.example:8443/api/v3"},
		{"[2001:db8::1]", "https://[2001:db8::1]/api/v3"},
	}
	for _, test := range tests {
		t.Run(test.host, func(t *testing.T) {
			got, err := apiBaseURL(test.host)
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("apiBaseURL() = %q, want %q", got, test.want)
			}
		})
	}
	for _, invalid := range []string{"https://github.example", "github.example/path", "user@github.example"} {
		if _, err := apiBaseURL(invalid); err == nil {
			t.Errorf("apiBaseURL(%q) succeeded", invalid)
		}
	}
}

func TestClientSuppressesAndBoundsUnusedResponseBodies(t *testing.T) {
	client := newTestClient(t, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(writer, strings.Repeat("x", 17))
	}), "github.com")
	client.responseLimit = 16
	err := client.Get(context.Background(), "/large", nil)
	if err == nil || !strings.Contains(err.Error(), "exceeds 16 bytes") {
		t.Fatalf("err = %v", err)
	}
}

func TestClientMapsAndSanitizesHTTPError(t *testing.T) {
	client := newTestClient(t, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(writer, `{"message":"missing test-token"}`)
	}), "github.com")
	err := client.Get(context.Background(), "/missing", &struct{}{})
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusNotFound {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(err.Error(), "test-token") || !strings.Contains(err.Error(), "[REDACTED]") {
		t.Fatalf("error was not sanitized: %v", err)
	}
	state, _ := ErrorState(err)
	if state != "unsupported" {
		t.Fatalf("state = %q", state)
	}
}

func TestClientRetriesTransientErrors(t *testing.T) {
	var requests atomic.Int32
	client := newTestClient(t, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		if requests.Add(1) == 1 {
			writer.WriteHeader(http.StatusServiceUnavailable)
			_, _ = io.WriteString(writer, `{"message":"temporarily unavailable"}`)
			return
		}
		_, _ = io.WriteString(writer, `{"ok":true}`)
	}), "github.com")
	client.wait = func(context.Context, time.Duration) error { return nil }
	var response struct {
		OK bool `json:"ok"`
	}
	if err := client.Get(context.Background(), "/transient", &response); err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 2 || !response.OK {
		t.Fatalf("requests = %d, response = %#v", requests.Load(), response)
	}
}

func TestClientDoesNotRetryPermanentErrors(t *testing.T) {
	var requests atomic.Int32
	client := newTestClient(t, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		writer.WriteHeader(http.StatusUnauthorized)
	}), "github.com")
	client.wait = func(context.Context, time.Duration) error {
		t.Fatal("permanent failures must not wait")
		return nil
	}
	if err := client.Get(context.Background(), "/permanent", &struct{}{}); err == nil {
		t.Fatal("expected API error")
	}
	if requests.Load() != 1 {
		t.Fatalf("requests = %d", requests.Load())
	}
}

func TestRetryDelayUsesRateLimitFloorAndServerHint(t *testing.T) {
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
			name: "rate limit floor",
			err:  &APIError{StatusCode: http.StatusTooManyRequests, rateLimit: true},
			want: rateLimitRetryDelay,
		},
		{
			name: "server retry hint",
			err: &APIError{
				StatusCode: http.StatusForbidden, rateLimit: true, retryAfter: 2 * rateLimitRetryDelay,
			},
			want: 2 * rateLimitRetryDelay,
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

func TestClientHonorsContextCancellation(t *testing.T) {
	client := newTestClient(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("canceled request reached the server")
	}), "github.com")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := client.Get(ctx, "/canceled", &struct{}{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
}

func TestClientRequiresExternalToken(t *testing.T) {
	t.Setenv("GH_TOKEN", "")
	if _, err := NewClient(); err == nil {
		t.Fatal("expected GH_TOKEN requirement")
	}
}

func newTestClient(t *testing.T, handler http.Handler, hostname string) *Client {
	t.Helper()
	return &Client{
		httpClient: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			if err := request.Context().Err(); err != nil {
				return nil, err
			}
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			return recorder.Result(), nil
		})},
		baseURL:       "https://api.github.test",
		hostname:      hostname,
		token:         "test-token",
		responseLimit: maxResponseBytes,
		wait:          waitForRetry,
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestResponseRetryDelay(t *testing.T) {
	reset := time.Now().Add(10 * time.Minute).Unix()
	response := &http.Response{Header: http.Header{"X-Ratelimit-Reset": {time.Unix(reset, 0).Format(time.RFC3339)}}}
	if got := responseRetryDelay(response); got != 0 {
		t.Fatalf("invalid reset delay = %s", got)
	}
	response.Header.Set("Retry-After", "12")
	if got := responseRetryDelay(response); got != 12*time.Second {
		t.Fatalf("Retry-After delay = %s", got)
	}
}

func TestAPIErrorClassification(t *testing.T) {
	tests := map[int]string{
		http.StatusNotFound:       "unsupported",
		http.StatusGone:           "unsupported",
		http.StatusNotImplemented: "unsupported",
		http.StatusForbidden:      "unknown",
	}
	for status, want := range tests {
		state, _ := ErrorState(&APIError{StatusCode: status, Message: "fixture"})
		if !reflect.DeepEqual(state, want) {
			t.Errorf("status %d state = %q, want %q", status, state, want)
		}
	}
}
