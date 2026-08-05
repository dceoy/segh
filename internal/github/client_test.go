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

func TestNewClientUsesGitHubDotComEndpoint(t *testing.T) {
	t.Setenv("GH_TOKEN", "test-token")
	client, err := NewClient()
	if err != nil {
		t.Fatal(err)
	}
	client.httpClient.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if got, want := request.URL.String(), githubAPIBaseURL+"/meta"; got != want {
			t.Fatalf("request URL = %q, want %q", got, want)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(`{"ok":true}`)),
		}, nil
	})
	var response struct {
		OK bool `json:"ok"`
	}
	if err := client.Get(context.Background(), "/meta", &response); err != nil {
		t.Fatal(err)
	}
	if !response.OK || client.Hostname() != githubHostname {
		t.Fatalf("response = %#v, hostname = %q", response, client.Hostname())
	}
}

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
	}))
	var repositories []apiRepository
	if err := client.Get(
		context.Background(), "/orgs/org/repos?per_page=100&page=1", &repositories,
	); err != nil {
		t.Fatal(err)
	}
	if client.Hostname() != githubHostname || len(repositories) != 1 {
		t.Fatalf("hostname = %q, repositories = %#v", client.Hostname(), repositories)
	}
}

func TestClientRejectsMalformedRequestPaths(t *testing.T) {
	client := newTestClient(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("malformed request reached transport")
	}))
	for _, apiPath := range []string{"relative", "//other.example/path", "/bad%zz"} {
		if err := client.Get(context.Background(), apiPath, &struct{}{}); err == nil {
			t.Errorf("Get(%q) succeeded", apiPath)
		}
	}
}

func TestClientBoundsDecodedResponseBodies(t *testing.T) {
	client := newTestClient(t, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(writer, strings.Repeat("x", 17))
	}))
	client.responseLimit = 16
	var out []byte
	err := client.Get(context.Background(), "/large", &out)
	if err == nil || !strings.Contains(err.Error(), "exceeds 16 bytes") {
		t.Fatalf("err = %v", err)
	}
}

func TestClientMapsAndSanitizesHTTPError(t *testing.T) {
	client := newTestClient(t, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(writer, `{"message":"missing test-token"}`)
	}))
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

func TestClientBoundsErrorBodies(t *testing.T) {
	client := newTestClient(t, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(writer, strings.Repeat("x", maxErrorBytes+1024))
	}))
	err := client.Get(context.Background(), "/large-error", &struct{}{})
	if err == nil || len(err.Error()) > 600 {
		t.Fatalf("unbounded error = %v", err)
	}
}

func TestClientRetriesRetryableHTTPResponses(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		headers http.Header
		body    string
	}{
		{name: "request timeout", status: http.StatusRequestTimeout},
		{name: "too many requests", status: http.StatusTooManyRequests},
		{name: "transient server failure", status: http.StatusBadGateway},
		{
			name: "primary rate limit", status: http.StatusForbidden,
			headers: http.Header{"X-RateLimit-Remaining": {"0"}},
		},
		{
			name: "secondary rate limit", status: http.StatusForbidden,
			body: `{"message":"secondary rate limit exceeded"}`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var requests atomic.Int32
			client := newTestClient(t, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				if requests.Add(1) == 1 {
					for name, values := range test.headers {
						for _, value := range values {
							writer.Header().Add(name, value)
						}
					}
					writer.WriteHeader(test.status)
					_, _ = io.WriteString(writer, test.body)
					return
				}
				_, _ = io.WriteString(writer, `{"ok":true}`)
			}))
			client.wait = func(context.Context, time.Duration) error { return nil }
			var response struct {
				OK bool `json:"ok"`
			}
			if err := client.Get(context.Background(), "/retryable", &response); err != nil {
				t.Fatal(err)
			}
			if requests.Load() != 2 || !response.OK {
				t.Fatalf("requests = %d, response = %#v", requests.Load(), response)
			}
		})
	}
}

func TestClientRetriesBodyReadFailureForDecodedResponse(t *testing.T) {
	var attempts atomic.Int32
	client := &Client{
		httpClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			if attempts.Add(1) == 1 {
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     make(http.Header),
					Body:       &partialThenErrorBody{data: []byte(`{"o`)},
				}, nil
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(`{"ok":true}`)),
			}, nil
		})},
		baseURL:       "https://api.github.test",
		token:         "test-token",
		responseLimit: maxResponseBytes,
		wait:          func(context.Context, time.Duration) error { return nil },
	}
	var response struct {
		OK bool `json:"ok"`
	}
	if err := client.Get(context.Background(), "/flaky-body", &response); err != nil {
		t.Fatal(err)
	}
	if attempts.Load() != 2 || !response.OK {
		t.Fatalf("attempts = %d, response = %#v", attempts.Load(), response)
	}
}

// partialThenErrorBody simulates a connection reset after some bytes have
// already been delivered: the first Read returns data with no error, and
// every subsequent Read fails, so callers cannot mistake it for io.EOF.
type partialThenErrorBody struct {
	data []byte
	sent bool
}

func (r *partialThenErrorBody) Read(p []byte) (int, error) {
	if !r.sent {
		r.sent = true
		return copy(p, r.data), nil
	}
	return 0, errors.New("connection reset by peer")
}

func (r *partialThenErrorBody) Close() error { return nil }

func TestClientDoesNotRetryPermanentErrors(t *testing.T) {
	var requests atomic.Int32
	client := newTestClient(t, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		writer.WriteHeader(http.StatusUnauthorized)
	}))
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
	}))
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

func newTestClient(t *testing.T, handler http.Handler) *Client {
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

func TestClientRetriesMalformedResponseBodyAndSurfacesRetryableAPIError(t *testing.T) {
	var requests atomic.Int32
	client := newTestClient(t, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_, _ = io.WriteString(writer, `{"ok": tru`) // truncated, invalid JSON on every attempt
	}))
	client.wait = func(context.Context, time.Duration) error { return nil }
	var response struct {
		OK bool `json:"ok"`
	}
	err := client.Get(context.Background(), "/malformed", &response)
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != 0 {
		t.Fatalf("err = %v", err)
	}
	if requests.Load() != maxAPIAttempts {
		t.Fatalf("requests = %d, want %d retries for a malformed response body", requests.Load(), maxAPIAttempts)
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
