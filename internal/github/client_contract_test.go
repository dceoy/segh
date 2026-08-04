package github

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestClientRejectsRedirects(t *testing.T) {
	t.Setenv("GH_TOKEN", "test-token")
	t.Setenv("GH_HOST", "github.com")
	client, err := NewClient()
	if err != nil {
		t.Fatal(err)
	}

	var redirected atomic.Bool
	destination := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		redirected.Store(true)
	}))
	defer destination.Close()
	source := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, destination.URL+"/credential-target", http.StatusFound)
	}))
	defer source.Close()

	client.baseURL = source.URL
	client.wait = func(context.Context, time.Duration) error { return nil }
	err = client.Get(context.Background(), "/redirect", &struct{}{})
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusFound {
		t.Fatalf("err = %v, want 302 APIError", err)
	}
	if redirected.Load() {
		t.Fatal("redirect target was requested")
	}
}

func TestClientStopsAfterMaximumRetriesAndUsesExponentialBackoff(t *testing.T) {
	var requests atomic.Int32
	client := newTestClient(t, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		writer.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(writer, `{"message":"still unavailable"}`)
	}), "github.com")
	var delays []time.Duration
	client.wait = func(_ context.Context, delay time.Duration) error {
		delays = append(delays, delay)
		return nil
	}

	err := client.Get(context.Background(), "/persistent-transient", &struct{}{})
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("err = %v, want terminal 503 APIError", err)
	}
	if requests.Load() != maxAPIAttempts {
		t.Fatalf("requests = %d, want %d", requests.Load(), maxAPIAttempts)
	}
	wantDelays := []time.Duration{retryBaseDelay, 2 * retryBaseDelay, 4 * retryBaseDelay}
	if len(delays) != len(wantDelays) {
		t.Fatalf("delays = %v, want %v", delays, wantDelays)
	}
	for i, want := range wantDelays {
		if delays[i] != want {
			t.Fatalf("delays = %v, want %v", delays, wantDelays)
		}
	}
}

func TestClientCancellationStopsRetryWait(t *testing.T) {
	var requests atomic.Int32
	client := newTestClient(t, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		writer.WriteHeader(http.StatusServiceUnavailable)
	}), "github.com")
	ctx, cancel := context.WithCancel(context.Background())
	client.wait = func(ctx context.Context, _ time.Duration) error {
		cancel()
		<-ctx.Done()
		return ctx.Err()
	}

	err := client.Get(ctx, "/cancel-wait", &struct{}{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if requests.Load() != 1 {
		t.Fatalf("requests = %d, want 1", requests.Load())
	}
}

func TestClientRedactsTokenFromTransportErrors(t *testing.T) {
	client := &Client{
		httpClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("connection reset for test-token")
		})},
		baseURL:       "https://api.github.test",
		hostname:      "github.com",
		token:         "test-token",
		responseLimit: maxResponseBytes,
		wait:          func(context.Context, time.Duration) error { return nil },
	}

	err := client.Get(context.Background(), "/transport", &struct{}{})
	if err == nil || strings.Contains(err.Error(), "test-token") || !strings.Contains(err.Error(), "[REDACTED]") {
		t.Fatalf("error was not redacted: %v", err)
	}
}

func TestClientAcceptsEmptyResponse(t *testing.T) {
	client := newTestClient(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), "github.com")
	var response struct {
		OK bool `json:"ok"`
	}
	if err := client.Get(context.Background(), "/empty", &response); err != nil {
		t.Fatalf("err = %v", err)
	}
}

func TestClientPropagatesDeadlineExceededWithoutRetry(t *testing.T) {
	var requests atomic.Int32
	client := &Client{
		httpClient: &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			requests.Add(1)
			<-request.Context().Done()
			return nil, request.Context().Err()
		})},
		baseURL:       "https://api.github.test",
		hostname:      "github.com",
		token:         "test-token",
		responseLimit: maxResponseBytes,
		wait: func(context.Context, time.Duration) error {
			t.Fatal("deadline failure waited for a retry")
			return nil
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	err := client.Get(ctx, "/timeout", &struct{}{})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want context.DeadlineExceeded", err)
	}
	if requests.Load() != 1 {
		t.Fatalf("requests = %d, want 1", requests.Load())
	}
}
