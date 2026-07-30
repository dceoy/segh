package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	maxResponseBytes    = 64 << 20
	maxErrorBytes       = 64 << 10
	maxAPIAttempts      = 4
	retryBaseDelay      = time.Second
	rateLimitRetryDelay = time.Minute
	githubAPIVersion    = "2022-11-28"
)

type API interface {
	Get(context.Context, string, any) error
	Hostname() string
}

type Client struct {
	httpClient    *http.Client
	baseURL       string
	hostname      string
	token         string
	responseLimit int64
	wait          func(context.Context, time.Duration) error
}

type APIError struct {
	StatusCode int
	Message    string
	rateLimit  bool
	retryAfter time.Duration
}

func (e *APIError) Error() string {
	if e.StatusCode == 0 {
		return "GitHub API request failed: " + e.Message
	}
	return fmt.Sprintf("GitHub API returned %d: %s", e.StatusCode, e.Message)
}

func NewClient() (*Client, error) {
	token := os.Getenv("GH_TOKEN")
	if token == "" {
		return nil, fmt.Errorf("GH_TOKEN is required")
	}
	hostname := effectiveHostname()
	baseURL, err := apiBaseURL(hostname)
	if err != nil {
		return nil, err
	}
	httpClient := &http.Client{
		Transport: http.DefaultTransport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return &Client{
		httpClient:    httpClient,
		baseURL:       baseURL,
		hostname:      hostname,
		token:         token,
		responseLimit: maxResponseBytes,
		wait:          waitForRetry,
	}, nil
}

func (c *Client) Get(ctx context.Context, apiPath string, out any) error {
	if !strings.HasPrefix(apiPath, "/") || strings.HasPrefix(apiPath, "//") {
		return fmt.Errorf("API path must be absolute and host-relative")
	}
	if _, err := url.ParseRequestURI(apiPath); err != nil {
		return fmt.Errorf("invalid API path: %w", err)
	}
	for attempt := 1; ; attempt++ {
		err := c.runOnce(ctx, apiPath, out)
		if err == nil || !retryableAPIError(err) || attempt == maxAPIAttempts {
			return err
		}
		if err := c.wait(ctx, retryDelay(err, attempt)); err != nil {
			return err
		}
	}
}

func (c *Client) Hostname() string {
	return c.hostname
}

func effectiveHostname() string {
	hostname := strings.TrimSpace(os.Getenv("GH_HOST"))
	if hostname == "" {
		return "github.com"
	}
	return strings.ToLower(hostname)
}

func apiBaseURL(hostname string) (string, error) {
	parsed, err := url.Parse("https://" + hostname)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Path != "" ||
		parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("GH_HOST must be a hostname, optionally with a port")
	}
	host := parsed.Hostname()
	port := parsed.Port()
	switch {
	case host == "github.com":
		host = "api.github.com"
	case strings.HasSuffix(host, ".ghe.com"):
		host = "api." + strings.TrimPrefix(host, "api.")
	default:
		if port != "" {
			host = net.JoinHostPort(host, port)
		} else if strings.Contains(host, ":") {
			host = "[" + host + "]"
		}
		return "https://" + host + "/api/v3", nil
	}
	if port != "" {
		host = net.JoinHostPort(host, port)
	}
	return "https://" + host, nil
}

func (c *Client) runOnce(ctx context.Context, apiPath string, out any) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+apiPath, nil)
	if err != nil {
		return fmt.Errorf("build GitHub API request: %w", err)
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("Authorization", "Bearer "+c.token)
	request.Header.Set("User-Agent", "segh")
	request.Header.Set("X-GitHub-Api-Version", githubAPIVersion)
	response, err := c.httpClient.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return &APIError{Message: sanitizeAPIMessage(err.Error(), c.token)}
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return apiErrorFromResponse(response, c.token)
	}
	if out == nil {
		size, err := io.Copy(io.Discard, io.LimitReader(response.Body, c.responseLimit+1))
		if err != nil {
			return fmt.Errorf("read GitHub API response: %w", err)
		}
		if size > c.responseLimit {
			return fmt.Errorf("GitHub API response exceeds %d bytes", c.responseLimit)
		}
		return nil
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, c.responseLimit+1))
	if err != nil {
		return fmt.Errorf("read GitHub API response: %w", err)
	}
	if int64(len(data)) > c.responseLimit {
		return fmt.Errorf("GitHub API response exceeds %d bytes", c.responseLimit)
	}
	if len(data) == 0 {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("decode GitHub API response: %w", err)
	}
	return nil
}

func apiErrorFromResponse(response *http.Response, token string) error {
	data, _ := io.ReadAll(io.LimitReader(response.Body, maxErrorBytes))
	message := strings.TrimSpace(string(data))
	var body struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(data, &body) == nil && body.Message != "" {
		message = body.Message
	}
	message = sanitizeAPIMessage(message, token)
	rateLimited := response.StatusCode == http.StatusTooManyRequests ||
		response.Header.Get("X-RateLimit-Remaining") == "0" ||
		strings.Contains(strings.ToLower(message), "rate limit") ||
		strings.Contains(strings.ToLower(message), "abuse detection")
	return &APIError{
		StatusCode: response.StatusCode,
		Message:    message,
		rateLimit:  rateLimited,
		retryAfter: responseRetryDelay(response),
	}
}

func responseRetryDelay(response *http.Response) time.Duration {
	if seconds, err := strconv.Atoi(response.Header.Get("Retry-After")); err == nil && seconds > 0 {
		return time.Duration(seconds) * time.Second
	}
	if reset, err := strconv.ParseInt(response.Header.Get("X-RateLimit-Reset"), 10, 64); err == nil {
		return max(0, time.Until(time.Unix(reset, 0)))
	}
	return 0
}

func retryableAPIError(err error) bool {
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	return apiErr.StatusCode == 0 || apiErr.StatusCode == http.StatusRequestTimeout ||
		apiErr.StatusCode == http.StatusTooManyRequests || apiErr.StatusCode >= 500 ||
		apiErr.StatusCode == http.StatusForbidden && apiErr.rateLimit
}

func retryDelay(err error, attempt int) time.Duration {
	delay := retryBaseDelay << (attempt - 1)
	var apiErr *APIError
	if errors.As(err, &apiErr) && apiErr.rateLimit {
		return max(delay, rateLimitRetryDelay, apiErr.retryAfter)
	}
	return delay
}

func waitForRetry(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func sanitizeAPIMessage(message, token string) string {
	message = strings.TrimSpace(message)
	if token != "" {
		message = strings.ReplaceAll(message, token, "[REDACTED]")
	}
	if message == "" {
		message = "request failed"
	}
	if len(message) > 512 {
		message = message[:512]
	}
	return message
}

func ErrorState(err error) (state string, reason string) {
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		return "unknown", "request failed"
	}
	switch apiErr.StatusCode {
	case http.StatusNotFound, http.StatusGone, http.StatusNotImplemented:
		return "unsupported", apiErr.Message
	default:
		return "unknown", apiErr.Message
	}
}
