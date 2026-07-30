package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Sixty-four MiB bounds a response, including a flattened paginated
// organization collection, so untrusted API data cannot exhaust memory.
const (
	maxResponseBytes    = 64 << 20
	maxAPIAttempts      = 4
	retryBaseDelay      = time.Second
	rateLimitRetryDelay = time.Minute
	githubAPIVersion    = "2022-11-28"
)

var httpStatusPattern = regexp.MustCompile(`(?i)\bHTTP ([0-9]{3})\b`)
var rateLimitPattern = regexp.MustCompile(`(?i)(rate limit|retry[- ]after|abuse detection)`)

type API interface {
	Get(context.Context, string, any) error
	GetAll(context.Context, string, any) error
	Hostname() string
}

type Client struct {
	executable string
	hostname   string
	wait       func(context.Context, time.Duration) error
}

type APIError struct {
	StatusCode int
	Message    string
}

func (e *APIError) Error() string {
	if e.StatusCode == 0 {
		return "GitHub API request failed: " + e.Message
	}
	return fmt.Sprintf("GitHub API returned %d: %s", e.StatusCode, e.Message)
}

func NewClient() (*Client, error) {
	if os.Getenv("GH_TOKEN") == "" {
		return nil, fmt.Errorf("GH_TOKEN is required")
	}
	executable, err := exec.LookPath("gh")
	if err != nil {
		return nil, fmt.Errorf("GitHub CLI is required: %w", err)
	}
	return &Client{executable: executable, hostname: effectiveHostname(), wait: waitForRetry}, nil
}

func (c *Client) Get(ctx context.Context, apiPath string, out any) error {
	return c.get(ctx, apiPath, out, false)
}

func (c *Client) GetAll(ctx context.Context, apiPath string, out any) error {
	return c.get(ctx, apiPath, out, true)
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

func (c *Client) get(ctx context.Context, apiPath string, out any, paginate bool) error {
	if !strings.HasPrefix(apiPath, "/") || strings.HasPrefix(apiPath, "//") {
		return fmt.Errorf("API path must be absolute and host-relative")
	}
	for attempt := 1; ; attempt++ {
		err := c.runOnce(ctx, apiPath, out, paginate)
		if err == nil || !retryableAPIError(err) || attempt == maxAPIAttempts {
			return err
		}
		delay := retryDelay(err, attempt)
		if err := c.wait(ctx, delay); err != nil {
			return err
		}
	}
}

func (c *Client) runOnce(ctx context.Context, apiPath string, out any, paginate bool) error {
	args := []string{
		"api",
		"--hostname", c.hostname,
		"--method", http.MethodGet,
		"--header", "X-GitHub-Api-Version: " + githubAPIVersion,
	}
	if out == nil {
		// Probe calls need only the HTTP status. In particular, dependency-graph
		// availability is checked through the SBOM endpoint; suppressing its body
		// avoids retaining an otherwise unused organization-scale document.
		args = append(args, "--silent")
	}
	if paginate {
		args = append(args, "--paginate", "--slurp")
	}
	args = append(args, apiPath)
	cmd := exec.CommandContext(ctx, c.executable, args...) // #nosec G204 -- executable is resolved with LookPath and arguments never pass through a shell.
	cmd.Env = os.Environ()
	if c.hostname != "github.com" && !strings.HasSuffix(c.hostname, ".ghe.com") {
		// gh uses GH_ENTERPRISE_TOKEN for custom hosts. Keep GH_TOKEN as segh's
		// single external credential contract and translate it only for this child.
		cmd.Env = replaceEnvironment(cmd.Env, "GH_ENTERPRISE_TOKEN", os.Getenv("GH_TOKEN"))
	}
	stdout := newBoundedBuffer(maxResponseBytes)
	stderr := newBoundedBuffer(64 << 10)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	err := cmd.Run()
	if stdout.exceeded {
		return fmt.Errorf("GitHub API response exceeds %d bytes", maxResponseBytes)
	}
	if err != nil {
		if errors.Is(ctx.Err(), context.Canceled) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return ctx.Err()
		}
		message := sanitizeCLIError(stderr.String())
		status := 0
		if matches := httpStatusPattern.FindAllStringSubmatch(message, -1); len(matches) > 0 {
			_, _ = fmt.Sscanf(matches[len(matches)-1][1], "%d", &status)
		}
		return &APIError{StatusCode: status, Message: message}
	}
	if out == nil || len(stdout.Bytes()) == 0 {
		return nil
	}
	data := stdout.Bytes()
	if paginate {
		var pages [][]json.RawMessage
		if err := json.Unmarshal(data, &pages); err != nil {
			return fmt.Errorf("decode paginated GitHub CLI response: %w", err)
		}
		items := make([]json.RawMessage, 0)
		for _, page := range pages {
			items = append(items, page...)
		}
		data, err = json.Marshal(items)
		if err != nil {
			return fmt.Errorf("flatten paginated GitHub CLI response: %w", err)
		}
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("decode GitHub CLI response: %w", err)
	}
	return nil
}

func retryableAPIError(err error) bool {
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	return apiErr.StatusCode == 0 || apiErr.StatusCode == http.StatusRequestTimeout ||
		apiErr.StatusCode == http.StatusTooManyRequests || apiErr.StatusCode >= 500 ||
		apiErr.StatusCode == http.StatusForbidden && rateLimitPattern.MatchString(apiErr.Message)
}

func retryDelay(err error, attempt int) time.Duration {
	delay := retryBaseDelay << (attempt - 1)
	var apiErr *APIError
	if errors.As(err, &apiErr) &&
		(apiErr.StatusCode == http.StatusTooManyRequests || rateLimitPattern.MatchString(apiErr.Message)) {
		return max(delay, rateLimitRetryDelay)
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

func sanitizeCLIError(message string) string {
	message = strings.TrimSpace(message)
	if token := os.Getenv("GH_TOKEN"); token != "" {
		message = strings.ReplaceAll(message, token, "[REDACTED]")
	}
	if message == "" {
		message = "gh api exited unsuccessfully"
	}
	if len(message) > 512 {
		message = message[:512]
	}
	return message
}

func replaceEnvironment(environment []string, key, value string) []string {
	prefix := key + "="
	result := make([]string, 0, len(environment)+1)
	for _, item := range environment {
		if !strings.HasPrefix(item, prefix) {
			result = append(result, item)
		}
	}
	return append(result, prefix+value)
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

type boundedBuffer struct {
	mu       sync.Mutex
	data     []byte
	limit    int
	exceeded bool
}

func newBoundedBuffer(limit int) *boundedBuffer {
	return &boundedBuffer{data: make([]byte, 0, min(limit, 4096)), limit: limit}
}

func (b *boundedBuffer) Write(data []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	remaining := b.limit - len(b.data)
	if remaining > 0 {
		b.data = append(b.data, data[:min(remaining, len(data))]...)
	}
	if len(data) > remaining {
		b.exceeded = true
	}
	return len(data), nil
}

func (b *boundedBuffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.data
}

func (b *boundedBuffer) String() string {
	return string(b.Bytes())
}
