package github

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/dceoy/segh/internal/config"
	"github.com/dceoy/segh/internal/logging"
)

const maxResponseBytes = 16 << 20

type TokenProvider interface {
	Token(context.Context) (string, error)
}

type Client struct {
	baseURL    *url.URL
	http       *http.Client
	tokens     TokenProvider
	maxRetries int
	baseDelay  time.Duration
	log        *logging.Logger
}

type APIError struct {
	StatusCode int
	Message    string
	RequestID  string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("GitHub API returned %d: %s (request ID %s)", e.StatusCode, e.Message, e.RequestID)
}

func NewClient(cfg config.Config, tokens TokenProvider, log *logging.Logger) (*Client, error) {
	baseURL, err := url.Parse(strings.TrimRight(cfg.GitHub.APIURL, "/") + "/")
	if err != nil {
		return nil, fmt.Errorf("parse GitHub API URL: %w", err)
	}
	return &Client{
		baseURL:    baseURL,
		http:       &http.Client{Timeout: cfg.Execution.APITimeout},
		tokens:     tokens,
		maxRetries: cfg.Execution.MaxRetries,
		baseDelay:  cfg.Execution.BaseRetryDelay,
		log:        log,
	}, nil
}

func (c *Client) Get(ctx context.Context, path string, out any) error {
	return c.Do(ctx, http.MethodGet, path, nil, out)
}

func (c *Client) Post(ctx context.Context, path string, body, out any) error {
	return c.Do(ctx, http.MethodPost, path, body, out)
}

func (c *Client) Do(ctx context.Context, method, path string, body, out any) error {
	if !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") {
		return fmt.Errorf("API path must be absolute and host-relative")
	}
	parsed, err := url.Parse(path)
	if err != nil {
		return fmt.Errorf("parse API path: %w", err)
	}
	endpoint := *c.baseURL
	endpoint.Path = strings.TrimRight(c.baseURL.Path, "/") + parsed.Path
	if parsed.RawPath != "" {
		endpoint.RawPath = strings.TrimRight(c.baseURL.EscapedPath(), "/") + parsed.EscapedPath()
	}
	endpoint.RawQuery = parsed.RawQuery

	var encoded []byte
	if body != nil {
		encoded, err = json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encode API request: %w", err)
		}
	}

	for attempt := 0; ; attempt++ {
		token, err := c.tokens.Token(ctx)
		if err != nil {
			return err
		}
		req, err := http.NewRequestWithContext(ctx, method, endpoint.String(), bytes.NewReader(encoded))
		if err != nil {
			return fmt.Errorf("create API request: %w", err)
		}
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
		req.Header.Set("User-Agent", "segh/1")
		req.Header.Set("Authorization", "Bearer "+token)
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}

		resp, requestErr := c.http.Do(req)
		if requestErr != nil {
			if attempt < c.maxRetries && isRetryableRequestError(requestErr) {
				if err := waitRetry(ctx, c.retryDelay(attempt, "")); err != nil {
					return err
				}
				continue
			}
			return fmt.Errorf("GitHub API request failed: %w", requestErr)
		}
		if resp.StatusCode >= 200 && resp.StatusCode < 300 && out == nil {
			if err := resp.Body.Close(); err != nil {
				return fmt.Errorf("close GitHub API response: %w", err)
			}
			return nil
		}
		data, readErr := readBounded(resp.Body, maxResponseBytes)
		closeErr := resp.Body.Close()
		if readErr != nil {
			return readErr
		}
		if closeErr != nil {
			return fmt.Errorf("close GitHub API response: %w", closeErr)
		}
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			if out != nil && len(data) > 0 {
				if err := json.Unmarshal(data, out); err != nil {
					return fmt.Errorf("decode GitHub API response: %w", err)
				}
			}
			return nil
		}

		apiErr := decodeAPIError(resp, data, token)
		if attempt < c.maxRetries && retryableStatus(resp.StatusCode, resp.Header) {
			delay := c.retryDelay(attempt, resp.Header.Get("Retry-After"))
			c.log.Info("retrying GitHub API request", "status", resp.StatusCode, "attempt", attempt+1, "delay", delay)
			if err := waitRetry(ctx, delay); err != nil {
				return err
			}
			continue
		}
		return apiErr
	}
}

func readBounded(reader io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read GitHub API response: %w", err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("GitHub API response exceeds %d bytes", limit)
	}
	return data, nil
}

func decodeAPIError(resp *http.Response, data []byte, token string) error {
	var payload struct {
		Message string `json:"message"`
	}
	_ = json.Unmarshal(data, &payload)
	if payload.Message == "" {
		payload.Message = http.StatusText(resp.StatusCode)
	}
	if token != "" {
		payload.Message = strings.ReplaceAll(payload.Message, token, "[REDACTED]")
	}
	if len(payload.Message) > 512 {
		payload.Message = payload.Message[:512]
	}
	return &APIError{StatusCode: resp.StatusCode, Message: payload.Message, RequestID: resp.Header.Get("X-GitHub-Request-Id")}
}

func retryableStatus(status int, header http.Header) bool {
	if status == http.StatusTooManyRequests || status >= 500 {
		return true
	}
	return status == http.StatusForbidden &&
		(header.Get("Retry-After") != "" || header.Get("X-RateLimit-Remaining") == "0")
}

func isRetryableRequestError(err error) bool {
	return !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded)
}

func (c *Client) retryDelay(attempt int, retryAfter string) time.Duration {
	if seconds, err := strconv.Atoi(retryAfter); err == nil && seconds > 0 {
		return time.Duration(seconds) * time.Second
	}
	exponent := math.Min(float64(attempt), 8)
	base := float64(c.baseDelay) * math.Pow(2, exponent)
	jitter := 1.0
	if random, err := rand.Int(rand.Reader, big.NewInt(5001)); err == nil {
		jitter = 0.75 + float64(random.Int64())/10_000
	}
	return time.Duration(base * jitter)
}

func waitRetry(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
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
