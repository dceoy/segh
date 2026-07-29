package github

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dceoy/segh/internal/config"
)

type testAPIClient struct {
	baseURL string
}

func (c testAPIClient) Get(ctx context.Context, apiPath string, out any) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+apiPath, nil)
	if err != nil {
		return err
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		data, _ := io.ReadAll(io.LimitReader(response.Body, 1024))
		return &APIError{StatusCode: response.StatusCode, Message: string(data)}
	}
	if out == nil {
		_, _ = io.Copy(io.Discard, response.Body)
		return nil
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, maxResponseBytes)).Decode(out); err != nil {
		return fmt.Errorf("decode test response: %w", err)
	}
	return nil
}

func newInventoryTestService(t *testing.T, handler http.HandlerFunc) *InventoryService {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	cfg := config.Default()
	cfg.Organization = "org"
	return NewInventoryService(cfg, testAPIClient{baseURL: server.URL}, 1)
}
