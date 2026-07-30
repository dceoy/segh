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
	"github.com/dceoy/segh/internal/model"
)

type testAPIClient struct {
	baseURL string
}

func (c testAPIClient) Hostname() string {
	return "github.com"
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

func (c testAPIClient) GetAll(ctx context.Context, apiPath string, out any) error {
	return c.Get(ctx, apiPath, out)
}

func newInventoryTestService(t *testing.T, handler http.HandlerFunc) *InventoryService {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	cfg := config.Default()
	cfg.Organization = "org"
	return NewInventoryService(cfg, testAPIClient{baseURL: server.URL}, 1)
}

func enrichForTest(service *InventoryService, repo apiRepository) model.Repository {
	return service.enrich(
		context.Background(),
		repo,
		model.Observed[map[string]any]{
			State: model.Available, Value: map[string]any{}, Source: "organization_properties/values",
		},
		nil,
	)
}
