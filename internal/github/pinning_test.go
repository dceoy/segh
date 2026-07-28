package github

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dceoy/segh/internal/config"
	"github.com/dceoy/segh/internal/logging"
	"github.com/dceoy/segh/internal/model"
)

func contentResponse(content string) string {
	encoded := base64.StdEncoding.EncodeToString([]byte(content))
	payload, _ := json.Marshal(map[string]any{"content": encoded, "encoding": "base64", "size": len(content)})
	return string(payload)
}

func newInventoryTestService(t *testing.T, handler http.HandlerFunc) *InventoryService {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	cfg := config.Default()
	cfg.Organization = "org"
	cfg.GitHub.APIURL = server.URL
	client, err := NewClient(cfg, staticToken("token"), logging.New(io.Discard))
	if err != nil {
		t.Fatal(err)
	}
	return NewInventoryService(cfg, client, logging.New(io.Discard))
}

func TestWorkflowPinningFollowsLocalCompositeActions(t *testing.T) {
	workflow := "on: push\njobs:\n  build:\n    steps:\n      - uses: ./.github/actions/example@main\n"
	action := "runs:\n  using: composite\n  steps:\n    - uses: third-party/action@main\n"
	service := newInventoryTestService(t, func(writer http.ResponseWriter, request *http.Request) {
		switch {
		case request.URL.Path == "/repos/org/repo/contents/.github/workflows" && request.URL.RawQuery == "ref=main":
			_, _ = io.WriteString(writer, `[{"name":"ci.yml","type":"file"}]`)
		case request.URL.Path == "/repos/org/repo/contents/.github/workflows/ci.yml":
			_, _ = io.WriteString(writer, contentResponse(workflow))
		case request.URL.Path == "/repos/org/repo/contents/.github/actions/example/action.yml":
			_, _ = io.WriteString(writer, contentResponse(action))
		case request.URL.Path == "/repos/org/repo/contents/.github/actions/example/action.yaml":
			writer.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(writer, `{"message":"Not Found"}`)
		default:
			t.Errorf("unexpected request: %s?%s", request.URL.Path, request.URL.RawQuery)
			writer.WriteHeader(http.StatusNotFound)
		}
	})
	pinned, status := service.workflowPinning(context.Background(), "/repos/org/repo", "main")
	if pinned.Value {
		t.Fatalf("pinned = %#v, want false due to nested unpinned reference", pinned)
	}
	if status.Value != "unpinned" || status.Reason != ".github/actions/example/action.yml" {
		t.Fatalf("status = %#v", status)
	}
}

func TestWorkflowPinningFollowsLocalCompositeActionWithoutRef(t *testing.T) {
	workflow := "on: push\njobs:\n  build:\n    steps:\n      - uses: ./.github/actions/example\n"
	action := "runs:\n  using: composite\n  steps:\n    - uses: third-party/action@main\n"
	service := newInventoryTestService(t, func(writer http.ResponseWriter, request *http.Request) {
		switch {
		case request.URL.Path == "/repos/org/repo/contents/.github/workflows" && request.URL.RawQuery == "ref=main":
			_, _ = io.WriteString(writer, `[{"name":"ci.yml","type":"file"}]`)
		case request.URL.Path == "/repos/org/repo/contents/.github/workflows/ci.yml":
			_, _ = io.WriteString(writer, contentResponse(workflow))
		case request.URL.Path == "/repos/org/repo/contents/.github/actions/example/action.yml":
			_, _ = io.WriteString(writer, contentResponse(action))
		case request.URL.Path == "/repos/org/repo/contents/.github/actions/example/action.yaml":
			writer.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(writer, `{"message":"Not Found"}`)
		default:
			t.Errorf("unexpected request: %s?%s", request.URL.Path, request.URL.RawQuery)
			writer.WriteHeader(http.StatusNotFound)
		}
	})
	pinned, status := service.workflowPinning(context.Background(), "/repos/org/repo", "main")
	if pinned.Value {
		t.Fatalf("pinned = %#v, want false due to nested unpinned reference", pinned)
	}
	if status.Value != "unpinned" || status.Reason != ".github/actions/example/action.yml" {
		t.Fatalf("status = %#v", status)
	}
}

func TestWorkflowPinningIgnoresLocalReusableWorkflowCall(t *testing.T) {
	workflow := "on: push\njobs:\n  call:\n    uses: ./.github/workflows/reusable.yml\n"
	service := newInventoryTestService(t, func(writer http.ResponseWriter, request *http.Request) {
		switch {
		case request.URL.Path == "/repos/org/repo/contents/.github/workflows" && request.URL.RawQuery == "ref=main":
			_, _ = io.WriteString(writer, `[{"name":"ci.yml","type":"file"}]`)
		case request.URL.Path == "/repos/org/repo/contents/.github/workflows/ci.yml":
			_, _ = io.WriteString(writer, contentResponse(workflow))
		default:
			t.Errorf("unexpected request: %s?%s", request.URL.Path, request.URL.RawQuery)
			writer.WriteHeader(http.StatusNotFound)
		}
	})
	pinned, status := service.workflowPinning(context.Background(), "/repos/org/repo", "main")
	if !pinned.Value {
		t.Fatalf("pinned = %#v, want true (no third-party actions)", pinned)
	}
	if status.Value != "no_actions" {
		t.Fatalf("status = %#v", status)
	}
}

func TestWorkflowPinningLocalCompositeActionFullyPinned(t *testing.T) {
	workflow := "on: push\njobs:\n  build:\n    steps:\n      - uses: ./.github/actions/example@main\n"
	pinnedSHA := "0123456789012345678901234567890123456789"
	action := fmt.Sprintf("runs:\n  using: composite\n  steps:\n    - uses: third-party/action@%s\n", pinnedSHA)
	service := newInventoryTestService(t, func(writer http.ResponseWriter, request *http.Request) {
		switch {
		case request.URL.Path == "/repos/org/repo/contents/.github/workflows" && request.URL.RawQuery == "ref=main":
			_, _ = io.WriteString(writer, `[{"name":"ci.yml","type":"file"}]`)
		case request.URL.Path == "/repos/org/repo/contents/.github/workflows/ci.yml":
			_, _ = io.WriteString(writer, contentResponse(workflow))
		case request.URL.Path == "/repos/org/repo/contents/.github/actions/example/action.yml":
			_, _ = io.WriteString(writer, contentResponse(action))
		default:
			writer.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(writer, `{"message":"Not Found"}`)
		}
	})
	pinned, status := service.workflowPinning(context.Background(), "/repos/org/repo", "main")
	if !pinned.Value {
		t.Fatalf("pinned = %#v, want true", pinned)
	}
	if status.Value != "pinned_freshness_unknown" {
		t.Fatalf("status = %#v", status)
	}
}

func TestWorkflowPinningRejectsMutableDockerTag(t *testing.T) {
	workflow := "on: push\njobs:\n  build:\n    steps:\n      - uses: docker://alpine:latest\n"
	service := newInventoryTestService(t, func(writer http.ResponseWriter, request *http.Request) {
		switch {
		case request.URL.Path == "/repos/org/repo/contents/.github/workflows" && request.URL.RawQuery == "ref=main":
			_, _ = io.WriteString(writer, `[{"name":"ci.yml","type":"file"}]`)
		case request.URL.Path == "/repos/org/repo/contents/.github/workflows/ci.yml":
			_, _ = io.WriteString(writer, contentResponse(workflow))
		default:
			t.Errorf("unexpected request: %s?%s", request.URL.Path, request.URL.RawQuery)
			writer.WriteHeader(http.StatusNotFound)
		}
	})
	pinned, status := service.workflowPinning(context.Background(), "/repos/org/repo", "main")
	if pinned.Value {
		t.Fatalf("pinned = %#v, want false due to mutable docker tag", pinned)
	}
	if status.Value != "unpinned" {
		t.Fatalf("status = %#v", status)
	}
}

func TestWorkflowPinningAcceptsDigestPinnedDockerImage(t *testing.T) {
	digest := strings.Repeat("0123456789abcdef", 4)
	workflow := fmt.Sprintf("on: push\njobs:\n  build:\n    steps:\n      - uses: docker://ghcr.io/org/image@sha256:%s\n", digest)
	service := newInventoryTestService(t, func(writer http.ResponseWriter, request *http.Request) {
		switch {
		case request.URL.Path == "/repos/org/repo/contents/.github/workflows" && request.URL.RawQuery == "ref=main":
			_, _ = io.WriteString(writer, `[{"name":"ci.yml","type":"file"}]`)
		case request.URL.Path == "/repos/org/repo/contents/.github/workflows/ci.yml":
			_, _ = io.WriteString(writer, contentResponse(workflow))
		default:
			t.Errorf("unexpected request: %s?%s", request.URL.Path, request.URL.RawQuery)
			writer.WriteHeader(http.StatusNotFound)
		}
	})
	pinned, status := service.workflowPinning(context.Background(), "/repos/org/repo", "main")
	if !pinned.Value {
		t.Fatalf("pinned = %#v, want true for digest-pinned docker image", pinned)
	}
	if status.Value != "pinned_freshness_unknown" {
		t.Fatalf("status = %#v", status)
	}
}

func TestWorkflowPinningTreatsOversizedLocalActionAsUnknown(t *testing.T) {
	workflow := "on: push\njobs:\n  build:\n    steps:\n      - uses: ./.github/actions/example\n"
	service := newInventoryTestService(t, func(writer http.ResponseWriter, request *http.Request) {
		switch {
		case request.URL.Path == "/repos/org/repo/contents/.github/workflows" && request.URL.RawQuery == "ref=main":
			_, _ = io.WriteString(writer, `[{"name":"ci.yml","type":"file"}]`)
		case request.URL.Path == "/repos/org/repo/contents/.github/workflows/ci.yml":
			_, _ = io.WriteString(writer, contentResponse(workflow))
		case request.URL.Path == "/repos/org/repo/contents/.github/actions/example/action.yml":
			_, _ = io.WriteString(writer, `{"content":"","encoding":"base64","size":1048577}`)
		default:
			t.Errorf("unexpected request: %s?%s", request.URL.Path, request.URL.RawQuery)
			writer.WriteHeader(http.StatusNotFound)
		}
	})
	pinned, status := service.workflowPinning(context.Background(), "/repos/org/repo", "main")
	if pinned.State != model.Unknown || status.State != model.Unknown {
		t.Fatalf("pinned = %#v, status = %#v, want unknown", pinned, status)
	}
	if !strings.Contains(pinned.Reason, ".github/actions/example/action.yml") ||
		!strings.Contains(pinned.Reason, "exceeds 1 MiB limit") {
		t.Fatalf("pinned reason = %q", pinned.Reason)
	}
}
