package github

import (
	"context"
	"io"
	"net/http"
	"testing"

	"github.com/dceoy/segh/internal/model"
)

func TestSecurityPolicyExistsRecognizesInheritedFile(t *testing.T) {
	// The community profile API reports a security policy found at a non-root location
	// (.github/SECURITY.md, docs/SECURITY.md) or inherited from the organization's
	// default .github community-health repository; a repository-root-only content
	// check misses both cases.
	service := newInventoryTestService(t, func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/repos/org/repo/community/profile" {
			t.Errorf("path = %s", request.URL.Path)
		}
		_, _ = io.WriteString(writer, `{"files":{"security":{"url":"https://api.github.com/repos/org/.github/contents/SECURITY.md"}}}`)
	})
	observed := service.securityPolicyExists(context.Background(), "/repos/org/repo", "main")
	if observed.State != model.Available || !observed.Value {
		t.Fatalf("observed = %#v", observed)
	}
}

func TestSecurityPolicyExistsFallsBackToPathsWhenProfileReportsAbsent(t *testing.T) {
	// Fall back to explicit path checks rather than trusting an absent community
	// profile result outright, since some repository visibility/permission
	// combinations may not populate it reliably.
	service := newInventoryTestService(t, func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/repos/org/repo/community/profile":
			_, _ = io.WriteString(writer, `{"files":{"security":null}}`)
		case "/repos/org/repo/contents/SECURITY.md":
			writer.WriteHeader(http.StatusNotFound)
		case "/repos/org/repo/contents/.github/SECURITY.md":
			_, _ = io.WriteString(writer, `{}`)
		default:
			t.Errorf("unexpected path = %s", request.URL.Path)
		}
	})
	observed := service.securityPolicyExists(context.Background(), "/repos/org/repo", "main")
	if observed.State != model.Available || !observed.Value {
		t.Fatalf("observed = %#v", observed)
	}
}

func TestSecurityPolicyExistsFallsBackTo404Profile(t *testing.T) {
	service := newInventoryTestService(t, func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/repos/org/repo/community/profile":
			writer.WriteHeader(http.StatusNotFound)
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	})
	observed := service.securityPolicyExists(context.Background(), "/repos/org/repo", "main")
	if observed.State != model.Available || observed.Value {
		t.Fatalf("observed = %#v", observed)
	}
}

func TestEndpointFeatureEnabled(t *testing.T) {
	for _, test := range []struct {
		name      string
		status    int
		wantState model.Availability
		wantValue bool
	}{
		{name: "enabled", status: http.StatusOK, wantState: model.Available, wantValue: true},
		{name: "disabled", status: http.StatusNotFound, wantState: model.Available, wantValue: false},
		{name: "permission unknown", status: http.StatusForbidden, wantState: model.Unknown, wantValue: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			service := newInventoryTestService(t, func(writer http.ResponseWriter, _ *http.Request) {
				writer.WriteHeader(test.status)
			})
			observed := service.endpointFeatureEnabled(context.Background(), "/feature", "feature")
			if observed.State != test.wantState || observed.Value != test.wantValue {
				t.Fatalf("observed = %#v", observed)
			}
		})
	}
}

func TestEnrichUsesFeatureSpecificSecurityEndpoints(t *testing.T) {
	service := newInventoryTestService(t, func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/repos/org/repo/dependency-graph/sbom", "/repos/org/repo/automated-security-fixes":
			_, _ = io.WriteString(writer, `{}`)
		default:
			writer.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(writer, `{"message":"Not Found"}`)
		}
	})
	repo := service.enrich(context.Background(), apiRepository{
		FullName:      "org/repo",
		DefaultBranch: "main",
		SecurityAndAnalysis: map[string]struct {
			Status string `json:"status"`
		}{
			"dependency_graph":            {Status: "disabled"},
			"dependabot_security_updates": {Status: "disabled"},
		},
	})
	for name, observed := range map[string]model.Observed[bool]{
		"dependency_graph":            repo.DependencyGraph,
		"dependabot_security_updates": repo.DependabotSecurityUpdates,
	} {
		if observed.State != model.Available || !observed.Value {
			t.Fatalf("%s = %#v, want endpoint-derived Available/true", name, observed)
		}
	}
}

func TestEnrichDecodesAttachedCodeSecurityConfiguration(t *testing.T) {
	service := newInventoryTestService(t, func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/repos/org/repo/code-security-configuration" {
			_, _ = io.WriteString(writer, `{"status":"attached","configuration":{"name":"organization default"}}`)
			return
		}
		writer.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(writer, `{"message":"Not Found"}`)
	})
	repo := service.enrich(context.Background(), apiRepository{
		FullName:      "org/repo",
		DefaultBranch: "main",
	})
	if observed := repo.CodeSecurityConfiguration; observed.State != model.Available || observed.Value != "organization default" {
		t.Fatalf("code security configuration = %#v", observed)
	}
}
