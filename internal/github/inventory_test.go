package github

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
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

func TestEnrichPreservesAndMatchesMultiSelectCustomProperties(t *testing.T) {
	service := newInventoryTestService(t, func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/repos/org/repo/properties/values" {
			_, _ = io.WriteString(writer, `[
				{"property_name":"teams","value":["security","platform"]},
				{"property_name":"tier","value":"critical"},
				{"property_name":"unset","value":null}
			]`)
			return
		}
		writer.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(writer, `{"message":"Not Found"}`)
	})
	service.cfg.Selectors.CustomProperties = map[string]string{
		"teams": "security",
		"tier":  "critical",
	}

	repo := service.enrich(context.Background(), apiRepository{
		FullName:      "org/repo",
		DefaultBranch: "main",
	})
	if !reflect.DeepEqual(repo.CustomProperties["teams"], []string{"platform", "security"}) {
		t.Fatalf("teams custom property = %#v, want a preserved, sorted string slice", repo.CustomProperties["teams"])
	}
	if value, present := repo.CustomProperties["unset"]; !present || value != nil {
		t.Fatalf("unset custom property = %#v, present = %v; want a preserved null", value, present)
	}
	if reason, unknown := service.exclusionReason(repo); reason != "" || unknown {
		t.Fatalf("exclusionReason() = %q, %v; want multi-select membership to match", reason, unknown)
	}

	service.cfg.Selectors.CustomProperties["teams"] = "application"
	if reason, unknown := service.exclusionReason(repo); reason != "custom property teams" || unknown {
		t.Fatalf("exclusionReason() = %q, %v; want a verified multi-select mismatch", reason, unknown)
	}
}

func TestEnrichFailsClosedOnUnsupportedCustomPropertyValue(t *testing.T) {
	service := newInventoryTestService(t, func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/repos/org/repo/properties/values" {
			_, _ = io.WriteString(writer, `[{"property_name":"tier","value":true}]`)
			return
		}
		writer.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(writer, `{"message":"Not Found"}`)
	})
	service.cfg.Selectors.CustomProperties = map[string]string{"tier": "critical"}

	repo := service.enrich(context.Background(), apiRepository{
		FullName:      "org/repo",
		DefaultBranch: "main",
	})
	if reason, unknown := service.exclusionReason(repo); reason != "" || !unknown {
		t.Fatalf("exclusionReason() = %q, %v; want unsupported value type to fail closed", reason, unknown)
	}
}

func TestListRepositoriesFetchesEachPageIndependently(t *testing.T) {
	// A full-size first page must trigger a second request rather than being
	// treated as the final page, and each page must be decoded on its own so
	// no single request's bound is inflated by organization size.
	var pageParams []string
	service := newInventoryTestService(t, func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/orgs/org/repos" {
			t.Errorf("path = %s", request.URL.Path)
			return
		}
		page := request.URL.Query().Get("page")
		pageParams = append(pageParams, page)
		switch page {
		case "1":
			repos := make([]string, 100)
			for i := range repos {
				repos[i] = fmt.Sprintf(`{"id":%d,"full_name":"org/repo-%d"}`, i, i)
			}
			_, _ = io.WriteString(writer, "["+strings.Join(repos, ",")+"]")
		case "2":
			_, _ = io.WriteString(writer, `[{"id":100,"full_name":"org/repo-100"}]`)
		default:
			t.Errorf("unexpected page = %s", page)
		}
	})
	repositories, err := service.listRepositories(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(repositories) != 101 {
		t.Fatalf("len(repositories) = %d, want 101", len(repositories))
	}
	if !reflect.DeepEqual(pageParams, []string{"1", "2"}) {
		t.Fatalf("pageParams = %#v, want [1 2]", pageParams)
	}
}

func TestGetInstallationMetadataPaginatesUntilMatchingID(t *testing.T) {
	var pageParams []string
	service := newInventoryTestService(t, func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/orgs/org/installations" {
			t.Errorf("path = %s", request.URL.Path)
			return
		}
		page := request.URL.Query().Get("page")
		pageParams = append(pageParams, page)
		switch page {
		case "1":
			installations := make([]string, 100)
			for i := range installations {
				installations[i] = fmt.Sprintf(`{"id":%d}`, i+2)
			}
			_, _ = io.WriteString(writer, `{"installations":[`+strings.Join(installations, ",")+`]}`)
		case "2":
			_, _ = io.WriteString(writer, `{"installations":[{"id":1,"account":{"login":"org"},"repository_selection":"all"}]}`)
		default:
			t.Errorf("unexpected page = %s", page)
		}
	})
	metadata, err := service.getInstallationMetadata(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if metadata.ID != 1 || metadata.Account.Login != "org" || metadata.RepositorySelection != "all" {
		t.Fatalf("metadata = %#v", metadata)
	}
	if !reflect.DeepEqual(pageParams, []string{"1", "2"}) {
		t.Fatalf("pageParams = %#v, want [1 2]", pageParams)
	}
}

func TestRunFailsClosedWhenInstallationIsScopedToSelectedRepositories(t *testing.T) {
	service := newInventoryTestService(t, func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/orgs/org/installations":
			_, _ = io.WriteString(writer, `{"total_count":1,"installations":[{"id":1,"account":{"login":"org"},"repository_selection":"selected"}]}`)
		case "/installation/repositories":
			t.Error("accessible repositories must not be queried after selected installation metadata")
		case "/orgs/org/repos":
			_, _ = io.WriteString(writer, `[]`)
		default:
			t.Errorf("unexpected path = %s", request.URL.Path)
		}
	})
	inventory, err := service.Run(context.Background())
	if err == nil {
		t.Fatalf("err = nil, want error for incomplete inventory")
	}
	if inventory.Complete {
		t.Fatalf("Complete = true, want false when installation repository_selection is not \"all\"")
	}
	found := false
	for _, runErr := range inventory.Errors {
		if runErr.Kind == "installation_scope" {
			found = true
		}
	}
	if !found {
		t.Fatalf("errors = %#v, want an installation_scope error", inventory.Errors)
	}
}

func TestRunSucceedsWhenInstallationCoversWholeOrganization(t *testing.T) {
	service := newInventoryTestService(t, func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/orgs/org/installations":
			_, _ = io.WriteString(writer, `{"total_count":1,"installations":[{"id":1,"account":{"login":"org"},"repository_selection":"all"}]}`)
		case "/installation/repositories":
			// This matches the documented endpoint shape: repository_selection
			// belongs to installation metadata, not this response.
			_, _ = io.WriteString(writer, `{"total_count":1,"repositories":[{"full_name":"org/repo-1"}]}`)
		case "/orgs/org/repos":
			_, _ = io.WriteString(writer, `[{"id":1,"full_name":"org/repo-1"}]`)
		default:
			writer.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(writer, `{"message":"Not Found"}`)
		}
	})
	inventory, err := service.Run(context.Background())
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if !inventory.Complete {
		t.Fatalf("Complete = false, want true when installation repository_selection is \"all\"")
	}
	for _, runErr := range inventory.Errors {
		if runErr.Kind == "installation_scope" {
			t.Fatalf("errors = %#v, want no installation_scope error", inventory.Errors)
		}
	}
}

func TestRunFailsClosedWhenInstallationCountExceedsOrganizationEnumeration(t *testing.T) {
	service := newInventoryTestService(t, func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/orgs/org/installations":
			_, _ = io.WriteString(writer, `{"total_count":1,"installations":[{"id":1,"account":{"login":"org"},"repository_selection":"all"}]}`)
		case "/installation/repositories":
			_, _ = io.WriteString(writer, `{"total_count":2,"repositories":[{"full_name":"org/repo-1"}]}`)
		case "/orgs/org/repos":
			_, _ = io.WriteString(writer, `[{"id":1,"full_name":"org/repo-1"}]`)
		default:
			writer.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(writer, `{"message":"Not Found"}`)
		}
	})
	inventory, err := service.Run(context.Background())
	if err == nil {
		t.Fatalf("err = nil, want error when installation total_count exceeds the enumerated repository count")
	}
	if inventory.Complete {
		t.Fatalf("Complete = true, want false when installation total_count (2) does not match organization enumeration (1)")
	}
	found := false
	for _, runErr := range inventory.Errors {
		if runErr.Kind == "installation_scope" {
			found = true
		}
	}
	if !found {
		t.Fatalf("errors = %#v, want an installation_scope error", inventory.Errors)
	}
}

func TestRunFailsClosedWhenInstallationAccountDoesNotMatchConfiguredOrganization(t *testing.T) {
	service := newInventoryTestService(t, func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/orgs/org/installations":
			_, _ = io.WriteString(writer, `{"total_count":1,"installations":[{"id":1,"account":{"login":"other-org"},"repository_selection":"all"}]}`)
		case "/installation/repositories":
			t.Error("accessible repositories must not be queried after account mismatch")
		case "/orgs/org/repos":
			_, _ = io.WriteString(writer, `[]`)
		default:
			t.Errorf("unexpected path = %s", request.URL.Path)
		}
	})
	inventory, err := service.Run(context.Background())
	if err == nil {
		t.Fatalf("err = nil, want error when the installation account does not match cfg.Organization")
	}
	if inventory.Complete {
		t.Fatalf("Complete = true, want false when the installation account does not match cfg.Organization")
	}
	found := false
	for _, runErr := range inventory.Errors {
		if runErr.Kind == "installation_scope" {
			found = true
		}
	}
	if !found {
		t.Fatalf("errors = %#v, want an installation_scope error", inventory.Errors)
	}
}

func TestRunSucceedsForAllRepositoriesInstallationOnEmptyOrganization(t *testing.T) {
	service := newInventoryTestService(t, func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/orgs/org/installations":
			_, _ = io.WriteString(writer, `{"total_count":1,"installations":[{"id":1,"account":{"login":"org"},"repository_selection":"all"}]}`)
		case "/installation/repositories":
			_, _ = io.WriteString(writer, `{"total_count":0,"repositories":[]}`)
		case "/orgs/org/repos":
			_, _ = io.WriteString(writer, `[]`)
		default:
			t.Errorf("unexpected path = %s", request.URL.Path)
		}
	})
	inventory, err := service.Run(context.Background())
	if err != nil {
		t.Fatalf("err = %v, want nil for an empty organization covered by an all-repositories installation", err)
	}
	if !inventory.Complete {
		t.Fatalf("Complete = false, want true for verified empty organization")
	}
	if inventory.Total != 0 || inventory.Selected != 0 || len(inventory.Errors) != 0 {
		t.Fatalf("inventory = %#v, want complete empty inventory", inventory)
	}
}

func TestRunFailsClosedWhenInstallationCountIsPositiveButReturnsNoRepositories(t *testing.T) {
	service := newInventoryTestService(t, func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/orgs/org/installations":
			_, _ = io.WriteString(writer, `{"total_count":1,"installations":[{"id":1,"account":{"login":"org"},"repository_selection":"all"}]}`)
		case "/installation/repositories":
			_, _ = io.WriteString(writer, `{"total_count":1,"repositories":[]}`)
		case "/orgs/org/repos":
			_, _ = io.WriteString(writer, `[]`)
		default:
			t.Errorf("unexpected path = %s", request.URL.Path)
		}
	})
	inventory, err := service.Run(context.Background())
	if err == nil {
		t.Fatalf("err = nil, want error for inconsistent accessible repository response")
	}
	if inventory.Complete {
		t.Fatalf("Complete = true, want false when total_count is positive but repositories is empty")
	}
}

func TestRunPreservesInstallationPermissionErrorAfterSuccessfulEnumeration(t *testing.T) {
	service := newInventoryTestService(t, func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/orgs/org/installations":
			writer.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(writer, `{"message":"Resource not accessible by integration"}`)
		case "/orgs/org/repos":
			_, _ = io.WriteString(writer, `[{"id":1,"full_name":"org/repo-1","default_branch":"main"}]`)
		default:
			writer.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(writer, `{"message":"Not Found"}`)
		}
	})
	inventory, err := service.Run(context.Background())
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusForbidden {
		t.Fatalf("err = %v, want wrapped 403 APIError", err)
	}
	if inventory.Complete || inventory.Total != 1 {
		t.Fatalf("inventory = %#v, want incomplete inventory with successful repository enumeration", inventory)
	}
}

func TestRunPreservesInstallationPermissionErrorWhenEnumerationAlsoFails(t *testing.T) {
	service := newInventoryTestService(t, func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/orgs/org/installations":
			writer.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(writer, `{"message":"Resource not accessible by integration"}`)
		case "/orgs/org/repos":
			writer.WriteHeader(http.StatusServiceUnavailable)
			_, _ = io.WriteString(writer, `{"message":"Service Unavailable"}`)
		default:
			writer.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(writer, `{"message":"Not Found"}`)
		}
	})
	inventory, err := service.Run(context.Background())
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusForbidden {
		t.Fatalf("err = %v, want wrapped 403 APIError before the enumeration failure", err)
	}
	if inventory.Complete {
		t.Fatalf("inventory = %#v, want incomplete inventory", inventory)
	}
	if len(inventory.Errors) != 2 ||
		inventory.Errors[0].Kind != "installation_scope" ||
		inventory.Errors[1].Kind != "enumeration" {
		t.Fatalf("errors = %#v, want installation_scope and enumeration errors", inventory.Errors)
	}
}

func TestRunFailsClosedWhenExplicitlyIncludedRepositoryIsNotEnumerated(t *testing.T) {
	service := newInventoryTestService(t, func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/orgs/org/installations":
			_, _ = io.WriteString(writer, `{"total_count":1,"installations":[{"id":1,"account":{"login":"org"},"repository_selection":"all"}]}`)
		case "/installation/repositories":
			_, _ = io.WriteString(writer, `{"total_count":1,"repositories":[{"full_name":"org/repo-1"}]}`)
		case "/orgs/org/repos":
			_, _ = io.WriteString(writer, `[{"id":1,"full_name":"org/repo-1"}]`)
		default:
			writer.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(writer, `{"message":"Not Found"}`)
		}
	})
	service.cfg.Selectors.Repositories = []string{"org/repo-1", "org/does-not-exist"}
	inventory, err := service.Run(context.Background())
	if err == nil {
		t.Fatalf("err = nil, want error for a missing explicitly included repository")
	}
	if inventory.Complete {
		t.Fatalf("Complete = true, want false when a selectors.repositories entry is not enumerated")
	}
	found := false
	for _, runErr := range inventory.Errors {
		if runErr.Kind == "repository_not_found" && runErr.Repository == "org/does-not-exist" {
			found = true
		}
	}
	if !found {
		t.Fatalf("errors = %#v, want a repository_not_found error for org/does-not-exist", inventory.Errors)
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
