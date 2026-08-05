package github

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/dceoy/segh/internal/model"
)

func TestCollectBranchGovernanceFromApplicableOrganizationRuleset(t *testing.T) {
	repo, _ := collectBranchGovernanceForTest(t, http.StatusOK, `[
		{"type":"pull_request","ruleset_source_type":"Organization","ruleset_source":"org","ruleset_id":1},
		{"type":"workflows","ruleset_source_type":"Organization","ruleset_source":"org","ruleset_id":1},
		{"type":"non_fast_forward","ruleset_source_type":"Organization","ruleset_source":"org","ruleset_id":1},
		{"type":"deletion","ruleset_source_type":"Organization","ruleset_source":"org","ruleset_id":1}
	]`)
	assertGovernance(t, repo, true, true, true, true, true)
}

func TestCollectBranchGovernanceFromApplicableRepositoryRuleset(t *testing.T) {
	repo, _ := collectBranchGovernanceForTest(t, http.StatusOK, `[
		{"type":"pull_request","ruleset_source_type":"Repository","ruleset_source":"org/repo","ruleset_id":2},
		{"type":"required_status_checks","ruleset_source_type":"Repository","ruleset_source":"org/repo","ruleset_id":2},
		{"type":"non_fast_forward","ruleset_source_type":"Repository","ruleset_source":"org/repo","ruleset_id":2},
		{"type":"deletion","ruleset_source_type":"Repository","ruleset_source":"org/repo","ruleset_id":2}
	]`)
	assertGovernance(t, repo, true, true, true, true, true)
}

func TestCollectBranchGovernanceCombinesEffectiveRuleResults(t *testing.T) {
	repo, _ := collectBranchGovernanceForTest(t, http.StatusOK, `[
		{"type":"pull_request","ruleset_source_type":"Organization","ruleset_source":"org","ruleset_id":1},
		{"type":"required_status_checks","ruleset_source_type":"Repository","ruleset_source":"org/repo","ruleset_id":2},
		{"type":"non_fast_forward","ruleset_source_type":"Organization","ruleset_source":"org","ruleset_id":1},
		{"type":"deletion","ruleset_source_type":"Repository","ruleset_source":"org/repo","ruleset_id":2}
	]`)
	assertGovernance(t, repo, true, true, true, true, true)
}

func TestCollectBranchGovernanceFetchesAllPages(t *testing.T) {
	service := newInventoryTestService(t, func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/repos/org/repo/rules/branches/main" {
			t.Fatalf("unexpected path = %s", request.URL.Path)
		}
		if perPage := request.URL.Query().Get("per_page"); perPage != "100" {
			t.Fatalf("per_page = %q, want 100", perPage)
		}
		switch page := request.URL.Query().Get("page"); page {
		case "1":
			rules := make([]map[string]string, 100)
			for index := range rules {
				rules[index] = map[string]string{"type": "creation"}
			}
			if err := json.NewEncoder(writer).Encode(rules); err != nil {
				t.Fatal(err)
			}
		case "2":
			_, _ = io.WriteString(writer, `[
				{"type":"pull_request"},
				{"type":"workflows"},
				{"type":"non_fast_forward"},
				{"type":"deletion"}
			]`)
		default:
			t.Fatalf("unexpected page = %q", page)
		}
	})
	var repo model.Repository
	service.collectBranchGovernance(context.Background(), "/repos/org/repo", "main", &repo)
	assertGovernance(t, repo, true, true, true, true, true)
}

func TestCollectBranchGovernanceTreatsSelectorExclusionAsNoEffectiveRules(t *testing.T) {
	repo, _ := collectBranchGovernanceForTest(t, http.StatusOK, `[]`)
	assertGovernance(t, repo, false, false, false, false, false)
}

func TestCollectBranchGovernanceKeepsMissingControlAsAvailableFalse(t *testing.T) {
	repo, _ := collectBranchGovernanceForTest(t, http.StatusOK, `[{"type":"deletion"}]`)
	assertGovernance(t, repo, true, false, false, false, true)
}

func TestCollectBranchGovernanceFailsClosedOnPermissionErrors(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			repo, service := collectBranchGovernanceForTest(t, status, `{"message":"permission denied"}`)
			for name, observed := range governanceObservations(repo) {
				if observed.State != model.Unknown || observed.Source != "rules_branches" {
					t.Fatalf("%s = %#v, want unknown ruleset evidence", name, observed)
				}
			}
			if service.permissionErr == nil || service.permissionErr.StatusCode != status {
				t.Fatalf("permissionErr = %#v, want %d", service.permissionErr, status)
			}
		})
	}
}

func TestCollectBranchGovernancePreservesUnsupportedEvidence(t *testing.T) {
	repo, _ := collectBranchGovernanceForTest(t, http.StatusNotFound, `{"message":"unsupported"}`)
	for name, observed := range governanceObservations(repo) {
		if observed.State != model.Unsupported {
			t.Fatalf("%s = %#v, want unsupported", name, observed)
		}
	}
}

func TestCollectBranchGovernanceRejectsMalformedEvidence(t *testing.T) {
	for _, body := range []string{`null`, `[{"ruleset_id":1}]`} {
		t.Run(body, func(t *testing.T) {
			repo, _ := collectBranchGovernanceForTest(t, http.StatusOK, body)
			for name, observed := range governanceObservations(repo) {
				if observed.State != model.Unknown || observed.Source != "rules_branches" {
					t.Fatalf("%s = %#v, want unknown malformed evidence", name, observed)
				}
			}
		})
	}
}

func collectBranchGovernanceForTest(t *testing.T, status int, body string) (model.Repository, *InventoryService) {
	t.Helper()
	service := newInventoryTestService(t, func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/repos/org/repo/rules/branches/main" {
			t.Fatalf("unexpected path = %s", request.URL.Path)
		}
		writer.WriteHeader(status)
		_, _ = io.WriteString(writer, body)
	})
	var repo model.Repository
	service.collectBranchGovernance(context.Background(), "/repos/org/repo", "main", &repo)
	return repo, service
}

func assertGovernance(t *testing.T, repo model.Repository, ruleset, pullRequest, checks, forcePush, deletion bool) {
	t.Helper()
	want := map[string]bool{
		"ruleset":                ruleset,
		"required_pull_requests": pullRequest,
		"required_checks":        checks,
		"force_push_restricted":  forcePush,
		"deletion_restricted":    deletion,
	}
	for name, observed := range governanceObservations(repo) {
		if observed.State != model.Available || observed.Value != want[name] || observed.Source != "rules_branches" {
			t.Fatalf("%s = %#v, want available/%v from rules_branches", name, observed, want[name])
		}
	}
}

func governanceObservations(repo model.Repository) map[string]model.Observed[bool] {
	return map[string]model.Observed[bool]{
		"ruleset":                repo.Ruleset,
		"required_pull_requests": repo.RequiredPullRequests,
		"required_checks":        repo.RequiredChecks,
		"force_push_restricted":  repo.ForcePushRestricted,
		"deletion_restricted":    repo.DeletionRestricted,
	}
}
