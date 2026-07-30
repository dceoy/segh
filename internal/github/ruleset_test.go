package github

import (
	"io"
	"net/http"
	"testing"

	"github.com/dceoy/segh/internal/model"
)

func TestEnrichTreatsRulesetOnlyRepositoryAsProtected(t *testing.T) {
	service := newInventoryTestService(t, func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/repos/org/repo/rules/branches/main":
			_, _ = io.WriteString(writer, `[
				{"type":"pull_request","ruleset_source_type":"Organization","ruleset_source":"org","ruleset_id":1},
				{"type":"required_status_checks","ruleset_source_type":"Organization","ruleset_source":"org","ruleset_id":1},
				{"type":"non_fast_forward","ruleset_source_type":"Organization","ruleset_source":"org","ruleset_id":1},
				{"type":"deletion","ruleset_source_type":"Organization","ruleset_source":"org","ruleset_id":1}
			]`)
		case "/repos/org/repo/branches/main/protection":
			writer.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(writer, `{"message":"Branch not protected"}`)
		default:
			writer.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(writer, `{"message":"Not Found"}`)
		}
	})
	repo := enrichForTest(service, apiRepository{FullName: "org/repo", DefaultBranch: "main"})
	for name, observed := range map[string]model.Observed[bool]{
		"ruleset":                repo.Ruleset,
		"branch_protection":      repo.BranchProtection,
		"required_pull_requests": repo.RequiredPullRequests,
		"required_checks":        repo.RequiredChecks,
		"force_push_restricted":  repo.ForcePushRestricted,
		"deletion_restricted":    repo.DeletionRestricted,
	} {
		if observed.State != model.Available || !observed.Value {
			t.Fatalf("%s = %#v, want Available/true (org ruleset alone must count as protection)", name, observed)
		}
	}
}

func TestEnrichDoesNotTreatUnrelatedRulesetAsProtection(t *testing.T) {
	service := newInventoryTestService(t, func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/repos/org/repo/rules/branches/main":
			// A ruleset exists in the org, but none of its rules apply to this branch/repo.
			_, _ = io.WriteString(writer, `[]`)
		case "/repos/org/repo/branches/main/protection":
			writer.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(writer, `{"message":"Branch not protected"}`)
		default:
			writer.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(writer, `{"message":"Not Found"}`)
		}
	})
	repo := enrichForTest(service, apiRepository{FullName: "org/repo", DefaultBranch: "main"})
	if repo.Ruleset.State != model.Available || repo.Ruleset.Value {
		t.Fatalf("ruleset = %#v, want Available/false", repo.Ruleset)
	}
	if repo.RequiredPullRequests.State != model.Available || repo.RequiredPullRequests.Value {
		t.Fatalf("required_pull_requests = %#v, want Available/false", repo.RequiredPullRequests)
	}
}

func TestMergeControlPrefersActiveRulesetRule(t *testing.T) {
	classic := model.Observed[bool]{State: model.Available, Value: false, Source: "branch_protection"}
	got := mergeControl(nil, true, classic)
	if got.State != model.Available || !got.Value {
		t.Fatalf("got = %#v, want Available/true", got)
	}
}

func TestMergeControlFallsBackToClassicWhenRuleAbsent(t *testing.T) {
	classic := model.Observed[bool]{State: model.Available, Value: true, Source: "branch_protection"}
	got := mergeControl(nil, false, classic)
	if got != classic {
		t.Fatalf("got = %#v, want classic %#v", got, classic)
	}
	classicFalse := model.Observed[bool]{State: model.Available, Value: false, Source: "branch_protection"}
	got = mergeControl(nil, false, classicFalse)
	if got != classicFalse {
		t.Fatalf("got = %#v, want classic %#v", got, classicFalse)
	}
}

func TestMergeControlUsesClassicWhenRulesEvaluationFails(t *testing.T) {
	classicTrue := model.Observed[bool]{State: model.Available, Value: true, Source: "branch_protection"}
	got := mergeControl(&APIError{StatusCode: 500, Message: "boom"}, false, classicTrue)
	if got != classicTrue {
		t.Fatalf("got = %#v, want classic (already confirmed true) %#v", got, classicTrue)
	}
}

func TestMergeControlIsUnknownWhenRulesFailAndClassicIsNotConfirmedTrue(t *testing.T) {
	classicFalse := model.Observed[bool]{State: model.Available, Value: false, Source: "branch_protection"}
	got := mergeControl(&APIError{StatusCode: 500, Message: "boom"}, false, classicFalse)
	if got.State == model.Available && !got.Value {
		t.Fatalf("got = %#v, must not claim confirmed-false when ruleset evaluation failed", got)
	}
	if got.State != model.Unknown {
		t.Fatalf("got = %#v, want Unknown", got)
	}

	classicUnknown := model.Observed[bool]{State: model.Unknown, Source: "branch_protection"}
	got = mergeControl(&APIError{StatusCode: 403, Message: "forbidden"}, false, classicUnknown)
	if got.State != model.Unknown {
		t.Fatalf("got = %#v, want Unknown", got)
	}
}
