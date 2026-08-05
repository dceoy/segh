package github

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/dceoy/segh/internal/model"
)

func TestCollectBranchGovernanceBoundsEffectiveRules(t *testing.T) {
	requests := 0
	service := newInventoryTestService(t, func(writer http.ResponseWriter, request *http.Request) {
		requests++
		if request.URL.Path != "/repos/org/repo/rules/branches/main" {
			t.Fatalf("unexpected path = %s", request.URL.Path)
		}
		if got := request.URL.Query().Get("per_page"); got != fmt.Sprint(effectiveRulesPageSize) {
			t.Fatalf("per_page = %q, want %d", got, effectiveRulesPageSize)
		}
		if got := request.URL.Query().Get("page"); got != fmt.Sprint(requests) {
			t.Fatalf("page = %q, want %d", got, requests)
		}
		rules := make([]map[string]string, effectiveRulesPageSize)
		for index := range rules {
			rules[index] = map[string]string{"type": "creation"}
		}
		if err := json.NewEncoder(writer).Encode(rules); err != nil {
			t.Fatal(err)
		}
	})

	var repo model.Repository
	service.collectBranchGovernance(context.Background(), "/repos/org/repo", "main", &repo)

	wantRequests := maxEffectiveRules/effectiveRulesPageSize + 1
	if requests != wantRequests {
		t.Fatalf("requests = %d, want %d", requests, wantRequests)
	}
	wantReason := fmt.Sprintf("effective-rules response exceeds %d rules", maxEffectiveRules)
	for name, observed := range governanceObservations(repo) {
		if observed.State != model.Unknown || observed.Source != "rules_branches" || observed.Reason != wantReason {
			t.Fatalf("%s = %#v, want unknown bounded-pagination evidence", name, observed)
		}
	}
}
