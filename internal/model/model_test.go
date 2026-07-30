package model

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRepositoryCustomPropertiesRetainVersionTwoWireFormat(t *testing.T) {
	repository := Repository{
		FullName: "example/repository",
		Topics:   []string{"governance"},
		CustomProperties: Observed[map[string]any]{
			State: Available,
			Value: map[string]any{"tier": "critical", "teams": []string{"platform", "security"}},
		},
	}
	data, err := json.Marshal(repository)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	const want = `{"id":0,"full_name":"example/repository","visibility":"","archived":false,"disabled":false,"fork":false,"template":false,"default_branch":"","topics":["governance"],"custom_properties":{"teams":["platform","security"],"tier":"critical"},"actions_enabled":{"state":""},"allowed_actions":{"state":""},"default_workflow_permissions":{"state":""},"fork_pr_approval":{"state":""},"ruleset":{"state":""},"branch_protection":{"state":""},"required_pull_requests":{"state":""},"required_checks":{"state":""},"force_push_restricted":{"state":""},"deletion_restricted":{"state":""},"code_security_configuration":{"state":""},"codeql":{"state":""},"secret_scanning":{"state":""},"push_protection":{"state":""},"dependency_graph":{"state":""},"dependabot_alerts":{"state":""},"dependabot_security_updates":{"state":""},"security_md":{"state":""},"sha_pinning_enforced":{"state":""}}`
	if text != want {
		t.Fatalf("repository JSON = %s\nwant = %s", text, want)
	}

	var decoded Repository
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.CustomProperties.State != Available || decoded.CustomProperties.Value["tier"] != "critical" {
		t.Fatalf("decoded custom properties = %#v", decoded.CustomProperties)
	}
}

func TestRepositoryCustomPropertyFailureRetainsCapabilityCompatibility(t *testing.T) {
	repository := Repository{
		CustomProperties: Observed[map[string]any]{State: Unsupported},
	}
	data, err := json.Marshal(repository)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"capabilities":{"custom_properties":"unsupported"}`) {
		t.Fatalf("repository JSON = %s", data)
	}
	var decoded Repository
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.CustomProperties.State != Unsupported {
		t.Fatalf("decoded custom properties = %#v", decoded.CustomProperties)
	}
}

func TestRepositoryUnmarshalRejectsUnknownField(t *testing.T) {
	var repository Repository
	err := json.Unmarshal([]byte(`{"full_name":"example/repository","unexpected":true}`), &repository)
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("UnmarshalJSON() = %v, want unknown-field rejection", err)
	}
}
