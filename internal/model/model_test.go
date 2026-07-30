package model

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRepositoryUsesVersionThreeTypedCustomPropertyObservation(t *testing.T) {
	repository := Repository{
		FullName: "example/repository",
		CustomProperties: Observed[map[string]any]{
			State:  Available,
			Value:  map[string]any{"tier": "critical", "teams": []string{"platform", "security"}},
			Source: "organization_properties/values",
		},
	}
	data, err := json.Marshal(repository)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.Contains(text, `"custom_properties":{"state":"available","value":{"teams":["platform","security"],"tier":"critical"},"source":"organization_properties/values"}`) {
		t.Fatalf("repository JSON = %s", text)
	}
	for _, removed := range []string{`"capabilities"`, `"codeql"`, `"secret_scanning"`, `"dependabot_alerts"`} {
		if strings.Contains(text, removed) {
			t.Fatalf("repository JSON retains removed field %s: %s", removed, text)
		}
	}

	var decoded Repository
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.CustomProperties.State != Available || decoded.CustomProperties.Value["tier"] != "critical" {
		t.Fatalf("decoded custom properties = %#v", decoded.CustomProperties)
	}
}
