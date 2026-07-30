package model

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRepositoryUsesVersionFourTypedObservations(t *testing.T) {
	repository := Repository{
		FullName: "example/repository",
		CustomProperties: Observed[map[string]any]{
			State:  Available,
			Value:  map[string]any{"tier": "critical", "teams": []string{"platform", "security"}},
			Source: "organization_properties/values",
		},
		DependencyGraph:           Observed[bool]{State: Available, Value: true},
		DependabotAlerts:          Observed[bool]{State: Available, Value: true},
		DependabotSecurityUpdates: Observed[bool]{State: Available, Value: true},
	}
	data, err := json.Marshal(repository)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.Contains(text, `"custom_properties":{"state":"available","value":{"teams":["platform","security"],"tier":"critical"},"source":"organization_properties/values"}`) {
		t.Fatalf("repository JSON = %s", text)
	}
	for _, removed := range []string{
		`"capabilities"`, `"codeql"`, `"code_scanning"`, `"secret_scanning"`,
		`"push_protection"`, `"code_security_configuration"`,
	} {
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
