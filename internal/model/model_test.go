package model

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRepositoryCustomPropertiesRetainVersionTwoWireFormat(t *testing.T) {
	repository := Repository{
		FullName: "example/repository",
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
	if !strings.Contains(text, `"custom_properties":{"teams":["platform","security"],"tier":"critical"}`) {
		t.Fatalf("repository JSON = %s", text)
	}
	if strings.Contains(text, `"capabilities"`) || strings.Contains(text, `"custom_properties":{"state"`) {
		t.Fatalf("repository JSON changed the version 2 custom-property shape: %s", text)
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
