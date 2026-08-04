package model

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRepositoryUsesTypedObservations(t *testing.T) {
	repository := Repository{
		FullName:                  "example/repository",
		DependencyGraph:           Observed[bool]{State: Available, Value: true, Source: "dependency_graph/sbom"},
		DependabotAlerts:          Observed[bool]{State: Available, Value: true},
		DependabotSecurityUpdates: Observed[bool]{State: Available, Value: true},
	}
	data, err := json.Marshal(repository)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.Contains(text, `"dependency_graph":{"state":"available","value":true,"source":"dependency_graph/sbom"}`) {
		t.Fatalf("repository JSON = %s", text)
	}
	for _, removed := range []string{
		`"topics"`, `"custom_properties"`, `"capabilities"`, `"codeql"`, `"code_scanning"`,
		`"secret_scanning"`, `"push_protection"`, `"code_security_configuration"`,
	} {
		if strings.Contains(text, removed) {
			t.Fatalf("repository JSON retains removed field %s: %s", removed, text)
		}
	}

	var decoded Repository
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.DependencyGraph.State != Available || !decoded.DependencyGraph.Value {
		t.Fatalf("decoded dependency graph observation = %#v", decoded.DependencyGraph)
	}
}
