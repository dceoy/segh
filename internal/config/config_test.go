package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestLoadExample(t *testing.T) {
	cfg, err := Load(filepath.Join("..", "..", "segh.example.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Version != 2 || cfg.Organization != "example-org" || cfg.Inventory.Concurrency != 4 {
		t.Fatalf("unexpected config: %#v", cfg)
	}
}

func TestLoadRejectsUnknownField(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "segh.yaml")
	data := "version: 2\norganization: test\nsurprise: true\n"
	if err := os.WriteFile(configPath, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(configPath); err == nil || !strings.Contains(err.Error(), "field surprise not found") {
		t.Fatalf("expected unknown-field error, got %v", err)
	}
}

func TestLoadRejectsMissingPolicies(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "segh.yaml")
	data := "version: 2\norganization: test\n"
	if err := os.WriteFile(configPath, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(configPath); err == nil || !strings.Contains(err.Error(), "at least one policy must be configured") {
		t.Fatalf("expected missing-policy error, got %v", err)
	}
}

func TestLoadAcceptsDefaultedNonPolicySections(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "segh.yaml")
	data := "version: 2\norganization: test\npolicies:\n  repository:\n    require_ruleset: true\n"
	if err := os.WriteFile(configPath, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.GitHub.WebURL != "https://github.com" || cfg.Inventory.Concurrency != 4 || cfg.Output.Directory != "segh-results" {
		t.Fatalf("defaults were not applied: %#v", cfg)
	}
}

func TestSchemaAllowsDefaultedNestedSections(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "schema", "segh-config-v2.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Properties map[string]struct {
			Required []string `json:"required"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatal(err)
	}
	for _, section := range []string{"github", "inventory", "policies"} {
		if required := schema.Properties[section].Required; len(required) != 0 {
			t.Fatalf("%s schema requirements conflict with loader defaults: %v", section, required)
		}
	}
}

func TestSchemaRequiresAnEffectivePolicy(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "schema", "segh-config-v2.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Properties map[string]struct {
			AnyOf []struct {
				Required   []string                   `json:"required"`
				Properties map[string]json.RawMessage `json:"properties"`
			} `json:"anyOf"`
		} `json:"properties"`
		Definitions map[string]struct {
			AnyOf []json.RawMessage `json:"anyOf"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatal(err)
	}
	policies := schema.Properties["policies"]
	if len(policies.AnyOf) != 3 {
		t.Fatalf("policies schema must require one configured subsection, got %d alternatives", len(policies.AnyOf))
	}
	for _, section := range []string{"actions", "code_security", "repository"} {
		found := false
		for _, alternative := range policies.AnyOf {
			if len(alternative.Required) == 1 && alternative.Required[0] == section && alternative.Properties[section] != nil {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("policies schema does not require an effective %s subsection", section)
		}
	}
	for _, name := range []string{"configuredActionsPolicy", "configuredCodeSecurityPolicy", "configuredRepositoryPolicy"} {
		if len(schema.Definitions[name].AnyOf) == 0 {
			t.Errorf("%s must define effective policy values", name)
		}
	}
}

func TestValidateRejectsSpoofedLocalEndpoints(t *testing.T) {
	unsafe := []string{
		"http://localhost.attacker.example",
		"http://localhost@attacker.example",
		"http://localhost:80@attacker.example",
		"http://attacker.example#localhost",
		"https://github.example/api/v3",
	}
	for _, raw := range unsafe {
		cfg := Default()
		cfg.Organization = "test"
		cfg.Policies.Repository.RequireRuleset = true
		cfg.GitHub.WebURL = raw
		if err := cfg.Validate(); err == nil {
			t.Fatalf("%s: expected URL rejection", raw)
		}
	}
}

func TestValidateAcceptsGenuineLocalEndpoints(t *testing.T) {
	safe := []string{"http://localhost", "http://localhost:8080", "http://127.0.0.1:9000", "http://[::1]:9000"}
	for _, raw := range safe {
		cfg := Default()
		cfg.Organization = "test"
		cfg.Policies.Repository.RequireRuleset = true
		cfg.GitHub.WebURL = raw
		if err := cfg.Validate(); err != nil {
			t.Fatalf("%s: unexpected rejection: %v", raw, err)
		}
	}
}

func TestSchemaWebURLPatternMatchesRuntimeValidation(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "schema", "segh-config-v2.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Properties struct {
			GitHub struct {
				Properties struct {
					WebURL struct {
						Pattern string `json:"pattern"`
					} `json:"web_url"`
				} `json:"properties"`
			} `json:"github"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatal(err)
	}
	pattern := schema.Properties.GitHub.Properties.WebURL.Pattern
	if pattern == "" {
		t.Fatal("github.web_url schema is missing a pattern constraint")
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		t.Fatalf("invalid github.web_url pattern: %v", err)
	}

	safe := []string{
		"https://github.com",
		"http://localhost",
		"http://localhost:8080",
		"http://127.0.0.1:9000",
		"http://[::1]:9000",
	}
	for _, raw := range safe {
		if !re.MatchString(raw) {
			t.Errorf("%s: expected schema pattern to accept, but it rejected", raw)
		}
	}

	unsafe := []string{
		"http://example.com",
		"http://localhost.attacker.example",
		"http://localhost@attacker.example",
		"http://localhost:80@attacker.example",
		"http://attacker.example#localhost",
		"https://github.example/api/v3",
		"https://user:pass@github.com",
		"https://github.com?query=1",
		"https://github.com#frag",
	}
	for _, raw := range unsafe {
		if re.MatchString(raw) {
			t.Errorf("%s: expected schema pattern to reject, but it accepted", raw)
		}
	}
}
