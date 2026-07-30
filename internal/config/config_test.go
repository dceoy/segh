package config

import (
	"encoding/json"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestLoadExample(t *testing.T) {
	cfg, err := Load(filepath.Join("..", "..", "segh.example.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Version != 3 || cfg.Organization != "example-org" || cfg.Inventory.Concurrency != 4 {
		t.Fatalf("unexpected config: %#v", cfg)
	}
}

func TestLoadRejectsUnknownField(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "segh.yaml")
	data := "version: 3\norganization: test\nsurprise: true\n"
	if err := os.WriteFile(configPath, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(configPath); err == nil || !strings.Contains(err.Error(), "field surprise not found") {
		t.Fatalf("expected unknown-field error, got %v", err)
	}
}

func TestLoadRejectsTrailingYAMLDocument(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "segh.yaml")
	data := "version: 3\norganization: test\npolicies:\n  repository:\n    require_ruleset: true\n---\norganization: ignored\n"
	if err := os.WriteFile(configPath, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(configPath); err == nil || !strings.Contains(err.Error(), "multiple YAML documents are not allowed") {
		t.Fatalf("expected multiple-document error, got %v", err)
	}
}

func TestLoadRejectsUnboundedDuration(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "segh.yaml")
	data := "version: 3\norganization: test\ninventory:\n  timeout: 999999999999999999999999999h\npolicies:\n  repository:\n    require_ruleset: true\n"
	if err := os.WriteFile(configPath, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(configPath); err == nil || !strings.Contains(err.Error(), "duration must be positive") {
		t.Fatalf("expected bounded-duration error, got %v", err)
	}
}

func TestLoadRejectsMissingPolicies(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "segh.yaml")
	data := "version: 3\norganization: test\n"
	if err := os.WriteFile(configPath, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(configPath); err == nil || !strings.Contains(err.Error(), "at least one policy must be configured") {
		t.Fatalf("expected missing-policy error, got %v", err)
	}
}

func TestLoadRejectsEmptyCodeSecurityPolicy(t *testing.T) {
	for _, codeSecurity := range []string{
		"{}",
		"{configuration: \"\"}",
	} {
		configPath := filepath.Join(t.TempDir(), "segh.yaml")
		data := "version: 3\norganization: test\npolicies:\n  code_security: " + codeSecurity +
			"\n  repository:\n    require_ruleset: true\n"
		if err := os.WriteFile(configPath, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(configPath); err == nil ||
			!strings.Contains(err.Error(), "policies.code_security.configuration is required") {
			t.Fatalf("Load() = %v, want empty code-security policy error", err)
		}
	}
}

func TestLoadAcceptsDefaultedNonPolicySections(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "segh.yaml")
	data := "version: 3\norganization: test\npolicies:\n  repository:\n    require_ruleset: true\n"
	if err := os.WriteFile(configPath, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Inventory.Concurrency != 4 || time.Duration(cfg.Inventory.Timeout) != 30*time.Minute {
		t.Fatalf("defaults were not applied: %#v", cfg)
	}
}

func TestSchemaAndRuntimeRejectDuplicateArrayItems(t *testing.T) {
	type arraySchema struct {
		Ref         string `json:"$ref"`
		UniqueItems bool   `json:"uniqueItems"`
	}
	data, err := os.ReadFile(filepath.Join("..", "..", "schema", "segh-config-v3.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Properties struct {
			Selectors struct {
				Properties map[string]arraySchema `json:"properties"`
			} `json:"selectors"`
			Policies struct {
				Properties struct {
					Repository struct {
						Properties map[string]arraySchema `json:"properties"`
					} `json:"repository"`
				} `json:"properties"`
			} `json:"policies"`
		} `json:"properties"`
		Definitions map[string]arraySchema `json:"$defs"`
	}
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatal(err)
	}
	if !schema.Properties.Selectors.Properties["visibilities"].UniqueItems {
		t.Error("selectors.visibilities schema must require unique items")
	}
	if !schema.Properties.Policies.Properties.Repository.Properties["allowed_visibilities"].UniqueItems {
		t.Error("policies.repository.allowed_visibilities schema must require unique items")
	}
	if !schema.Definitions["stringArray"].UniqueItems {
		t.Error("$defs/stringArray schema must require unique items")
	}
	for _, name := range []string{"include_topics", "exclude_topics", "repositories", "exclude"} {
		if ref := schema.Properties.Selectors.Properties[name].Ref; ref != "#/$defs/stringArray" {
			t.Errorf("selectors.%s schema must use the unique stringArray definition, got %q", name, ref)
		}
	}

	cases := []struct {
		name      string
		configure func(*Config)
	}{
		{
			name: "selectors.visibilities",
			configure: func(cfg *Config) {
				cfg.Selectors.Visibilities = []string{"private", "private"}
			},
		},
		{
			name: "selectors.include_topics",
			configure: func(cfg *Config) {
				cfg.Selectors.IncludeTopics = []string{"security", "security"}
			},
		},
		{
			name: "selectors.exclude_topics",
			configure: func(cfg *Config) {
				cfg.Selectors.ExcludeTopics = []string{"archived", "archived"}
			},
		},
		{
			name: "selectors.repositories",
			configure: func(cfg *Config) {
				cfg.Selectors.Repositories = []string{"example/repository", "example/repository"}
			},
		},
		{
			name: "selectors.exclude",
			configure: func(cfg *Config) {
				cfg.Selectors.Exclude = []string{"example/legacy", "example/legacy"}
			},
		},
		{
			name: "policies.repository.allowed_visibilities",
			configure: func(cfg *Config) {
				cfg.Policies.Repository.AllowedVisibilities = []string{"private", "private"}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Default()
			cfg.Organization = "test"
			cfg.Policies.Repository.RequireRuleset = true
			tc.configure(&cfg)
			err := cfg.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.name+" contains duplicate value") {
				t.Fatalf("expected duplicate-value error for %s, got %v", tc.name, err)
			}
		})
	}
}

func TestSchemaAllowsDefaultedNestedSections(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "schema", "segh-config-v3.schema.json"))
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
	for _, section := range []string{"inventory", "policies"} {
		if required := schema.Properties[section].Required; len(required) != 0 {
			t.Fatalf("%s schema requirements conflict with loader defaults: %v", section, required)
		}
	}
}

func TestSchemaRequiresAnEffectivePolicy(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "schema", "segh-config-v3.schema.json"))
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
			AnyOf    []json.RawMessage `json:"anyOf"`
			Required []string          `json:"required"`
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
	for _, name := range []string{"configuredActionsPolicy", "configuredRepositoryPolicy"} {
		if len(schema.Definitions[name].AnyOf) == 0 {
			t.Errorf("%s must define effective policy values", name)
		}
	}
	if required := schema.Definitions["configuredCodeSecurityPolicy"].Required; !slices.Equal(required, []string{"configuration"}) {
		t.Errorf("configuredCodeSecurityPolicy must require configuration, got %v", required)
	}
}

func TestLoadRejectsVersionOneTwoAndRemovedRuntimeFields(t *testing.T) {
	for _, test := range []struct {
		name string
		data string
		want string
	}{
		{"version 1", "version: 1\norganization: test\npolicies:\n  repository:\n    require_ruleset: true\n", "version must be 3"},
		{"version 2", "version: 2\norganization: test\npolicies:\n  repository:\n    require_ruleset: true\n", "version must be 3"},
		{"github host", "version: 3\norganization: test\ngithub:\n  web_url: https://github.com\npolicies:\n  repository:\n    require_ruleset: true\n", "field github not found"},
		{"output directory", "version: 3\norganization: test\noutput:\n  directory: results\npolicies:\n  repository:\n    require_ruleset: true\n", "field output not found"},
		{"feature policy", "version: 3\norganization: test\npolicies:\n  code_security:\n    configuration: approved\n    codeql: required\n", "field codeql not found"},
	} {
		t.Run(test.name, func(t *testing.T) {
			configPath := filepath.Join(t.TempDir(), "segh.yaml")
			if err := os.WriteFile(configPath, []byte(test.data), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(configPath); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Load() = %v, want %q", err, test.want)
			}
		})
	}
}

func TestSchemaDurationPatternMatchesRuntimeValidation(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "schema", "segh-config-v3.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Defs struct {
			Duration struct {
				Pattern string `json:"pattern"`
				Not     struct {
					Pattern string `json:"pattern"`
				} `json:"not"`
			} `json:"duration"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatal(err)
	}
	pattern := schema.Defs.Duration.Pattern
	notPattern := schema.Defs.Duration.Not.Pattern
	if pattern == "" || notPattern == "" {
		t.Fatal("$defs/duration is missing a pattern or not-pattern constraint")
	}
	if pattern != durationPatternText || notPattern != zeroDurationPattern {
		t.Fatal("$defs/duration patterns must exactly match runtime duration syntax")
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		t.Fatalf("invalid duration pattern: %v", err)
	}
	notRe, err := regexp.Compile(notPattern)
	if err != nil {
		t.Fatalf("invalid duration not-pattern: %v", err)
	}
	schemaAccepts := func(raw string) bool {
		return re.MatchString(raw) && !notRe.MatchString(raw)
	}

	// The custom YAML duration parser deliberately accepts a bounded subset of
	// time.ParseDuration syntax, so every value must agree with the schema.
	cases := []struct {
		raw   string
		valid bool
	}{
		{"30m", true},
		{"1h30m", true},
		{"500ms", true},
		{"1s", true},
		{"0h30m", true},
		{"+1s", true},
		{"+1.5s", true},

		{"0s", false},
		{"+0s", false},
		{"+0.0s", false},
		{"-1s", false},
		{"0ns", false},
		{"00s", false},
		{"0h0m", false},
		{"0h0m0s", false},
		{"0h0m0ns", false},
		{"00h0m", false},
		{"0ms", false},
		{"0µs", false},
		{"0μs", false},
		{"0h0m0s0ns", false},
		{"1ns", true},
		{"0h0m1ns", true},

		{"1.5s", true},
		{"0.5ms", true},
		{"1.5h", true},
		{"0h1.5m", true},
		{"0.05s", true},
		{"1.5us", true},
		{"1.5µs", true},
		{"1.5μs", true},
		{".5s", true},
		{"5.s", true},
		{"99999h", true},
		{strings.Repeat("99999h", 16), true},

		{"0.0s", false},
		{".0s", false},
		{"0.00h0m", false},
		{"100000h", false},
		{"1.0000000000s", false},
		{strings.Repeat("1h", 17), false},
		{"999999999999999999999999999h", false},
	}
	for _, tc := range cases {
		if got := schemaAccepts(tc.raw); got != tc.valid {
			t.Errorf("%s: schema acceptance = %v, want %v", tc.raw, got, tc.valid)
		}
		node := yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: tc.raw}
		var dur Duration
		if got := dur.UnmarshalYAML(&node) == nil; got != tc.valid {
			t.Errorf("%s: runtime duration acceptance = %v, want %v", tc.raw, got, tc.valid)
		}
	}
}

func TestSchemaSuppressionRepositoryPatternMatchesRuntimeValidation(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "schema", "segh-config-v3.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Properties struct {
			Suppressions struct {
				Items struct {
					Properties struct {
						Repository struct {
							Pattern string `json:"pattern"`
						} `json:"repository"`
					} `json:"properties"`
				} `json:"items"`
			} `json:"suppressions"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatal(err)
	}
	pattern := schema.Properties.Suppressions.Items.Properties.Repository.Pattern
	if pattern == "" {
		t.Fatal("suppressions[].repository schema is missing a pattern constraint")
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		t.Fatalf("invalid suppression repository pattern: %v", err)
	}

	cases := []struct {
		raw   string
		valid bool
	}{
		{"", true},
		{"example/repository", true},
		{"example/*", true},
		{"example/repo?", true},
		{"example/[a-z]*", true},
		{"example/[^a-z]*", true},
		{`example/\[literal\]`, true},
		{`example/[\-]`, true},
		{"example/[z-a]", true},

		{"example/[", false},
		{"example/[]", false},
		{"example/[^]", false},
		{"example/[a-]", false},
		{"example/[-a]", false},
		{"example/[a--b]", false},
		{`example/trailing\`, false},
	}
	for _, tc := range cases {
		if got := re.MatchString(tc.raw); got != tc.valid {
			t.Errorf("%q: schema acceptance = %v, want %v", tc.raw, got, tc.valid)
		}
		_, runtimeErr := path.Match(tc.raw, "example/repository")
		if got := runtimeErr == nil; got != tc.valid {
			t.Errorf("%q: path.Match-derived validity = %v, want %v", tc.raw, got, tc.valid)
		}
	}

	// Exhaust the syntax-significant ASCII alphabet through short patterns so
	// optional negation, escaping, and character-range boundaries cannot drift
	// between the static schema and path.Match's parser.
	alphabet := []byte{'a', '*', '?', '[', ']', '^', '-', '\\', '/'}
	var checkPatterns func([]byte, int)
	checkPatterns = func(prefix []byte, remaining int) {
		if remaining == 0 {
			raw := string(prefix)
			_, runtimeErr := path.Match(raw, "example/repository")
			if schemaValid, runtimeValid := re.MatchString(raw), runtimeErr == nil; schemaValid != runtimeValid {
				t.Errorf("%q: schema acceptance = %v, path.Match-derived validity = %v", raw, schemaValid, runtimeValid)
			}
			return
		}
		for _, char := range alphabet {
			checkPatterns(append(prefix, char), remaining-1)
		}
	}
	for length := 0; length <= 5; length++ {
		checkPatterns(make([]byte, 0, length), length)
	}
}
