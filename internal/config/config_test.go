package config

import (
	"encoding/json"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
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

	// Each case must agree between the schema pattern and validateGitHubURL:
	// the schema is meant to be an exact static description of the runtime
	// contract, not merely an example-based approximation of it.
	cases := []struct {
		raw   string
		valid bool
	}{
		{"https://github.com", true},
		{"http://localhost", true},
		{"http://localhost:8080", true},
		{"http://127.0.0.1:9000", true},
		{"http://127.255.255.255", true},
		{"http://[::1]:9000", true},

		{"http://example.com", false},
		{"http://localhost.attacker.example", false},
		{"http://localhost@attacker.example", false},
		{"http://localhost:80@attacker.example", false},
		{"http://attacker.example#localhost", false},
		{"https://github.example/api/v3", false},
		{"https://user:pass@github.com", false},
		{"https://github.com?query=1", false},
		{"https://github.com#frag", false},

		// Invalid IPv4 octets: the pattern must reject these by range,
		// not merely by digit count.
		{"http://127.999.999.999", false},
		{"http://127.256.0.1", false},

		// Alternate loopback spellings that net.IP.IsLoopback would
		// accept but the schema pattern does not encode: the runtime
		// validator must reject these too so the schema remains an
		// exact description of what it accepts.
		{"http://[0:0:0:0:0:0:0:1]", false},
		{"http://[::ffff:127.0.0.1]", false},
		{"http://[::ffff:7f00:1]", false},
	}
	for _, tc := range cases {
		if got := re.MatchString(tc.raw); got != tc.valid {
			t.Errorf("%s: schema pattern match = %v, want %v", tc.raw, got, tc.valid)
		}
		if got := validateGitHubURL(tc.raw) == nil; got != tc.valid {
			t.Errorf("%s: validateGitHubURL acceptance = %v, want %v", tc.raw, got, tc.valid)
		}
	}
}

func TestSchemaDurationPatternMatchesRuntimeValidation(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "schema", "segh-config-v2.schema.json"))
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

	// Config.Validate rejects inventory.timeout <= 0, so every duration
	// string here must agree between the schema and time.ParseDuration.
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

		{"0.0s", false},
		{".0s", false},
		{"0.00h0m", false},
	}
	for _, tc := range cases {
		if got := schemaAccepts(tc.raw); got != tc.valid {
			t.Errorf("%s: schema acceptance = %v, want %v", tc.raw, got, tc.valid)
		}
		dur, err := time.ParseDuration(tc.raw)
		if got := err == nil && dur > 0; got != tc.valid {
			t.Errorf("%s: time.ParseDuration-derived validity = %v, want %v", tc.raw, got, tc.valid)
		}
	}
}

func TestSchemaSuppressionRepositoryPatternMatchesRuntimeValidation(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "schema", "segh-config-v2.schema.json"))
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
