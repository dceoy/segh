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

	"gopkg.in/yaml.v3"
)

func TestLoadExample(t *testing.T) {
	cfg, err := Load(filepath.Join("..", "..", "segh.example.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Version != 5 || cfg.Organization != "example-org" || cfg.Inventory.Concurrency != 4 ||
		!cfg.SourceScan.Enabled || cfg.SourceScan.Concurrency != 4 {
		t.Fatalf("unexpected config: %#v", cfg)
	}
}

func TestLoadRejectsUnknownField(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "segh.yaml")
	data := "version: 5\norganization: test\nsurprise: true\n"
	if err := os.WriteFile(configPath, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(configPath); err == nil || !strings.Contains(err.Error(), "additional properties 'surprise' not allowed") {
		t.Fatalf("expected unknown-field error, got %v", err)
	}
}

func TestLoadRejectsTrailingYAMLDocument(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "segh.yaml")
	data := "version: 5\norganization: test\npolicies:\n  repository:\n    require_ruleset: true\n---\norganization: ignored\n"
	if err := os.WriteFile(configPath, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(configPath); err == nil || !strings.Contains(err.Error(), "multiple YAML documents are not allowed") {
		t.Fatalf("expected multiple-document error, got %v", err)
	}
}

func TestLoadRejectsUnboundedDuration(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "segh.yaml")
	data := "version: 5\norganization: test\ninventory:\n  timeout: 999999999999999999999999999h\npolicies:\n  repository:\n    require_ruleset: true\n"
	if err := os.WriteFile(configPath, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(configPath); err == nil || !strings.Contains(err.Error(), "does not match pattern") {
		t.Fatalf("expected bounded-duration error, got %v", err)
	}
}

func TestLoadRejectsMissingPolicies(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "segh.yaml")
	data := "version: 5\norganization: test\n"
	if err := os.WriteFile(configPath, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(configPath); err == nil || !strings.Contains(err.Error(), "missing property 'policies'") {
		t.Fatalf("expected missing-policy error, got %v", err)
	}
}

func TestLoadRejectsRemovedCodeSecurityPolicy(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "segh.yaml")
	data := "version: 5\norganization: test\npolicies:\n  code_security:\n    configuration: approved\n"
	if err := os.WriteFile(configPath, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(configPath); err == nil || !strings.Contains(err.Error(), "additional properties 'code_security' not allowed") {
		t.Fatalf("Load() = %v, want removed code-security field error", err)
	}
}

func TestSchemaAndRuntimeRejectNullValues(t *testing.T) {
	for _, tc := range []struct {
		name string
		data string
	}{
		{"section", "version: 5\norganization: test\ninventory: null\npolicies:\n  repository:\n    require_ruleset: true\n"},
		{"array", "version: 5\norganization: test\nselectors:\n  repositories: null\npolicies:\n  repository:\n    require_ruleset: true\n"},
		{"nested scalar", "version: 5\norganization: test\npolicies:\n  actions:\n    enabled: null\n  repository:\n    require_ruleset: true\n"},
		{"bare key", "version: 5\norganization: test\npolicies:\n  dependencies:\n  repository:\n    require_ruleset: true\n"},
		{"alias", "version: 5\norganization: test\nselectors:\n  repositories: &empty null\npolicies:\n  actions:\n    enabled: *empty\n  repository:\n    require_ruleset: true\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			configPath := filepath.Join(t.TempDir(), "segh.yaml")
			if err := os.WriteFile(configPath, []byte(tc.data), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(configPath); err == nil ||
				!strings.Contains(err.Error(), "got null") {
				t.Fatalf("Load() = %v, want null-value error", err)
			}
		})
	}
}

func TestLoadAcceptsDefaultedNonPolicySections(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "segh.yaml")
	data := "version: 5\norganization: test\npolicies:\n  repository:\n    require_ruleset: true\n"
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
	if cfg.SourceScan.Enabled || cfg.SourceScan.Concurrency != 4 {
		t.Fatalf("source scan defaults were not applied: %#v", cfg.SourceScan)
	}
}

func TestSchemaRejectsInvalidStructuralValuesAtRuntime(t *testing.T) {
	tests := []struct {
		name string
		data string
	}{
		{
			"invalid actions enum",
			"policies:\n  actions:\n    allowed_actions: unrestricted\n",
		},
		{
			"zero concurrency",
			"inventory:\n  concurrency: 0\npolicies:\n  repository:\n    require_ruleset: true\n",
		},
		{
			"excessive source scan concurrency",
			"source_scan:\n  enabled: true\n  concurrency: 17\npolicies:\n  repository:\n    require_ruleset: true\n",
		},
		{
			"excessive inventory timeout",
			"inventory:\n  timeout: 30m1s\npolicies:\n  repository:\n    require_ruleset: true\n",
		},
		{"empty policies", "policies: {}\n"},
		{"empty policy section", "policies:\n  actions: {}\n"},
		{
			"ineffective false-only policy",
			"policies:\n  repository:\n    require_ruleset: false\n",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			configPath := filepath.Join(t.TempDir(), "segh.yaml")
			data := "version: 5\norganization: test\n" + test.data
			if err := os.WriteFile(configPath, []byte(data), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(configPath); err == nil {
				t.Fatal("Load() succeeded for a schema-invalid configuration")
			}
		})
	}
}

func TestSchemaAndRuntimeRejectDuplicateArrayItems(t *testing.T) {
	cases := []struct {
		name string
		data string
	}{
		{"selectors.repositories", "selectors:\n  repositories: [example/repository, example/repository]\n"},
		{"selectors.exclude", "selectors:\n  exclude: [example/legacy, example/legacy]\n"},
		{
			"policies.repository.allowed_visibilities",
			"policies:\n  repository:\n    allowed_visibilities: [private, private]\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			policies := "policies:\n  repository:\n    require_ruleset: true\n"
			if strings.HasPrefix(tc.data, "policies:") {
				policies = ""
			}
			configPath := filepath.Join(t.TempDir(), "segh.yaml")
			if err := os.WriteFile(
				configPath,
				[]byte("version: 5\norganization: test\n"+tc.data+policies),
				0o600,
			); err != nil {
				t.Fatal(err)
			}
			_, err := Load(configPath)
			segments := strings.Split(tc.name, ".")
			lastSegment := segments[len(segments)-1]
			if err == nil || !strings.Contains(err.Error(), lastSegment) ||
				!strings.Contains(err.Error(), "equal") {
				t.Fatalf("expected duplicate-value error for %s, got %v", tc.name, err)
			}
		})
	}
}

func TestLoadRejectsPreviousVersionsAndRemovedRuntimeFields(t *testing.T) {
	for _, test := range []struct {
		name string
		data string
		want string
	}{
		{"version 1", "version: 1\norganization: test\npolicies:\n  repository:\n    require_ruleset: true\n", "value must be 5"},
		{"version 2", "version: 2\norganization: test\npolicies:\n  repository:\n    require_ruleset: true\n", "value must be 5"},
		{"version 3", "version: 3\norganization: test\npolicies:\n  repository:\n    require_ruleset: true\n", "value must be 5"},
		{"version 4", "version: 4\norganization: test\npolicies:\n  repository:\n    require_ruleset: true\n", "value must be 5"},
		{"github host", "version: 5\norganization: test\ngithub:\n  web_url: https://github.com\npolicies:\n  repository:\n    require_ruleset: true\n", "additional properties 'github' not allowed"},
		{"output directory", "version: 5\norganization: test\noutput:\n  directory: results\npolicies:\n  repository:\n    require_ruleset: true\n", "additional properties 'output' not allowed"},
		{"code security policy", "version: 5\norganization: test\npolicies:\n  code_security:\n    configuration: approved\n", "additional properties 'code_security' not allowed"},
		{"CodeQL policy", "version: 5\norganization: test\npolicies:\n  dependencies:\n    codeql: true\n", "additional properties 'codeql' not allowed"},
		{"visibilities selector", "version: 5\norganization: test\nselectors:\n  visibilities: [public]\npolicies:\n  repository:\n    require_ruleset: true\n", "additional properties 'visibilities' not allowed"},
		{"include_topics selector", "version: 5\norganization: test\nselectors:\n  include_topics: [security]\npolicies:\n  repository:\n    require_ruleset: true\n", "additional properties 'include_topics' not allowed"},
		{"exclude_topics selector", "version: 5\norganization: test\nselectors:\n  exclude_topics: [exempt]\npolicies:\n  repository:\n    require_ruleset: true\n", "additional properties 'exclude_topics' not allowed"},
		{"custom_properties selector", "version: 5\norganization: test\nselectors:\n  custom_properties:\n    tier: critical\npolicies:\n  repository:\n    require_ruleset: true\n", "additional properties 'custom_properties' not allowed"},
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

func TestSchemaDrivesRuntimeDurationValidation(t *testing.T) {
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
	// This exercises the shared duration schema pattern only, independent
	// of any semantic range bound placed on a specific field (such as
	// inventory.timeout's 30m cap): it decodes straight to
	// validateConfigDocument rather than going through Load(), so large
	// pattern-valid durations remain schema-valid here even though Load()
	// would separately reject them on semantic grounds.
	for _, tc := range cases {
		data := "version: 5\norganization: test\ninventory:\n  timeout: \"" + tc.raw +
			"\"\npolicies:\n  repository:\n    require_ruleset: true\n"
		var document any
		if err := yaml.Unmarshal([]byte(data), &document); err != nil {
			t.Fatalf("%s: yaml.Unmarshal: %v", tc.raw, err)
		}
		err := validateConfigDocument(document)
		if got := err == nil; got != tc.valid {
			t.Errorf("%s: validateConfigDocument() valid = %v, want %v (err = %v)", tc.raw, got, tc.valid, err)
		}
	}
}

func TestSchemaSuppressionRepositoryPatternMatchesRuntimeValidation(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "schema", "segh-config-v5.schema.json"))
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

}

func TestLoadRejectsLenientRFC3339FormsInUnquotedSuppressionExpiry(t *testing.T) {
	// Without demoteTimestampScalars, YAML's default resolver decodes an
	// unquoted timestamp-looking scalar straight into a time.Time before the
	// schema-validation document is built, so an out-of-range offset or a
	// comma fractional separator never reaches the schema's format check as
	// the literal text the operator wrote.
	base := "version: 5\norganization: test\npolicies:\n  repository:\n    require_ruleset: true\n" +
		"suppressions:\n  - policy: p1\n    owner: someone\n    rationale: testing\n    expires: "
	for name, expires := range map[string]string{
		"unquoted out-of-range offset minute": "2026-01-01T00:00:00+00:60",
		"unquoted out-of-range offset hour":   "2026-01-01T00:00:00+24:00",
		"unquoted comma fractional separator": "2026-01-01T00:00:00,000Z",
		"quoted out-of-range offset minute":   `"2026-01-01T00:00:00+00:60"`,
		"quoted lowercase T and Z":            `"2026-01-01t00:00:00z"`,
		"quoted leap second":                  `"2016-12-31T23:59:60Z"`,
	} {
		t.Run(name, func(t *testing.T) {
			configPath := filepath.Join(t.TempDir(), "segh.yaml")
			if err := os.WriteFile(configPath, []byte(base+expires+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(configPath); err == nil ||
				!strings.Contains(err.Error(), "must be an RFC 3339 date-time") {
				t.Fatalf("Load() = %v, want an RFC 3339 date-time error", err)
			}
		})
	}
}

func TestLoadAcceptsUnquotedValidSuppressionExpiry(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "segh.yaml")
	data := "version: 5\norganization: test\npolicies:\n  repository:\n    require_ruleset: true\n" +
		"suppressions:\n  - policy: p1\n    owner: someone\n    rationale: testing\n    expires: 2026-06-15T12:30:00Z\n"
	if err := os.WriteFile(configPath, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Suppressions) != 1 || cfg.Suppressions[0].Expires == nil ||
		!cfg.Suppressions[0].Expires.Equal(time.Date(2026, 6, 15, 12, 30, 0, 0, time.UTC)) {
		t.Fatalf("unexpected decoded suppression: %#v", cfg.Suppressions)
	}
}

func TestLoadAcceptsSuppressionExpiryWithFractionAndOffset(t *testing.T) {
	// Confirms that every RFC 3339 form the schema's format check accepts
	// also decodes cleanly into the *time.Time the value ultimately becomes,
	// not just the plain "Z"-suffixed, fraction-free form the other tests use.
	for name, expires := range map[string]string{
		"fractional second with non-Z offset": `"2026-01-01T00:00:00.5+05:30"`,
		"fractional second beyond nanosecond": `"2026-01-01T00:00:00.1234567890123Z"`,
	} {
		t.Run(name, func(t *testing.T) {
			configPath := filepath.Join(t.TempDir(), "segh.yaml")
			data := "version: 5\norganization: test\npolicies:\n  repository:\n    require_ruleset: true\n" +
				"suppressions:\n  - policy: p1\n    owner: someone\n    rationale: testing\n    expires: " + expires + "\n"
			if err := os.WriteFile(configPath, []byte(data), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, err := Load(configPath)
			if err != nil {
				t.Fatalf("Load() = %v, want no error for a valid RFC 3339 date-time", err)
			}
			if len(cfg.Suppressions) != 1 || cfg.Suppressions[0].Expires == nil {
				t.Fatalf("unexpected decoded suppression: %#v", cfg.Suppressions)
			}
		})
	}
}
