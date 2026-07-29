package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/dceoy/segh/internal/model"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Version      int                 `yaml:"version"`
	Organization string              `yaml:"organization"`
	GitHub       GitHub              `yaml:"github"`
	Inventory    Inventory           `yaml:"inventory"`
	Selectors    Selectors           `yaml:"selectors"`
	Policies     Policies            `yaml:"policies"`
	Suppressions []model.Suppression `yaml:"suppressions"`
	Output       Output              `yaml:"output"`
}

type GitHub struct {
	WebURL string `yaml:"web_url"`
}

type Inventory struct {
	Concurrency int           `yaml:"concurrency"`
	Timeout     time.Duration `yaml:"timeout"`
}

type Selectors struct {
	ExcludeArchived  bool              `yaml:"exclude_archived"`
	ExcludeDisabled  bool              `yaml:"exclude_disabled"`
	ExcludeForks     bool              `yaml:"exclude_forks"`
	Visibilities     []string          `yaml:"visibilities"`
	IncludeTopics    []string          `yaml:"include_topics"`
	ExcludeTopics    []string          `yaml:"exclude_topics"`
	CustomProperties map[string]string `yaml:"custom_properties"`
	Repositories     []string          `yaml:"repositories"`
	Exclude          []string          `yaml:"exclude"`
}

type Policies struct {
	Actions      ActionsPolicy      `yaml:"actions"`
	CodeSecurity CodeSecurityPolicy `yaml:"code_security"`
	Repository   RepositoryPolicy   `yaml:"repository"`
}

type ActionsPolicy struct {
	Enabled                      *bool  `yaml:"enabled"`
	AllowedActions               string `yaml:"allowed_actions"`
	DefaultWorkflowPermissions   string `yaml:"default_workflow_permissions"`
	RequireSHAPinningEnforcement bool   `yaml:"require_sha_pinning_enforcement"`
	RequireForkPRApproval        *bool  `yaml:"require_fork_pr_approval"`
}

type CodeSecurityPolicy struct {
	Configuration     string `yaml:"configuration"`
	CodeQL            string `yaml:"codeql"`
	SecretScanning    string `yaml:"secret_scanning"`
	PushProtection    string `yaml:"push_protection"`
	DependencyGraph   string `yaml:"dependency_graph"`
	DependabotAlerts  string `yaml:"dependabot_alerts"`
	DependabotUpdates string `yaml:"dependabot_security_updates"`
}

type RepositoryPolicy struct {
	RequireRuleset          bool     `yaml:"require_ruleset"`
	RequireBranchProtection bool     `yaml:"require_branch_protection"`
	RequirePullRequest      bool     `yaml:"require_pull_request"`
	RequireRequiredChecks   bool     `yaml:"require_required_checks"`
	RestrictForcePushes     bool     `yaml:"restrict_force_pushes"`
	RestrictDeletions       bool     `yaml:"restrict_deletions"`
	RequireSecurityMD       bool     `yaml:"require_security_md"`
	AllowedVisibilities     []string `yaml:"allowed_visibilities"`
	ProhibitArchived        bool     `yaml:"prohibit_archived"`
	ProhibitForks           bool     `yaml:"prohibit_forks"`
	ProhibitTemplates       bool     `yaml:"prohibit_templates"`
}

type Output struct {
	Directory string `yaml:"directory"`
}

func Default() Config {
	return Config{
		Version: 2,
		GitHub: GitHub{
			WebURL: "https://github.com",
		},
		Inventory: Inventory{
			Concurrency: 4,
			Timeout:     30 * time.Minute,
		},
		Selectors: Selectors{ExcludeArchived: true, ExcludeForks: true},
		Output:    Output{Directory: "segh-results"},
	}
}

func Load(configPath string) (Config, error) {
	cfg := Default()
	info, err := os.Stat(configPath)
	if err != nil {
		return Config{}, fmt.Errorf("stat config: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() > 2<<20 {
		return Config{}, fmt.Errorf("read config: file must be regular and no larger than 2 MiB")
	}
	data, err := os.ReadFile(configPath) // #nosec G304 -- the CLI operator explicitly selects the configuration.
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("decode config: %w", err)
	}
	var trailing any
	if err := dec.Decode(&trailing); err == nil {
		return Config{}, fmt.Errorf("decode config: multiple YAML documents are not allowed")
	} else if !errors.Is(err, io.EOF) {
		return Config{}, fmt.Errorf("decode config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c Config) Validate() error {
	var errs []error
	if c.Version != 2 {
		errs = append(errs, fmt.Errorf("version must be 2"))
	}
	if c.Organization == "" {
		errs = append(errs, fmt.Errorf("organization is required"))
	}
	if !c.Policies.configured() {
		errs = append(errs, fmt.Errorf("at least one policy must be configured"))
	}
	if err := validateGitHubURL(c.GitHub.WebURL); err != nil {
		errs = append(errs, fmt.Errorf("github.web_url %w", err))
	}
	if c.Inventory.Concurrency < 1 || c.Inventory.Concurrency > 64 {
		errs = append(errs, fmt.Errorf("inventory.concurrency must be between 1 and 64"))
	}
	if c.Inventory.Timeout <= 0 {
		errs = append(errs, fmt.Errorf("inventory.timeout must be positive"))
	}
	if c.Output.Directory == "" {
		errs = append(errs, fmt.Errorf("output.directory is required"))
	}
	for name, values := range map[string][]string{
		"selectors.visibilities":                   c.Selectors.Visibilities,
		"selectors.include_topics":                 c.Selectors.IncludeTopics,
		"selectors.exclude_topics":                 c.Selectors.ExcludeTopics,
		"selectors.repositories":                   c.Selectors.Repositories,
		"selectors.exclude":                        c.Selectors.Exclude,
		"policies.repository.allowed_visibilities": c.Policies.Repository.AllowedVisibilities,
	} {
		if duplicate, ok := firstDuplicate(values); ok {
			errs = append(errs, fmt.Errorf("%s contains duplicate value %q", name, duplicate))
		}
	}
	for _, visibility := range append(slices.Clone(c.Selectors.Visibilities), c.Policies.Repository.AllowedVisibilities...) {
		if !slices.Contains([]string{"public", "private", "internal"}, visibility) {
			errs = append(errs, fmt.Errorf("invalid visibility %q", visibility))
		}
	}
	if value := c.Policies.Actions.DefaultWorkflowPermissions; value != "" && value != "read" && value != "write" {
		errs = append(errs, fmt.Errorf("policies.actions.default_workflow_permissions must be read or write"))
	}
	if value := c.Policies.Actions.AllowedActions; value != "" && !slices.Contains([]string{"all", "local_only", "selected"}, value) {
		errs = append(errs, fmt.Errorf("policies.actions.allowed_actions must be all, local_only, or selected"))
	}
	for name, value := range map[string]string{
		"policies.code_security.codeql":                      c.Policies.CodeSecurity.CodeQL,
		"policies.code_security.secret_scanning":             c.Policies.CodeSecurity.SecretScanning,
		"policies.code_security.push_protection":             c.Policies.CodeSecurity.PushProtection,
		"policies.code_security.dependency_graph":            c.Policies.CodeSecurity.DependencyGraph,
		"policies.code_security.dependabot_alerts":           c.Policies.CodeSecurity.DependabotAlerts,
		"policies.code_security.dependabot_security_updates": c.Policies.CodeSecurity.DependabotUpdates,
	} {
		if value != "" && value != "required" && value != "disabled" {
			errs = append(errs, fmt.Errorf("%s must be required or disabled", name))
		}
	}
	for i, suppression := range c.Suppressions {
		if suppression.Policy == "" || suppression.Owner == "" || suppression.Rationale == "" {
			errs = append(errs, fmt.Errorf("suppressions[%d] requires policy, owner, and rationale", i))
		}
		if _, err := path.Match(suppression.Repository, "owner/repository"); suppression.Repository != "" && err != nil {
			errs = append(errs, fmt.Errorf("suppressions[%d].repository is not a valid glob", i))
		}
	}
	return errors.Join(errs...)
}

func firstDuplicate(values []string) (string, bool) {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			return value, true
		}
		seen[value] = struct{}{}
	}
	return "", false
}

func (p Policies) configured() bool {
	actions := p.Actions
	if actions.Enabled != nil || actions.AllowedActions != "" || actions.DefaultWorkflowPermissions != "" ||
		actions.RequireSHAPinningEnforcement || actions.RequireForkPRApproval != nil {
		return true
	}
	code := p.CodeSecurity
	if code.Configuration != "" || code.CodeQL != "" || code.SecretScanning != "" || code.PushProtection != "" ||
		code.DependencyGraph != "" || code.DependabotAlerts != "" || code.DependabotUpdates != "" {
		return true
	}
	repository := p.Repository
	return repository.RequireRuleset || repository.RequireBranchProtection || repository.RequirePullRequest ||
		repository.RequireRequiredChecks || repository.RestrictForcePushes || repository.RestrictDeletions ||
		repository.RequireSecurityMD || len(repository.AllowedVisibilities) > 0 || repository.ProhibitArchived ||
		repository.ProhibitForks || repository.ProhibitTemplates
}

// loopbackIPv4Pattern matches only the canonical dotted-quad 127.0.0.0/8
// spellings that the github.web_url JSON Schema pattern also accepts.
// Alternate loopback representations (IPv4-mapped IPv6 such as
// ::ffff:127.0.0.1, or expanded IPv6 forms such as 0:0:0:0:0:0:0:1) are
// deliberately rejected here so the schema stays an exact, auditable
// description of what this validator accepts rather than an approximation
// of net.IP.IsLoopback's broader notion of "loopback".
var loopbackIPv4Pattern = regexp.MustCompile(
	`^127(?:\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3}$`,
)

func isLoopbackHostname(hostname string) bool {
	return hostname == "localhost" || hostname == "::1" || loopbackIPv4Pattern.MatchString(hostname)
}

func validateGitHubURL(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" ||
		(parsed.EscapedPath() != "" && parsed.EscapedPath() != "/") {
		return fmt.Errorf("must be an origin URL without credentials, path, query, or fragment")
	}
	if parsed.Scheme == "https" {
		return nil
	}
	if parsed.Scheme == "http" && isLoopbackHostname(parsed.Hostname()) {
		return nil
	}
	return fmt.Errorf("must use HTTPS (HTTP is allowed only for local tests)")
}

func (c Config) GitHubHostname() (string, error) {
	parsed, err := url.Parse(c.GitHub.WebURL)
	if err != nil || parsed.Hostname() == "" {
		return "", fmt.Errorf("invalid github.web_url")
	}
	return strings.ToLower(parsed.Host), nil
}
