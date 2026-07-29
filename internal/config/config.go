package config

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path"
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
	Directory     string `yaml:"directory"`
	JSONL         bool   `yaml:"jsonl"`
	RetentionDays int    `yaml:"retention_days"`
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
		Output:    Output{Directory: "segh-results", JSONL: true, RetentionDays: 14},
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
	if err := validateGitHubURL(c.GitHub.WebURL); err != nil {
		errs = append(errs, fmt.Errorf("github.web_url %w", err))
	}
	if c.Inventory.Concurrency < 1 || c.Inventory.Concurrency > 64 {
		errs = append(errs, fmt.Errorf("inventory.concurrency must be between 1 and 64"))
	}
	if c.Inventory.Timeout <= 0 {
		errs = append(errs, fmt.Errorf("inventory.timeout must be positive"))
	}
	if c.Output.RetentionDays < 1 || c.Output.RetentionDays > 400 {
		errs = append(errs, fmt.Errorf("output.retention_days must be between 1 and 400"))
	}
	if c.Output.Directory == "" {
		errs = append(errs, fmt.Errorf("output.directory is required"))
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

func validateGitHubURL(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" ||
		(parsed.EscapedPath() != "" && parsed.EscapedPath() != "/") {
		return fmt.Errorf("must be an origin URL without credentials, path, query, or fragment")
	}
	if parsed.Scheme == "https" {
		return nil
	}
	if parsed.Scheme == "http" {
		hostname := parsed.Hostname()
		if hostname == "localhost" || net.ParseIP(hostname).IsLoopback() {
			return nil
		}
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
