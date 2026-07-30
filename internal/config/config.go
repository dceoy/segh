package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"slices"
	"time"

	"github.com/dceoy/segh/internal/model"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Version      int                 `yaml:"version"`
	Organization string              `yaml:"organization"`
	Inventory    Inventory           `yaml:"inventory"`
	Selectors    Selectors           `yaml:"selectors"`
	Policies     Policies            `yaml:"policies"`
	Suppressions []model.Suppression `yaml:"suppressions"`
}

type Duration time.Duration

type Inventory struct {
	Concurrency int      `yaml:"concurrency"`
	Timeout     Duration `yaml:"timeout"`
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
	Configuration string `yaml:"configuration"`
	present       bool
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

func Default() Config {
	return Config{
		Version: 3,
		Inventory: Inventory{
			Concurrency: 4,
			Timeout:     Duration(30 * time.Minute),
		},
		Selectors: Selectors{ExcludeArchived: true, ExcludeForks: true},
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
	if c.Version != 3 {
		errs = append(errs, fmt.Errorf("version must be 3"))
	}
	if c.Organization == "" {
		errs = append(errs, fmt.Errorf("organization is required"))
	}
	if !c.Policies.configured() {
		errs = append(errs, fmt.Errorf("at least one policy must be configured"))
	}
	if c.Policies.CodeSecurity.present && c.Policies.CodeSecurity.Configuration == "" {
		errs = append(errs, fmt.Errorf("policies.code_security.configuration is required"))
	}
	if c.Inventory.Concurrency < 1 || c.Inventory.Concurrency > 64 {
		errs = append(errs, fmt.Errorf("inventory.concurrency must be between 1 and 64"))
	}
	if time.Duration(c.Inventory.Timeout) <= 0 {
		errs = append(errs, fmt.Errorf("inventory.timeout must be positive"))
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

const (
	durationPatternText = `^\+?(([0-9]{1,5}(\.[0-9]{0,9})?|\.[0-9]{1,9})(ns|us|µs|μs|ms|s|m|h)){1,16}$`
	zeroDurationPattern = `^\+?((0{1,5}(\.0{0,9})?|\.0{1,9})(ns|us|µs|μs|ms|s|m|h)){1,16}$`
)

var durationPattern = regexp.MustCompile(durationPatternText)
var zeroDuration = regexp.MustCompile(zeroDurationPattern)

func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.ScalarNode || node.Tag != "!!str" {
		return fmt.Errorf("duration must be a string")
	}
	if !durationPattern.MatchString(node.Value) || zeroDuration.MatchString(node.Value) {
		return fmt.Errorf("duration must be positive and use at most 16 components with 5 integer and 9 fractional digits each")
	}
	parsed, err := time.ParseDuration(node.Value)
	if err != nil {
		return fmt.Errorf("parse duration: %w", err)
	}
	*d = Duration(parsed)
	return nil
}

func (p *CodeSecurityPolicy) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("code security policy must be an object")
	}
	for i := 0; i < len(node.Content); i += 2 {
		if key := node.Content[i].Value; key != "configuration" {
			return fmt.Errorf("field %s not found in type config.CodeSecurityPolicy", key)
		}
	}
	type plain CodeSecurityPolicy
	var decoded plain
	if err := node.Decode(&decoded); err != nil {
		return err
	}
	*p = CodeSecurityPolicy(decoded)
	p.present = true
	return nil
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
	if p.CodeSecurity.Configuration != "" {
		return true
	}
	repository := p.Repository
	return repository.RequireRuleset || repository.RequireBranchProtection || repository.RequirePullRequest ||
		repository.RequireRequiredChecks || repository.RestrictForcePushes || repository.RestrictDeletions ||
		repository.RequireSecurityMD || len(repository.AllowedVisibilities) > 0 || repository.ProhibitArchived ||
		repository.ProhibitForks || repository.ProhibitTemplates
}
