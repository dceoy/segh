package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"time"

	"github.com/dceoy/segh/internal/model"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Version      int                 `yaml:"version"`
	Organization string              `yaml:"organization"`
	Inventory    Inventory           `yaml:"inventory"`
	SourceScan   SourceScan          `yaml:"source_scan"`
	Selectors    Selectors           `yaml:"selectors"`
	Policies     Policies            `yaml:"policies"`
	Suppressions []model.Suppression `yaml:"suppressions"`
}

type Duration time.Duration

type Inventory struct {
	Concurrency int      `yaml:"concurrency"`
	Timeout     Duration `yaml:"timeout"`
}

type SourceScan struct {
	Enabled     bool `yaml:"enabled"`
	Concurrency int  `yaml:"concurrency"`
}

type Selectors struct {
	ExcludeArchived bool     `yaml:"exclude_archived"`
	ExcludeDisabled bool     `yaml:"exclude_disabled"`
	ExcludeForks    bool     `yaml:"exclude_forks"`
	Repositories    []string `yaml:"repositories"`
	Exclude         []string `yaml:"exclude"`
}

type Policies struct {
	Actions      ActionsPolicy      `yaml:"actions"`
	Dependencies DependenciesPolicy `yaml:"dependencies"`
	Repository   RepositoryPolicy   `yaml:"repository"`
}

type ActionsPolicy struct {
	Enabled                      *bool  `yaml:"enabled"`
	AllowedActions               string `yaml:"allowed_actions"`
	DefaultWorkflowPermissions   string `yaml:"default_workflow_permissions"`
	RequireSHAPinningEnforcement bool   `yaml:"require_sha_pinning_enforcement"`
	RequireForkPRApproval        *bool  `yaml:"require_fork_pr_approval"`
}

type DependenciesPolicy struct {
	DependencyGraph           *bool `yaml:"dependency_graph"`
	DependabotAlerts          *bool `yaml:"dependabot_alerts"`
	DependabotSecurityUpdates *bool `yaml:"dependabot_security_updates"`
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
		Version: 5,
		Inventory: Inventory{
			Concurrency: 4,
			Timeout:     Duration(30 * time.Minute),
		},
		SourceScan: SourceScan{
			Concurrency: 4,
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
	var root yaml.Node
	dec := yaml.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&root); err != nil {
		return Config{}, fmt.Errorf("decode config: %w", err)
	}
	var trailing yaml.Node
	if err := dec.Decode(&trailing); err == nil {
		return Config{}, fmt.Errorf("decode config: multiple YAML documents are not allowed")
	} else if !errors.Is(err, io.EOF) {
		return Config{}, fmt.Errorf("decode config: %w", err)
	}
	demoteTimestampScalars(&root)
	var document any
	if err := root.Decode(&document); err != nil {
		return Config{}, fmt.Errorf("decode config: %w", err)
	}
	if err := validateConfigDocument(document); err != nil {
		return Config{}, err
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("decode typed config: %w", err)
	}
	if err := cfg.validateSemantics(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// demoteTimestampScalars retags every "!!timestamp" scalar reachable from
// node (including through anchors and aliases) as a plain string. YAML's
// default resolver would otherwise decode a timestamp-looking scalar
// straight into a time.Time before the schema-validation document is built,
// silently accepting or reinterpreting an out-of-range offset or
// non-standard separator instead of leaving the literal text for the
// schema's RFC 3339 format check to reject.
func demoteTimestampScalars(node *yaml.Node) {
	if node.Kind == yaml.ScalarNode && node.Tag == "!!timestamp" {
		node.Tag = "!!str"
	}
	for _, child := range node.Content {
		demoteTimestampScalars(child)
	}
}

func (c Config) validateSemantics() error {
	var errs []error
	if time.Duration(c.Inventory.Timeout) > 30*time.Minute {
		errs = append(errs, fmt.Errorf("inventory.timeout must not exceed 30m"))
	}
	for i, suppression := range c.Suppressions {
		if _, err := path.Match(suppression.Repository, "owner/repository"); suppression.Repository != "" && err != nil {
			errs = append(errs, fmt.Errorf("suppressions[%d].repository is not a valid glob", i))
		}
	}
	return errors.Join(errs...)
}

func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	parsed, err := time.ParseDuration(node.Value)
	if err != nil {
		return fmt.Errorf("parse duration: %w", err)
	}
	*d = Duration(parsed)
	return nil
}
