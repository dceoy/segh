package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/dceoy/segh/internal/model"
	"gopkg.in/yaml.v3"
)

type Config struct {
	SourceDir    string              `yaml:"-"`
	Version      int                 `yaml:"version"`
	Organization string              `yaml:"organization"`
	GitHub       GitHub              `yaml:"github"`
	Auth         Auth                `yaml:"auth"`
	Selectors    Selectors           `yaml:"selectors"`
	Policies     Policies            `yaml:"policies"`
	Suppressions []model.Suppression `yaml:"suppressions"`
	Scanners     Scanners            `yaml:"scanners"`
	Execution    Execution           `yaml:"execution"`
	Publication  Publication         `yaml:"publication"`
	Output       Output              `yaml:"output"`
	PullRequest  PullRequest         `yaml:"pull_request"`
}

type GitHub struct {
	WebURL     string `yaml:"web_url"`
	APIURL     string `yaml:"api_url"`
	GraphQLURL string `yaml:"graphql_url"`
}

type Auth struct {
	AppID              int64  `yaml:"app_id"`
	InstallationID     int64  `yaml:"installation_id"`
	PrivateKeyFile     string `yaml:"private_key_file"`
	PrivateKeyEnv      string `yaml:"private_key_env"`
	TokenEnv           string `yaml:"token_env"`
	AllowExistingToken bool   `yaml:"allow_existing_token"`
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
	RequireFullSHA               bool   `yaml:"require_full_sha"`
	RequireSHAPinningEnforcement bool   `yaml:"require_sha_pinning_enforcement"`
	RequireRenovate              bool   `yaml:"require_renovate"`
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

type Scanners struct {
	Zizmor    Scanner `yaml:"zizmor"`
	Trivy     Scanner `yaml:"trivy"`
	Scorecard Scanner `yaml:"scorecard"`
	Semgrep   Semgrep `yaml:"semgrep"`
}

type Scanner struct {
	Enabled    bool          `yaml:"enabled"`
	Version    string        `yaml:"version"`
	Timeout    time.Duration `yaml:"timeout"`
	CPUSeconds int           `yaml:"cpu_seconds"`
	MemoryMB   int           `yaml:"memory_mb"`
	Exclude    []string      `yaml:"exclude"`
}

type Semgrep struct {
	Scanner `yaml:",inline"`
	Rules   []string `yaml:"rules"`
}

type Execution struct {
	Concurrency       int           `yaml:"concurrency"`
	RepositoryTimeout time.Duration `yaml:"repository_timeout"`
	TotalTimeout      time.Duration `yaml:"total_timeout"`
	APITimeout        time.Duration `yaml:"api_timeout"`
	MaxRetries        int           `yaml:"max_retries"`
	BaseRetryDelay    time.Duration `yaml:"base_retry_delay"`
	DryRun            bool          `yaml:"dry_run"`
}

type Publication struct {
	Enabled        bool          `yaml:"enabled"`
	PollTimeout    time.Duration `yaml:"poll_timeout"`
	CategoryPrefix string        `yaml:"category_prefix"`
}

type Output struct {
	Directory     string `yaml:"directory"`
	JSONL         bool   `yaml:"jsonl"`
	RetentionDays int    `yaml:"retention_days"`
}

type PullRequest struct {
	ReportOnly bool                     `yaml:"report_only"`
	Thresholds map[string]GateThreshold `yaml:"thresholds"`
}

type GateThreshold struct {
	MinimumSeverity string   `yaml:"minimum_severity"`
	Rules           []string `yaml:"rules"`
}

func Default() Config {
	return Config{
		SourceDir: ".",
		Version:   1,
		GitHub: GitHub{
			WebURL:     "https://github.com",
			APIURL:     "https://api.github.com",
			GraphQLURL: "https://api.github.com/graphql",
		},
		Auth:      Auth{PrivateKeyEnv: "SEGH_GITHUB_APP_PRIVATE_KEY", TokenEnv: "SEGH_GITHUB_TOKEN"}, // #nosec G101 -- these are environment variable names, not credentials.
		Selectors: Selectors{ExcludeArchived: true, ExcludeForks: true},
		Execution: Execution{
			Concurrency:       4,
			RepositoryTimeout: 20 * time.Minute,
			TotalTimeout:      6 * time.Hour,
			APITimeout:        30 * time.Second,
			MaxRetries:        4,
			BaseRetryDelay:    time.Second,
		},
		Publication: Publication{PollTimeout: 2 * time.Minute, CategoryPrefix: "segh"},
		Output:      Output{Directory: "segh-results", JSONL: true, RetentionDays: 14},
		PullRequest: PullRequest{Thresholds: map[string]GateThreshold{}},
	}
}

func Load(path string) (Config, []byte, error) {
	cfg := Default()
	data, err := boundedFile(path, 2<<20)
	if err != nil {
		return Config{}, nil, fmt.Errorf("read config: %w", err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return Config{}, nil, fmt.Errorf("decode config: %w", err)
	}
	cfg.SourceDir = filepath.Clean(baseDir(path))
	if value := os.Getenv("SEGH_GITHUB_APP_ID"); value != "" {
		cfg.Auth.AppID, err = strconv.ParseInt(value, 10, 64)
		if err != nil {
			return Config{}, nil, fmt.Errorf("SEGH_GITHUB_APP_ID must be an integer")
		}
	}
	if value := os.Getenv("SEGH_GITHUB_INSTALLATION_ID"); value != "" {
		cfg.Auth.InstallationID, err = strconv.ParseInt(value, 10, 64)
		if err != nil {
			return Config{}, nil, fmt.Errorf("SEGH_GITHUB_INSTALLATION_ID must be an integer")
		}
	}
	if err := cfg.Validate(filepath.Dir(path)); err != nil {
		return Config{}, nil, err
	}
	return cfg, data, nil
}

func baseDir(path string) string {
	dir, err := filepath.Abs(filepath.Dir(path))
	if err != nil {
		return filepath.Clean(filepath.Dir(path))
	}
	return dir
}

func (c *Config) Validate(baseDir string) error {
	var errs []error
	if c.Version != 1 {
		errs = append(errs, fmt.Errorf("version must be 1"))
	}
	if c.Organization == "" {
		errs = append(errs, fmt.Errorf("organization is required"))
	}
	for name, raw := range map[string]string{"github.web_url": c.GitHub.WebURL, "github.api_url": c.GitHub.APIURL, "github.graphql_url": c.GitHub.GraphQLURL} {
		if !strings.HasPrefix(raw, "https://") && !strings.HasPrefix(raw, "http://localhost") && !strings.HasPrefix(raw, "http://127.0.0.1") {
			errs = append(errs, fmt.Errorf("%s must use HTTPS (HTTP is allowed only for local tests)", name))
		}
	}
	if c.Auth.PrivateKeyFile != "" && !filepath.IsAbs(c.Auth.PrivateKeyFile) {
		c.Auth.PrivateKeyFile = filepath.Clean(filepath.Join(baseDir, c.Auth.PrivateKeyFile))
	}
	if c.Auth.PrivateKeyFile != "" {
		c.Auth.PrivateKeyEnv = ""
	}
	if c.Auth.AllowExistingToken && c.Auth.TokenEnv == "" {
		errs = append(errs, fmt.Errorf("auth.token_env is required when auth.allow_existing_token is true"))
	}
	if c.Execution.Concurrency < 1 || c.Execution.Concurrency > 64 {
		errs = append(errs, fmt.Errorf("execution.concurrency must be between 1 and 64"))
	}
	for name, value := range map[string]time.Duration{
		"execution.repository_timeout": c.Execution.RepositoryTimeout,
		"execution.total_timeout":      c.Execution.TotalTimeout,
		"execution.api_timeout":        c.Execution.APITimeout,
		"execution.base_retry_delay":   c.Execution.BaseRetryDelay,
	} {
		if value <= 0 {
			errs = append(errs, fmt.Errorf("%s must be positive", name))
		}
	}
	if c.Execution.MaxRetries < 0 || c.Execution.MaxRetries > 10 {
		errs = append(errs, fmt.Errorf("execution.max_retries must be between 0 and 10"))
	}
	if c.Output.RetentionDays < 1 || c.Output.RetentionDays > 400 {
		errs = append(errs, fmt.Errorf("output.retention_days must be between 1 and 400"))
	}
	if c.Output.Directory == "" {
		errs = append(errs, fmt.Errorf("output.directory is required"))
	}
	if c.Publication.CategoryPrefix == "" {
		errs = append(errs, fmt.Errorf("publication.category_prefix is required"))
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
	if c.Scanners.Semgrep.Enabled && len(c.Scanners.Semgrep.Rules) == 0 {
		errs = append(errs, fmt.Errorf("scanners.semgrep.rules is required when Semgrep is enabled"))
	}
	for i, rule := range c.Scanners.Semgrep.Rules {
		if strings.Contains(rule, "://") || strings.HasPrefix(rule, "p/") || strings.HasPrefix(rule, "r/") {
			errs = append(errs, fmt.Errorf("scanners.semgrep.rules[%d] must be a repository-controlled local file", i))
			continue
		}
		if !filepath.IsAbs(rule) {
			rule = filepath.Clean(filepath.Join(baseDir, rule))
			c.Scanners.Semgrep.Rules[i] = rule
		}
		if c.Scanners.Semgrep.Enabled {
			info, err := os.Stat(rule)
			if err != nil || !info.Mode().IsRegular() {
				errs = append(errs, fmt.Errorf("scanners.semgrep.rules[%d] must be a regular file", i))
			}
		}
	}
	for name, scanner := range map[string]Scanner{
		"zizmor": c.Scanners.Zizmor, "trivy": c.Scanners.Trivy,
		"scorecard": c.Scanners.Scorecard, "semgrep": c.Scanners.Semgrep.Scanner,
	} {
		if scanner.Enabled && scanner.Version == "" {
			errs = append(errs, fmt.Errorf("scanners.%s.version is required when enabled", name))
		}
		if scanner.Enabled && (scanner.CPUSeconds <= 0 || scanner.MemoryMB <= 0) {
			errs = append(errs, fmt.Errorf("scanners.%s requires positive cpu_seconds and memory_mb limits", name))
		}
		if scanner.CPUSeconds < 0 || scanner.MemoryMB < 0 {
			errs = append(errs, fmt.Errorf("scanners.%s resource limits cannot be negative", name))
		}
	}
	for name, threshold := range c.PullRequest.Thresholds {
		if !slices.Contains([]string{"note", "warning", "error", "none", "low", "medium", "high", "critical"}, strings.ToLower(threshold.MinimumSeverity)) {
			errs = append(errs, fmt.Errorf("pull_request.thresholds.%s.minimum_severity is invalid", name))
		}
	}
	return errors.Join(errs...)
}

func boundedFile(path string, limit int64) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return nil, fmt.Errorf("file must be regular and no larger than %d bytes", limit)
	}
	return os.ReadFile(path) // #nosec G304 -- caller selected path was statted and size-bounded.
}

func Digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
