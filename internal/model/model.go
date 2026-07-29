package model

import "time"

const (
	InventorySchemaVersion = 2
	PolicySchemaVersion    = 2
	ReportSchemaVersion    = 2
)

type Availability string

const (
	Available   Availability = "available"
	Unknown     Availability = "unknown"
	Unsupported Availability = "unsupported"
)

type Observed[T any] struct {
	State  Availability `json:"state" yaml:"state"`
	Value  T            `json:"value,omitempty" yaml:"value,omitempty"`
	Source string       `json:"source,omitempty" yaml:"source,omitempty"`
	Reason string       `json:"reason,omitempty" yaml:"reason,omitempty"`
}

type Inventory struct {
	SchemaVersion int                   `json:"schema_version"`
	Organization  string                `json:"organization"`
	GitHubHost    string                `json:"github_host"`
	GeneratedAt   time.Time             `json:"generated_at"`
	Complete      bool                  `json:"complete"`
	Total         int                   `json:"total"`
	Selected      int                   `json:"selected"`
	Excluded      int                   `json:"excluded"`
	Repositories  []Repository          `json:"repositories"`
	Exclusions    []RepositoryExclusion `json:"exclusions,omitempty"`
	Errors        []RunError            `json:"errors,omitempty"`
}

type RepositoryExclusion struct {
	Repository string `json:"repository"`
	Reason     string `json:"reason"`
}

type Repository struct {
	ID                         int64                   `json:"id"`
	FullName                   string                  `json:"full_name"`
	HTMLURL                    string                  `json:"html_url,omitempty"`
	Visibility                 string                  `json:"visibility"`
	Archived                   bool                    `json:"archived"`
	Disabled                   bool                    `json:"disabled"`
	Fork                       bool                    `json:"fork"`
	Template                   bool                    `json:"template"`
	DefaultBranch              string                  `json:"default_branch"`
	Topics                     []string                `json:"topics,omitempty"`
	CustomProperties           map[string]string       `json:"custom_properties,omitempty"`
	ActionsEnabled             Observed[bool]          `json:"actions_enabled"`
	AllowedActions             Observed[string]        `json:"allowed_actions"`
	DefaultWorkflowPermissions Observed[string]        `json:"default_workflow_permissions"`
	ForkPRApproval             Observed[bool]          `json:"fork_pr_approval"`
	Ruleset                    Observed[bool]          `json:"ruleset"`
	BranchProtection           Observed[bool]          `json:"branch_protection"`
	RequiredPullRequests       Observed[bool]          `json:"required_pull_requests"`
	RequiredChecks             Observed[bool]          `json:"required_checks"`
	ForcePushRestricted        Observed[bool]          `json:"force_push_restricted"`
	DeletionRestricted         Observed[bool]          `json:"deletion_restricted"`
	CodeSecurityConfiguration  Observed[string]        `json:"code_security_configuration"`
	CodeQL                     Observed[bool]          `json:"codeql"`
	SecretScanning             Observed[bool]          `json:"secret_scanning"`
	PushProtection             Observed[bool]          `json:"push_protection"`
	DependencyGraph            Observed[bool]          `json:"dependency_graph"`
	DependabotAlerts           Observed[bool]          `json:"dependabot_alerts"`
	DependabotSecurityUpdates  Observed[bool]          `json:"dependabot_security_updates"`
	SecurityMD                 Observed[bool]          `json:"security_md"`
	SHAPinningEnforced         Observed[bool]          `json:"sha_pinning_enforced"`
	Capabilities               map[string]Availability `json:"capabilities,omitempty"`
}

type PolicyStatus string

const (
	PolicyPass        PolicyStatus = "pass"
	PolicyFail        PolicyStatus = "fail"
	PolicyUnknown     PolicyStatus = "unknown"
	PolicyUnsupported PolicyStatus = "unsupported"
	PolicyExempt      PolicyStatus = "exempt"
)

type PolicyResult struct {
	Repository  string       `json:"repository"`
	PolicyID    string       `json:"policy_id"`
	Status      PolicyStatus `json:"status"`
	Severity    string       `json:"severity"`
	Observed    any          `json:"observed,omitempty"`
	Expected    any          `json:"expected,omitempty"`
	Evidence    string       `json:"evidence,omitempty"`
	Remediation string       `json:"remediation"`
	Suppression *Suppression `json:"suppression,omitempty"`
}

type Suppression struct {
	Policy     string     `json:"policy" yaml:"policy"`
	Repository string     `json:"repository,omitempty" yaml:"repository,omitempty"`
	Owner      string     `json:"owner" yaml:"owner"`
	Rationale  string     `json:"rationale" yaml:"rationale"`
	Expires    *time.Time `json:"expires,omitempty" yaml:"expires,omitempty"`
}

type Audit struct {
	SchemaVersion int            `json:"schema_version"`
	Organization  string         `json:"organization"`
	GeneratedAt   time.Time      `json:"generated_at"`
	Results       []PolicyResult `json:"results"`
	Counts        map[string]int `json:"counts"`
}

type RunError struct {
	Repository string `json:"repository,omitempty"`
	Component  string `json:"component"`
	Kind       string `json:"kind"`
	Message    string `json:"message"`
}
