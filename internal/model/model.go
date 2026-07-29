package model

import "time"

const (
	InventorySchemaVersion = 1
	PolicySchemaVersion    = 1
	ScanSchemaVersion      = 1
	ReportSchemaVersion    = 1
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
	CloneURL                   string                  `json:"clone_url,omitempty"`
	Visibility                 string                  `json:"visibility"`
	Archived                   bool                    `json:"archived"`
	Disabled                   bool                    `json:"disabled"`
	Fork                       bool                    `json:"fork"`
	Template                   bool                    `json:"template"`
	DefaultBranch              string                  `json:"default_branch"`
	DefaultBranchSHA           Observed[string]        `json:"default_branch_sha"`
	Languages                  map[string]int64        `json:"languages,omitempty"`
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
	FullSHAPinning             Observed[bool]          `json:"full_sha_pinning"`
	ActionPinningStatus        Observed[string]        `json:"action_pinning_status"`
	SHAPinningEnforced         Observed[bool]          `json:"sha_pinning_enforced"`
	RenovateConfigured         Observed[bool]          `json:"renovate_configured"`
	LastSuccessfulScan         *time.Time              `json:"last_successful_scan,omitempty"`
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

type ScannerStatus string

const (
	ScannerClean    ScannerStatus = "clean"
	ScannerFindings ScannerStatus = "findings"
	ScannerFailed   ScannerStatus = "failed"
	ScannerSkipped  ScannerStatus = "skipped"
	ScannerPlanned  ScannerStatus = "planned"
)

type ScannerResult struct {
	Repository       string           `json:"repository"`
	Scanner          string           `json:"scanner"`
	Version          string           `json:"version"`
	Status           ScannerStatus    `json:"status"`
	StartedAt        time.Time        `json:"started_at,omitempty"`
	DurationMS       int64            `json:"duration_ms,omitempty"`
	ResultPath       string           `json:"result_path,omitempty"`
	DiagnosticPath   string           `json:"diagnostic_path,omitempty"`
	Findings         int              `json:"findings"`
	FindingSummaries []FindingSummary `json:"finding_summaries,omitempty"`
	Error            string           `json:"error,omitempty"`
}

// FindingSummary is a compact, deterministic grouping of findings from a
// scanner's raw result artifact. The artifact remains the source of full
// messages and locations; summaries make organization reports useful without
// duplicating every raw finding into each intermediate JSON document.
type FindingSummary struct {
	RuleID   string `json:"rule_id"`
	Severity string `json:"severity"`
	Count    int    `json:"count"`
}

type ScanRun struct {
	SchemaVersion int                   `json:"schema_version"`
	RunID         string                `json:"run_id"`
	ConfigDigest  string                `json:"config_digest"`
	StartedAt     time.Time             `json:"started_at"`
	FinishedAt    time.Time             `json:"finished_at"`
	Selected      int                   `json:"selected"`
	Excluded      int                   `json:"excluded"`
	Repositories  []RepositoryExecution `json:"repositories"`
	Results       []ScannerResult       `json:"results"`
	Errors        []RunError            `json:"errors,omitempty"`
}

type RepositoryExecution struct {
	Repository string    `json:"repository"`
	QueuedAt   time.Time `json:"queued_at"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
	QueueMS    int64     `json:"queue_ms"`
	DurationMS int64     `json:"duration_ms"`
	Status     string    `json:"status"`
	// CommitSHA is the commit actually checked out and scanned (resolved after clone),
	// not the inventory's default-branch SHA captured at inventory time. Publication must
	// bind SARIF uploads to this value so findings are never attributed to a commit other
	// than the one that was scanned.
	CommitSHA string `json:"commit_sha,omitempty"`
}

type PublicationStatus string

const (
	PublicationPending     PublicationStatus = "pending"
	PublicationSucceeded   PublicationStatus = "succeeded"
	PublicationRejected    PublicationStatus = "rejected"
	PublicationFailed      PublicationStatus = "failed"
	PublicationUnsupported PublicationStatus = "unsupported"
	PublicationRetained    PublicationStatus = "retained"
)

type Publication struct {
	Repository string            `json:"repository"`
	Scanner    string            `json:"scanner"`
	Category   string            `json:"category"`
	CommitSHA  string            `json:"commit_sha"`
	Ref        string            `json:"ref"`
	Status     PublicationStatus `json:"status"`
	SARIFID    string            `json:"sarif_id,omitempty"`
	URL        string            `json:"url,omitempty"`
	Error      string            `json:"error,omitempty"`
}

type RunError struct {
	Repository string `json:"repository,omitempty"`
	Component  string `json:"component"`
	Kind       string `json:"kind"`
	Message    string `json:"message"`
}
