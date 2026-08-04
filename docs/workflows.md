# Workflows

## Organization audit and periodic source scan

`.github/workflows/organization-audit.yml` runs from a private control
repository.

1. Add a reviewed 40-character commit from protected `dceoy/segh` `main` to
   `config/segh-source-commit`.
2. Install a read-only GitHub App on every repository in the organization.
3. Add the App ID as `SEGH_READ_APP_ID` and private key as
   `SEGH_READ_APP_PRIVATE_KEY`.
4. Store the version 5 policy in `config/organization.yaml`.
5. Configure `source_scan.enabled`, `source_scan.concurrency`, and
   `source_scan.timeout`.
6. Add a weekly `schedule` trigger to the control repository's copy of the
   workflow (the checked-in `segh` template is dispatch-only, since its
   prerequisites only exist in the private control repository), or run
   `Organization security audit and source scan` manually.

The audit job verifies that the pinned `segh` source is reachable from protected
`main`, mints a short-lived App token, requires a private control repository,
and runs `segh audit`. Its 75-minute bound covers the sequential governance and
source-planning phases, each of which can use the default 30-minute inventory
timeout.

When scanning is enabled, `segh scan-plan` reuses the authoritative inventory
and resolves every selected default branch to a full commit SHA. Failed
resolutions remain in `scan-manifest.json` as unscheduled selections, so the
final coverage counts cannot report them as passes. At most 256 resolved
repositories are scheduled in a `fail-fast: false` matrix with configured,
bounded concurrency and per-repository timeout.

Each worker:

- mints a new Contents/Metadata read token limited to one repository;
- checks out the recorded commit with persisted credentials, LFS, and
  submodules disabled;
- checks out the trusted repository scanner from `dceoy/gha-for-devops` at the
  full commit pinned in the workflow;
- installs that revision's checksum-verified scanner versions;
- runs its preflight, Zizmor, actionlint/embedded ShellCheck, standalone
  ShellCheck, Checkov, Trivy vulnerability, and Trivy secret operations;
- binds the upstream evidence to the planned repository and commit identity;
  and
- uploads a unique private artifact before enforcing the aggregate result.

The upstream policy rejects target-owned Zizmor ignores, ShellCheck directives,
expression-valued shell selection, and Checkov inline suppressions. It also
scans supported shell blocks from composite actions. Target repositories cannot
replace the scanner, its configuration, thresholds, or accepted exclusions.

Workers cache only Trivy's public vulnerability and Java advisory databases
under a daily, scanner-versioned key. Repository content and scan artifacts are
not shared between matrix jobs.

The scanner never runs a repository script, dependency installation, package
lifecycle hook, Terraform initialization, LFS hook, or submodule command.
Tracked symlinks are removed before scanning. LFS pointers and submodule
gitlinks produce incomplete-coverage evidence.

Governance artifacts remain `inventory.json`, `audit.json`, and `report.md`.
Source scan planning, per-repository reports, `scan-summary.json`, and the
bounded `scan-report.md` are separate private artifacts retained for 14 days on
success and failure.

## Pull-request security

The existing `PR security / scan` required workflow remains active while the
`Repository security` migration in `dceoy/gha-for-devops` is incomplete. Do
not remove the local workflow or self-check publisher until the upstream direct
pull-request and merge-group path is active and its organization-ruleset
replacement has been verified. Pin the replacement to a reviewed upstream
commit and complete that rollout before removing the local path in a follow-up.
