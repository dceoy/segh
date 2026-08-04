# Workflows

## Organization audit and periodic source scan

`.github/workflows/organization-audit.yml` runs from a private control
repository.

1. Add a reviewed 40-character commit from protected `dceoy/segh` `main` to
   `config/segh-source-commit`.
2. Install a read-only GitHub App on every repository in the organization.
3. Add the App ID as `SEGH_READ_APP_ID`, its Client ID as
   `SEGH_READ_APP_CLIENT_ID`, and its private key as
   `SEGH_READ_APP_PRIVATE_KEY`. The Client ID is required in addition to the
   App ID because the pinned upstream reusable workflow mints its own
   per-repository token through `actions/create-github-app-token`'s
   `client-id` input rather than `app-id`.
4. Store the version 5 policy in `config/organization.yaml`.
5. Configure `source_scan.enabled` and `source_scan.concurrency`.
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
bounded concurrency.

Each matrix entry calls `dceoy/gha-for-devops`'s
`repository-security-scan.yml` reusable workflow, pinned to a reviewed full
commit SHA, supplying the repository's ID, full name, default branch, resolved
commit SHA, and a unique evidence artifact name. `segh` itself does not mint
the per-repository token, check out the target, install or invoke a scanner, or
classify scanner exit codes. The called workflow mints its own short-lived,
repository-scoped Contents/Metadata read token, checks out the recorded commit
with LFS and submodules disabled, runs its own preflight and scanner pipeline,
classifies the result, and uploads the identity-bound `status.json` evidence
under the supplied artifact name. Its per-repository scan duration is bounded
by that reusable workflow's fixed timeout, not a `segh` configuration field.

The upstream policy rejects target-owned scanner configuration and unsupported
suppressions. Target repositories cannot replace the scanner, versions,
thresholds, configuration, or accepted exclusions.

The scanner never runs a repository script, dependency installation, package
lifecycle hook, Terraform initialization, LFS hook, or submodule command.
Tracked symlinks are removed before scanning. LFS pointers and submodule
gitlinks produce incomplete-coverage evidence.

The aggregation job downloads every repository's `status.json` artifact and
parses it against the upstream workflow's evidence shape, converting it into
`segh`'s own `RepositoryScanStatus` before matching it against the planned
repository identity in `scan-manifest.json` and writing `scan-summary.json`.
Missing, malformed, duplicate, or identity-mismatched evidence remains a
coverage gap, not a silent pass.

Governance artifacts remain `inventory.json`, `audit.json`, and `report.md`.
Source scan planning, per-repository reports, `scan-summary.json`, and the
bounded `scan-report.md` are separate private artifacts retained for 14 days on
success and failure.

## Scope boundary

`segh` has no workflow that scans pull requests or merge queues and no code that
publishes pull-request security checks. Those controls are outside this
repository's responsibility. The periodic organization scan described above is
unchanged and remains the only source-scanning path maintained here.

After this removal is merged, an administrator should delete external GitHub
configuration that existed only for the retired pull-request publisher: the
dedicated Checks-write App or installation, its protected environment,
associated secrets and variables, and obsolete branch-protection or ruleset
required-check entries. Repository code must not attempt to modify those
organization settings.
