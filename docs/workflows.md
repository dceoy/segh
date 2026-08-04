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

Each matrix entry calls `dceoy/gha-for-devops`'s `repository-security-scan.yml`
reusable workflow, pinned to a reviewed full commit SHA, supplying the
repository's ID, full name, default branch, resolved commit SHA, and a unique
evidence artifact name. `segh` itself no longer mints the per-repository
token, checks out the target, installs or invokes a scanner, or classifies
scanner exit codes: the called workflow mints its own short-lived,
repository-scoped Contents/Metadata read token, checks out the recorded
commit with LFS and submodules disabled, runs its own preflight and scanner
pipeline (Zizmor, actionlint/embedded ShellCheck, standalone ShellCheck,
Checkov, Trivy vulnerability, Trivy secret), classifies the result, and
uploads the identity-bound `status.json` evidence itself under the supplied
artifact name. Its per-repository scan duration is bounded by that reusable
workflow's own fixed timeout, not a `segh` configuration field.

The upstream policy rejects target-owned Zizmor ignores, ShellCheck directives,
expression-valued shell selection, and Checkov inline suppressions. It also
scans supported shell blocks from composite actions. Target repositories cannot
replace the scanner, its configuration, thresholds, or accepted exclusions.

The scanner never runs a repository script, dependency installation, package
lifecycle hook, Terraform initialization, LFS hook, or submodule command.
Tracked symlinks are removed before scanning. LFS pointers and submodule
gitlinks produce incomplete-coverage evidence.

The aggregation job downloads every repository's `status.json` artifact and
parses it against the upstream workflow's own evidence shape (hyphenated
keys, a string repository ID, no schema version), converting it into
`segh`'s own `RepositoryScanStatus` before matching it against the planned
repository identity in `scan-manifest.json` and writing `scan-summary.json`.
Missing, malformed, duplicate, or identity-mismatched evidence remains a
coverage gap, not a silent pass.

Governance artifacts remain `inventory.json`, `audit.json`, and `report.md`.
Source scan planning, per-repository reports, `scan-summary.json`, and the
bounded `scan-report.md` are separate private artifacts retained for 14 days on
success and failure.

## Pull-request security

The existing `PR security / scan` required workflow (`pr-security.yml`,
`pr-security-self.yml`, and the `.github/actions/pr-security` composite
action) remains active. `dceoy/gha-for-devops`'s `repository-security-scan.yml`
now has direct `pull_request`/`merge_group` triggers active and verified live
(`dceoy/gha-for-devops#873`, merged as
`c84ceed28723b5cd5a93edb1febdfaad39e7c522`), so the upstream replacement
itself is ready to be required. Migration is not complete, and the local
workflow and self-check publisher must not be removed yet:

1. An organization administrator adds
   `dceoy/gha-for-devops/.github/workflows/repository-security-scan.yml@c84ceed28723b5cd5a93edb1febdfaad39e7c522`
   as a required workflow in the organization ruleset that currently requires
   `dceoy/segh`'s own `pr-security.yml`, alongside the existing requirement
   (not replacing it yet) — an organization-ruleset change this repository's
   code cannot make or verify itself.
2. Verify a live pull request and a live `merge_group` run in `dceoy/segh`
   and in at least one representative downstream repository produce a
   passing `Repository security / scan` check, including confirming which
   commit the required-workflow execution actually trusts as the scanner
   revision for a repository other than `dceoy/gha-for-devops` itself — this
   specific trust-selection path has not been live-verified and must be
   before anything is required.
3. Make `Repository security / scan` required (not just present) and confirm
   representative failing pull requests are still blocked.
4. Only after step 3 is verified: remove `pr-security.yml`,
   `pr-security-self.yml`, `.github/actions/pr-security`, their tests and
   documentation, and the `dceoy/segh`'s own required-workflow entry for the
   old check; remove the organization ruleset's requirement of the old
   check; and decommission the dedicated Checks-write GitHub App and the
   `self-scan-publisher` environment if nothing else uses them.

Steps 1, 3 (the ruleset change), and 4's App/environment decommission are
organization-administrator actions outside this repository; they must be
performed and confirmed by an operator, not assumed complete.
