# Workflows

## Organization audit and periodic source scan

`.github/workflows/organization-audit.yml` runs from a private control
repository.

1. Add a reviewed 40-character commit from protected `dceoy/segh` `main` to
   `config/segh-source-commit`.
2. Install a read-only GitHub App on every repository in the organization.
3. Add the App ID as `SEGH_READ_APP_ID`, its Client ID as
   `SEGH_READ_APP_CLIENT_ID`, and its private key as
   `SEGH_READ_APP_PRIVATE_KEY`. The pinned upstream reusable workflow requires
   the Client ID to mint its per-repository token.
4. Store the version 5 policy in `config/organization.yaml` and configure
   `source_scan.enabled` and `source_scan.concurrency`.
5. Add a weekly `schedule` trigger to the control repository's copy of the
   workflow, or dispatch it manually. The checked-in template is dispatch-only
   because its prerequisites exist only in the private control repository.

The audit job verifies that the pinned `segh` source is reachable from protected
`main`, mints one short-lived read-only App token, requires a private control
repository, and runs `segh audit`. Configuration validation completes before
any API access. The command performs one authoritative inventory collection and,
when source scanning is enabled, reuses that in-memory inventory to resolve each
selected default branch to a full immutable commit SHA and write
`scan-manifest.json`. Failed resolutions remain unscheduled manifest entries, so
they cannot be counted as passes. At most 256 resolved repositories enter a
`fail-fast: false` matrix with bounded configured concurrency.

The authenticated inventory and planning phases share a 50-minute parent
deadline. The workflow step has a 55-minute timeout, so `segh` regains control,
writes governance evidence and an incomplete manifest, and exits fail closed
before the short-lived App token or runner timeout can preempt evidence
emission.

Each matrix entry calls the reviewed
`dceoy/gha-for-devops/.github/workflows/repository-security-scan.yml` revision
pinned by full SHA. The call supplies repository ID, full name, default branch,
resolved commit SHA, and a unique artifact name. The upstream workflow owns
repository-scoped token minting, target checkout, scanner installation and
execution, repository-level classification, bounded repository summary,
`status.json` production, complete artifact publication, and enforcement.
`segh` does not duplicate those generic repository-scan responsibilities.

The upstream status contract has no schema-version field and uses the exact keys
`result`, `repository-id` (string), `repository`, `default-branch`, and
`commit-sha`. Its result is `pass`, `findings`, `incomplete`, or `error`.
The organization summary job invokes the same `segh audit` executable route in
reconciliation mode. It treats every downloaded artifact as untrusted input,
rejects malformed or unsupported status values, detects missing or duplicate
status files, and requires repository ID, name, default branch, and commit SHA
to match the manifest exactly. It then writes deterministic aggregate counts to
`scan-summary.json` and a bounded `scan-report.md`.

Governance artifacts remain `inventory.json`, `audit.json`, and `report.md`.
Source scan planning, repository reports, `scan-summary.json`, and the bounded
`scan-report.md` remain separate private artifacts retained for 14 days on
success and failure. The hidden `scan-plan` and `scan-summary` commands were
removed without aliases.

The upstream policy rejects target-owned Zizmor ignores, unapproved ShellCheck
directives, expression-valued shell selection, and Checkov inline suppressions.
It scans supported composite-action shell blocks and never runs repository
scripts, dependency installation, package lifecycle hooks, Terraform
initialization, LFS hooks, or submodule commands. Tracked symlinks are removed;
LFS pointers and submodule gitlinks produce incomplete evidence.

## Scope boundary

`segh` has no workflow that scans pull requests or merge queues and no code that
publishes pull-request security checks. Those controls are outside this
repository's responsibility. The periodic organization scan described above is
the only source-scanning path maintained here.

Administrators should remove obsolete organization-ruleset required-workflow
entries and branch-protection or ruleset required-check entries for
`PR security / scan` and `segh source scan (head commit)` if they remain. They
should also delete the retired publisher's dedicated Checks-write App or
installation, protected environment, and associated secrets or variables when
nothing else uses them. Repository code does not modify those organization
settings.
