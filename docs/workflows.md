# GitHub Actions workflows

## Organization audit

`.github/workflows/organization-audit.yml` supports schedule and
`workflow_dispatch`. It inventories first, creates lexically deterministic
batches, scans each batch with `fail-fast: false`, and aggregates every
available result under `if: always()`. A failed repository or scanner is a
partial result, not a reason to discard unrelated results.

Manual inputs support dry-run and exact comma-separated target repositories.
This provides troubleshooting and resume behavior without rescanning the
organization. Batch size, CLI concurrency, repository/scanner/total timeouts,
API retries, and artifact retention are bounded in workflow/configuration.

The workflow never caches a target checkout. Scanner installation goes through
the pinned Aqua registry and checksum metadata. Each target clone lives only in
a temporary worktree.

Required Actions secrets are `SEGH_READ_APP_ID`,
`SEGH_READ_INSTALLATION_ID` (optional when discovery is permitted), and
`SEGH_READ_APP_PRIVATE_KEY`. Publication uses a distinct
`SEGH_PUBLISH_APP_ID`, `SEGH_PUBLISH_INSTALLATION_ID`, and
`SEGH_PUBLISH_APP_PRIVATE_KEY`. Configure `config/organization.yaml` before
enabling the schedule.

## Pull-request workflow

`.github/workflows/reusable-pr-security.yml` is a reusable `workflow_call`
workflow. Organization rulesets can require it where required-workflow support
is available. The fallback is a small workflow in each repository:

```yaml
name: segh
on:
  pull_request:
permissions:
  contents: read
jobs:
  security:
    uses: dceoy/segh/.github/workflows/reusable-pr-security.yml@FULL_COMMIT_SHA
```

The scanner job receives no App key or write token. It checks out target data
without persisted credentials, computes a NUL-delimited diff, scans only copied
changed files, and never runs target scripts. Base and current SARIF are
compared by native fingerprints (with a deterministic fallback). Existing
baseline findings do not block; configured new scanner/rule/severity findings
do. Start with `report_only: true`, review baselines/false positives, then turn
on enforcement for high-confidence critical/high findings.

Fork pull requests remain read-only and skip privileged publication. A separate
publication job may be enabled for same-repository pull requests; it consumes
SARIF with a trusted `segh` binary and is the only job given publication
credentials. GitHub-native CodeQL, secret scanning, and push protection remain
outside this workflow.

All third-party `uses:` references in the supplied workflows are full commit
SHAs with readable release comments.
