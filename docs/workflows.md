# GitHub Actions workflows

## Organization audit

`.github/workflows/organization-audit.yml` ships with only
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
adding a `schedule` trigger.

This workflow retains the organization inventory, audit, and scanner findings
in Actions artifacts and the run summary. Both are readable by anyone with
repository read access, so the workflow must run from a private control
repository, never from a public fork or mirror of `dceoy/segh`. The `plan` and
`aggregate` jobs each fail fast with `Require a private control repository`,
which queries `repos/$GITHUB_REPOSITORY` via `gh api` rather than trusting
repository visibility from the triggering event payload, since that field is
not reliably populated for every trigger. Copy this workflow into your own
private control repository and add a `schedule:` trigger there; `dceoy/segh`
itself ships without one because it is public and the guard would fail every
scheduled run.

## Pull-request workflow

`.github/workflows/reusable-pr-security.yml` is a reusable `workflow_call`
workflow. GitHub's "require workflows to pass before merging" ruleset rule only
invokes workflows whose `on:` section includes `pull_request`,
`pull_request_target`, or `merge_group`; a `workflow_call`-only file is never
triggered by a ruleset directly, regardless of required-workflow support.
Keep a small `pull_request`-triggered caller workflow in a central trusted
source repository instead (see `pr-security.yml` in this repository), and
configure the organization ruleset to require that source repository, protected
branch, and workflow file. Do not copy the ruleset workflow into each target
repository: GitHub runs the selected central workflow for every repository
targeted by the ruleset, so target-repository workflow content is not part of
the enforcement boundary.

```yaml
name: segh
on:
  pull_request:
permissions:
  contents: read
jobs:
  security:
    uses: dceoy/segh/.github/workflows/reusable-pr-security.yml@FULL_COMMIT_SHA
    with:
      segh-ref: FULL_COMMIT_SHA
```

Protect the selected source branch and restrict changes to the caller workflow.
If the source repository is internal or private, allow the target repositories
to access its Actions workflows. See GitHub's
[ruleset workflow requirements](https://docs.github.com/en/enterprise-cloud@latest/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets#using-a-workflow-file).

`segh-ref` must be the same `FULL_COMMIT_SHA` used to pin the `uses:` line above.
The `github` context in a called reusable workflow reflects the target
repository where the ruleset runs, not `dceoy/segh`, so the revision to build
from must be passed explicitly rather than inferred.

A target repository may also keep its own caller as an optional ordinary status
check when ruleset workflows are unavailable. That caller is maintained by the
target repository and must not be documented or configured as the centralized
ruleset trust boundary.

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
