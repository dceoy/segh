# segh

`segh` is a workflow-only organization source scanner. A private control repository invokes a reviewed immutable `segh` revision to enumerate the repositories selected by a read-only GitHub App, scan immutable default-branch commits, and maintain one issue-backed security dashboard per repository ID.

The repository deliberately has no CLI, Go runtime, governance engine, custom REST client, database, web UI, or general reporting framework. Detection is delegated to established scanners; local code is limited to trusted orchestration, bounded normalization, and dashboard reconciliation.

## Scanner profile

Aqua installs exactly five checksum-pinned tools:

- OpenSSF Scorecard for selected supply-chain posture checks;
- zizmor for GitHub Actions security findings;
- actionlint with ShellCheck integration for workflow validation;
- ShellCheck for tracked shell files and supported shell shebangs;
- Trivy for vulnerability, secret, and misconfiguration scanning.

Scorecard runs against the immutable repository commit with `--show-details`. Its aggregate score is not a gate. Selected checks below 7/10 become bounded dashboard findings; unavailable negative scores are excluded rather than treated as findings. Scanner runtime failure or malformed required output fails closed.

## Execution model

The GitHub App installation selection is authoritative. Planning excludes archived and disabled repositories, includes explicitly selected forks, validates identity and visibility, sorts targets deterministically, and resolves every active default branch to a 40-character commit SHA before matrix execution.

Each target is treated as untrusted input. The scan job:

1. mints a repository-scoped read-only token for one target;
2. checks out the exact commit with `persist-credentials: false`, `lfs: false`, and `submodules: false`;
3. removes tracked symlinks and rejects gitlinks, unmaterialized LFS pointers, unreadable tracked regular files, and incomplete checkouts;
4. installs scanners only from the trusted `segh` revision;
5. ignores target-owned scanner configuration where supported;
6. never executes target scripts, actions, hooks, package managers, installers, builds, tests, or Terraform providers;
7. uploads raw private evidence plus a bounded `summary.json`.

A separate read-only selection snapshot records repository identity and lifecycle state so reconciliation can account for renamed, archived, disabled, newly selected, or removed repositories even when scan planning fails.

## Credentials

Credential domains are intentionally separate:

```text
trusted PR boundary   -> dedicated segh-only App: metadata read + checks write
organization planning -> organization App: metadata + contents read
per-target scan       -> one target-scoped App token: metadata/contents/checks/issues/PRs read
selection snapshot    -> organization App: metadata + contents read
dashboard reconcile   -> private caller GITHUB_TOKEN: actions/contents read + issues write
```

No scanner or selection job receives issue-write or trusted-boundary credentials. Target repositories receive no write permission.

See [CREDENTIALS.md](CREDENTIALS.md) for the exact App permissions, secrets, token consumers, and trusted required-check setup. See [SECURITY.md](SECURITY.md) for the threat model and deployment validation requirements.

## Use from a private control repository

Create a GitHub App installed only on the repositories that should be scanned. Grant repository permissions:

- Metadata: read;
- Contents: read;
- Checks: read;
- Issues: read;
- Pull requests: read.

Store its identity as `SEGH_ORG_SCAN_APP_ID` and `SEGH_ORG_SCAN_APP_PRIVATE_KEY` Actions secrets in the private control repository.

Pin the reusable dashboard workflow to one reviewed 40-character commit:

```yaml
---
name: Organization security dashboard
on:
  schedule:
    - cron: "17 3 * * 0"
  workflow_dispatch:
permissions: {}
jobs:
  dashboard:
    permissions:
      actions: read
      contents: read
      checks: read
      issues: write
      pull-requests: read
    uses: dceoy/segh/.github/workflows/organization-dashboard.yml@<reviewed-40-character-commit-sha>
    with:
      repository_limit: "50"
      max_parallel: "4"
      stale_after_hours: "192"
    secrets:
      SEGH_ORG_SCAN_APP_ID: ${{ secrets.SEGH_ORG_SCAN_APP_ID }}
      SEGH_ORG_SCAN_APP_PRIVATE_KEY: ${{ secrets.SEGH_ORG_SCAN_APP_PRIVATE_KEY }}
```

The default schedule is weekly. A stale threshold of 192 hours gives one day of tolerance beyond that cadence. Production execution and dashboard publication must remain in a private repository; the public `dceoy/segh` repository is not a production dashboard target.

## Dashboard contract

The control repository maintains one managed issue per immutable repository ID:

- `pass` closes the issue with `scan:pass`;
- `findings`, `incomplete`, and `error` keep it open with the matching state label;
- archived, disabled, or deselected repositories with an existing dashboard become `scan:retired`;
- renames update the existing issue by repository ID;
- unchanged normalized state causes no issue or history-comment write;
- malformed, duplicate, missing, stale, or identity-mismatched evidence fails closed.

Issue bodies contain only bounded repository identity, immutable scan metadata, scanner status/counts, selected Scorecard scores, remediation categories, and a private workflow-run link. Source excerpts, private paths, secret values, scanner logs, and stack traces are excluded.

Managed state and finding labels are owned by `segh`; operator-owned labels are preserved.

## Evidence

Each target scan retains a private `repository-scan-<repository-id>` artifact for 14 days with immutable target metadata, scanner versions, preflight output, native scanner outputs/logs, and `summary.json`.

A separate `repository-summary-<repository-id>` artifact retains only the bounded summary for 31 days. The immutable plan and selection snapshot are transient. Raw evidence is intentionally not a stable public schema.

## Validation

Pull-request CI verifies:

- credential and workflow boundaries;
- dashboard normalization, idempotency, privacy, recovery, retirement, stale-state handling, and reconciliation;
- actionlint, zizmor, ShellCheck, YAML/JSON parsing, and Aqua checksums;
- guarded production scanner fixtures, including clean, findings, incomplete content, unsafe repository shapes, checkout failure, scanner failure, and proof that target code is not executed.

Repository CI cannot prove external App installation scope or private artifact visibility. Before deploying a new reviewed revision, run it from the intended private control repository and validate the external credential and privacy boundaries described in [SECURITY.md](SECURITY.md).

## Non-goals

`segh` does not provide organization governance auditing, PR-time target scanning, a general workflow-policy framework, historical analytics, continuous target-push scanning, or compatibility with the removed CLI-era product surface.
