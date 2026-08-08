# segh

`segh` is a workflow-only GitHub organization source-security scanner. It enumerates repositories available to a GitHub App, scans immutable default-branch commits with established tools, retains private evidence, and publishes one issue-backed dashboard per scanned repository.

The repository intentionally contains no application server, database, custom REST client, or target-code execution framework.

## Scanners

The production workflow installs checksum-verified tools with Aqua and runs:

- OpenSSF Scorecard
- zizmor
- actionlint
- ShellCheck
- Trivy vulnerability, secret, and misconfiguration scanners

OpenSSF Scorecard is informational evidence. A successful execution with parseable native Scorecard JSON is reported as `pass` regardless of aggregate or individual check scores; only execution or evidence-integrity failures become scanner errors. `segh` does not translate Scorecard scores into findings, thresholds, or finding labels.

Target repositories are treated as untrusted data. Their scripts, actions, hooks, package managers, builds, tests, Terraform providers, submodules, and Git LFS objects are not executed or expanded.

## Architecture

```text
organization-scan.yml
  plan
    -> enumerate App installation repositories
    -> resolve each default branch to an immutable commit SHA
  scan matrix
    -> checkout one target with a repository-scoped read-only token
    -> run established scanners
    -> retain raw evidence and a bounded summary
  publish-dashboard
    -> download this run's plan and summaries
    -> create/update the corresponding dashboard issues
```

The dashboard is a projection of the current scan run, not a state-reconciliation system. `segh` does not independently track repository retirement, stale scan age, historical transitions, or issue-body integrity. A later successful scan simply overwrites the managed dashboard for that repository.

## Private control repository

Production scans must be invoked from a private control repository. The source repository `dceoy/segh` is public, while repository identities, scanner evidence, and dashboard issues may be private organization information.

A caller can invoke the reusable workflow at a reviewed immutable revision:

```yaml
jobs:
  security-scan:
    permissions:
      actions: read
      contents: read
      checks: read
      issues: write
      pull-requests: read
    uses: dceoy/segh/.github/workflows/organization-scan.yml@<full-commit-sha>
    secrets:
      SEGH_ORG_SCAN_APP_ID: ${{ secrets.SEGH_ORG_SCAN_APP_ID }}
      SEGH_ORG_SCAN_APP_PRIVATE_KEY: ${{ secrets.SEGH_ORG_SCAN_APP_PRIVATE_KEY }}
```

The control repository must provide `SEGH_ORG_SCAN_APP_ID` and `SEGH_ORG_SCAN_APP_PRIVATE_KEY`. See [CREDENTIALS.md](CREDENTIALS.md) for the exact credential boundary.

## Outputs

Each target scan retains `repository-scan-<repository-id>` with immutable target metadata, scanner versions, preflight output, native scanner outputs/logs, and `summary.json`.

A small `repository-summary-<repository-id>` artifact is used by the publisher in the same workflow run. The summary contains only repository identity needed to bind it to the current plan, the overall status, bounded scanner status/count rows, and the raw-evidence artifact name. Dashboard issues add current plan metadata and the private workflow-run link; raw source excerpts and scanner logs stay in artifacts.

Before enabling dashboard publication, bootstrap these managed labels in the private control repository. The publisher deliberately does not create or modify label definitions at runtime:

- `scan:pass`
- `scan:findings`
- `scan:incomplete`
- `scan:error`
- `finding:actions`
- `finding:shell`
- `finding:vulnerability`
- `finding:secret`
- `finding:misconfiguration`

Scorecard remains visible in the scanner-results table as informational `pass`/`error` evidence but does not produce `finding:*` labels.

## Validation

Pull-request CI runs:

- a small Ruby credential-boundary validator for segh-specific invariants;
- Node tests for summary normalization and issue publication;
- actionlint, zizmor, and ShellCheck;
- YAML/JSON parsing and Aqua checksum verification; and
- the real organization scanner in deterministic `validation_mode`.

Generic workflow correctness and action hardening are intentionally delegated to actionlint and zizmor rather than duplicated in custom validators.

## Non-goals

`segh` does not provide organization governance auditing, PR-time target scanning, repository merge protection, a general workflow-policy framework, stale/retired dashboard reconciliation, historical analytics, continuous target-push scanning, or compatibility with the removed CLI-era product surface.
