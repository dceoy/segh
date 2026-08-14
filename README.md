# segh

`segh` is a workflow-only GitHub organization source-security scanner. It enumerates repositories available to a GitHub App, scans immutable default-branch commits with established tools, retains private evidence, and publishes one issue-backed dashboard per scanned repository.

The repository intentionally contains no application server, database, custom REST client, or target-code execution framework.

## Scanners

The production workflow installs checksum-verified tools with Aqua and runs:

- OpenSSF Scorecard
- zizmor
- actionlint
- ShellCheck
- Checkov, the sole owner of IaC misconfiguration scanning (running its full default framework set, so it also incidentally overlaps Trivy secret scanning and zizmor Actions scanning; every Checkov finding is still reported under the `finding:misconfiguration` label regardless of which framework produced it)
- Trivy vulnerability and secret scanners

OpenSSF Scorecard is informational evidence. A successful execution with parseable native Scorecard JSON is reported as `pass` regardless of aggregate or individual check scores; only execution or evidence-integrity failures become scanner errors. `segh` does not translate Scorecard scores into findings, thresholds, or finding labels.

Target repositories are treated as untrusted data. Their scripts, actions, hooks, package managers, builds, tests, Terraform providers, submodules, and Git LFS objects are not executed or expanded. Preflight rejects every untracked path, including paths hidden by target-owned ignore files, removes tracked symlinks, and rejects unmaterialized submodules and Git LFS pointers before scanners run.

### Scanner input collection

Scanner-native collection is used only when it preserves the preflighted target boundary and native result semantics:

- **zizmor:** keep explicit Git-index selection for workflow and action YAML. Native workflow/action collection honors target-owned `.gitignore`; disabling that behavior with `--collect=all` broadens the collected input kinds. Explicit selection also preserves a successful empty result when no matching files exist.
- **actionlint:** keep explicit Git-index selection. Repository-native discovery recursively walks `.github/workflows` from the filesystem and treats an empty workflow set as a fatal error, so it is not coverage- or no-match-equivalent.
- **ShellCheck:** keep explicit Git-index selection because ShellCheck has no repository-native collector matching segh's extension-plus-supported-shebang policy.
- **Checkov:** keep native directory collection after preflight, running Checkov's full default framework set (no `framework:` allowlist). This intentionally overlaps Trivy's secret scanning and zizmor's GitHub Actions scanning rather than trying to keep Checkov confined to IaC misconfiguration alone; Checkov remains the sole owner of IaC misconfiguration scanning. The workflow pins trusted Checkov configuration, disables Prisma Cloud downloads and result uploads, and does not load target-owned `.checkov.yml`, external checks, or remote policies. Checkov's Serverless framework has a known accepted gap: its collector silently drops files it cannot parse without incrementing `parsing_errors`, so a target can hide from that framework specifically with a deliberately malformed `serverless.yml`; this is accepted as a residual risk rather than fixed, since Checkov's serverless parser internals aren't a stable dependency to pin a pre-check against.
- **Trivy:** keep native `filesystem` collection for vulnerability and secret scanning only. It runs only after preflight has excluded untracked content and unsafe Git object types; target-owned Trivy configuration and ignore files are disabled with `/dev/null`, and `.git` is excluded.

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

Each target scan retains `repository-scan-<repository-id>` with immutable target metadata, scanner versions, preflight output, native scanner outputs/logs, and `summary.json`. Checkov contributes native `checkov.json`, stderr, and execution status evidence; Trivy no longer emits misconfiguration evidence.

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

Production helpers live in `scripts/`; test code lives separately in `tests/`.

Pull-request CI runs:

- a small Shell/yq credential-boundary validator for segh-specific invariants;
- shell tests for the target preflight boundary;
- Node tests for summary normalization and issue publication, including Checkov findings versus scanner/parsing failures;
- a per-framework Checkov IaC coverage regression gate (originally run as a Checkov-versus-Trivy comparison to justify retiring Trivy misconfiguration scanning; now a permanent check that each representative framework still produces scanned resources);
- actionlint, zizmor, and ShellCheck;
- YAML/JSON parsing and Aqua checksum verification; and
- the real organization scanner in deterministic `validation_mode`.

Generic workflow correctness and action hardening are intentionally delegated to actionlint and zizmor rather than duplicated in custom validators.

## Non-goals

`segh` does not provide organization governance auditing, PR-time target scanning, repository merge protection, a general workflow-policy framework, stale/retired dashboard reconciliation, historical analytics, continuous target-push scanning, or compatibility with the removed CLI-era product surface.
