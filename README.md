# segh

`segh` is a workflow-only GitHub organization source-security scanner. It enumerates repositories available to a GitHub App, scans immutable default-branch commits with established tools, retains private evidence, and publishes one issue-backed dashboard per scanned repository.

The repository intentionally contains no application server, database, custom REST client, or target-code execution framework.

## Scanners

The shared, checksum-verified CLI toolchain is defined by repository-root `mise.toml` and `mise.lock`. Both the organization workflow and standalone skill use that trusted configuration. The production workflow runs:

- OpenSSF Scorecard
- zizmor
- actionlint
- ShellCheck
- Checkov, an independent IaC misconfiguration scanner (all non-Kubernetes default frameworks; Argo Workflows, Helm, Kubernetes, and Kustomize are excluded). Findings remain labeled `finding:misconfiguration`.
- Trivy vulnerability, secret, and misconfiguration scanners (one filesystem invocation)
- Optional OWASP dep-scan of a trusted Trivy-generated CycloneDX SBOM (disabled by default)

OpenSSF Scorecard is informational evidence. A successful execution with parseable native Scorecard JSON is reported as `pass` regardless of aggregate or individual check scores; only execution or evidence-integrity failures become scanner errors. `segh` does not translate Scorecard scores into findings, thresholds, or finding labels.

Target repositories are treated as untrusted data. Their scripts, actions, hooks, package managers, builds, tests, Terraform providers, submodules, and Git LFS objects are not executed or expanded. Preflight rejects every untracked path, including paths hidden by target-owned ignore files, removes tracked symlinks, and rejects unmaterialized submodules and Git LFS pointers before scanners run.

### Scanner input collection

Scanner-native collection is used only when it preserves the preflighted target boundary and native result semantics:

- **zizmor:** keep explicit Git-index selection for workflow and action YAML. Native workflow/action collection honors target-owned `.gitignore`; disabling that behavior with `--collect=all` broadens the collected input kinds. Explicit selection also preserves a successful empty result when no matching files exist.
- **actionlint:** keep explicit Git-index selection. Repository-native discovery recursively walks `.github/workflows` from the filesystem and treats an empty workflow set as a fatal error, so it is not coverage- or no-match-equivalent.
- **ShellCheck:** keep explicit Git-index selection because ShellCheck has no repository-native collector matching segh's extension-plus-supported-shebang policy.
- **Checkov:** keep native directory collection after preflight, excluding Argo Workflows, Helm, Kubernetes, and Kustomize. Other default frameworks stay enabled. Trusted configuration disables downloads/uploads and excludes target-owned settings. Serverless and OpenAPI parsers can silently ignore malformed inputs without incrementing `parsing_errors`; this is a known residual coverage risk.
- **Trivy:** keep native `filesystem` collection for vulnerabilities, secrets, and misconfigurations in one invocation. Misconfiguration scanning excludes Helm and Kubernetes while preserving other IaC types. The trusted validator rejects target-owned suppressions and all Terraform/OpenTofu module declarations before potential downloads. Rejections leave all three categories as errors, not clean results.

Kubernetes workloads and Helm/Kustomize manifests are out of scope for IaC misconfiguration scanning. Generic secret, dependency, and source scanners may still inspect those files.

### Optional OWASP dep-scan

Set `use_dep_scan: true` in a private caller's reusable workflow invocation or through `workflow_dispatch`. The default is `false`; scheduled audits do not enable it automatically.

The optional runner exports a CycloneDX SBOM using Trivy and passes **only the SBOM**, not target source, Git history, or GitHub credentials, into a digest-pinned OWASP dep-scan v6 container. It writes native VDR/CSAF and logs into private raw scan artifacts. The dashboard reports a separate `dep-scan` scanner with `finding:vulnerability` labels where applicable. Missing or malformed evidence fails closed; a verified SBOM with no dependency components is `skipped`.

This **SBOM-only mode does not perform source reachability analysis**. Vulnerability results may overlap Trivy. The separate Docker execution is intentional to preserve the prohibition on executing target-owned code. Docker is required on the organization scanner runner. The standalone `repository-security-audit` skill remains Docker-free and unchanged.

The standalone `repository-security-audit` skill additionally runs
OSV-Scanner, Semgrep OSS, and TruffleHog without verification or updates against the preflighted
detached checkout. It retains dependency and SAST findings, plus only
redacted Git-history secret metadata. These Docker-free tools are added to the **skill**
rather than to this repository's CI or organization-scanning workflow.

`audit.sh` retains evidence evaluation. `run-scanners.sh` dispatches all
source scanner execution to tool-specific scripts under `scripts/scanners/`.
Checkov and ShellCheck keep their safety controls, and shared selection
logic is factored into `scanners/common.sh`.

## GitHub paid-feature exposure

The standalone `repository-security-audit` skill reports a separate
`billing-exposure.json` for repository-level GitHub Code Security and GitHub
Secret Protection configuration. For private/internal repositories, observed
enablement is flagged as `potential-license-required`; missing administration
visibility is `unknown`, not evidence of a free or disabled configuration.
Public-repository enablement does not imply private-repository license charges.
This is a configuration signal, **not** a GitHub billing, active-committer,
organization policy, or workflow SARIF-upload audit.

The production `organization-scan.yml` remains a read-only OSS source scanner;
it does not enable CodeQL or upload results to GitHub Code Scanning. The public
`segh` development CI does use CodeQL. Simply declaring `security-events: write`
is not billable; whether the permission can be removed depends on the
requirements of the pinned reusable workflow.

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
    with:
      use_dep_scan: false # Set true for SBOM-based dependency analysis
    secrets:
      SEGH_ORG_SCAN_APP_ID: ${{ secrets.SEGH_ORG_SCAN_APP_ID }}
      SEGH_ORG_SCAN_APP_PRIVATE_KEY: ${{ secrets.SEGH_ORG_SCAN_APP_PRIVATE_KEY }}
```

The control repository must provide `SEGH_ORG_SCAN_APP_ID` and `SEGH_ORG_SCAN_APP_PRIVATE_KEY`. See [CREDENTIALS.md](CREDENTIALS.md) for the exact credential boundary.

## Outputs

Each target scan retains `repository-scan-<repository-id>` with immutable target metadata, scanner versions, preflight output, native scanner outputs/logs, and `summary.json`. Checkov contributes native `checkov.json`, stderr, and execution status evidence. Trivy retains a single `trivy.json` with vulnerability, secret, and misconfiguration results, which are summarized in separate scanner rows. When enabled, dep-scan additionally retains its CycloneDX SBOM input and VDR/CSAF evidence, with a separate dashboard row.

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
- a non-Kubernetes Checkov framework coverage regression gate and a complementary Trivy misconfiguration coverage run;
- actionlint, zizmor, and ShellCheck;
- YAML/JSON parsing and Aqua checksum verification; and
- the real organization scanner in deterministic `validation_mode`.

Generic workflow correctness and action hardening are intentionally delegated to actionlint and zizmor rather than duplicated in custom validators.

## Non-goals

`segh` does not provide organization governance auditing, PR-time target scanning, repository merge protection, a general workflow-policy framework, stale/retired dashboard reconciliation, historical analytics, continuous target-push scanning, or compatibility with the removed CLI-era product surface.
