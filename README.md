# segh

`segh` is a workflow-only organization source scanner. It runs a small, pinned scanner profile against immutable default-branch commits selected by a read-only GitHub App installation and maintains one issue-backed security dashboard per immutable repository ID in the private control repository.

The repository intentionally contains no CLI, Go implementation, governance policy engine, general report renderer, custom REST client, database, web UI, or broad source-scan reconciliation framework.

## Scanner profile

The workflow installs exactly five checksum-pinned tools through trusted Aqua configuration:

- OpenSSF Scorecard for selected supply-chain posture checks and bounded dashboard findings;
- zizmor for tracked GitHub Actions workflows and action definitions;
- actionlint for tracked workflow validation with trusted ShellCheck configuration;
- ShellCheck for tracked regular shell files and supported shell shebangs;
- Trivy for independent vulnerability, secret, and misconfiguration scans.

Scorecard runs against the immutable repository and commit with `--show-details`. Its aggregate score is not a gate. Each available selected check below 7/10 contributes one bounded `scorecard` finding and affects the privacy-preserving finding fingerprint; unavailable negative scores are excluded rather than converted into findings. The repository job fails when Scorecard cannot execute or does not produce valid non-empty JSON.

## Repository selection

The GitHub App installation selection is authoritative. The source-scan planner excludes disabled and archived repositories from the scan matrix, includes explicitly selected forks, sorts targets deterministically, validates repository identity and visibility, and resolves every active default branch to a lowercase 40-character commit SHA.

A separate bounded selection-snapshot workflow records only the identity and class metadata needed for reconciliation: repository ID and full name, visibility, fork state, archived/disabled state, default branch, and an explicit active/retired reason. It does not collect governance settings, policy evidence, source content, or scanner output. This transient snapshot lets the issue dashboard account for archived, disabled, newly selected, renamed, and removed repositories even when immutable target planning fails.

Planning and selection capture fail closed on malformed pagination, duplicate identities, oversized selections, unavailable required metadata, or invalid bounds. A missing immutable target is represented as a dashboard error rather than silently disappearing from organization coverage.

## Credential architecture

Organization discovery, target scanning, complete selection capture, and issue publication use separate credential domains:

```text
scan plan
  └─ organization installation token, read-only

scan matrix
  └─ one repository-scoped installation token per target, read-only

selection snapshot
  └─ organization installation token, read-only; no issue-write permission

dashboard reconciliation
  └─ private control-repository GITHUB_TOKEN with actions: read,
     contents: read, and issues: write; no configured secrets
```

No job receives both organization/target scan credentials and an issue-write credential. The dashboard reconciler receives no configured secrets and can write issues only in the private caller repository.

See [CREDENTIALS.md](CREDENTIALS.md) for the complete permission mapping, Scorecard limitations, publisher contract, private-control-repository requirements, and migration guidance.

## Operation

Consume the reusable workflows from a **private execution or control repository**. This is mandatory because artifacts and dashboard issues can contain private repository identities and security status.

Create one GitHub App installed on the authoritative target set with these repository permissions:

- Metadata: read;
- Contents: read;
- Checks: read;
- Issues: read;
- Pull requests: read.

Do not grant target-repository write permissions. `Actions` and `Administration` are intentionally not requested because the retained Scorecard profile does not require them. Administrator-only classic branch-protection evidence and the experimental Webhooks check are therefore unavailable and are recorded as explicit limitations in every scan artifact.

Configure these Actions secrets in the private control repository:

- `SEGH_ORG_SCAN_APP_ID`
- `SEGH_ORG_SCAN_APP_PRIVATE_KEY`

A caller should pin all reusable workflows to the same reviewed commit. Run the scanner and complete App-selection snapshot in parallel, then invoke dashboard reconciliation unconditionally so planning or scanner failure cannot leave a previous passing dashboard looking current:

```yaml
---
name: Organization source scan
on:
  schedule:
    - cron: "17 3 * * 0"
  workflow_dispatch:
permissions: {}
jobs:
  scan:
    permissions:
      actions: read
      contents: read
      checks: read
      issues: write
      pull-requests: read
    uses: dceoy/segh/.github/workflows/organization-scan.yml@<reviewed-40-character-commit-sha>
    with:
      repository_limit: "50"
      max_parallel: "4"
    secrets:
      SEGH_ORG_SCAN_APP_ID: ${{ secrets.SEGH_ORG_SCAN_APP_ID }}
      SEGH_ORG_SCAN_APP_PRIVATE_KEY: ${{ secrets.SEGH_ORG_SCAN_APP_PRIVATE_KEY }}

  selection:
    permissions: {}
    uses: dceoy/segh/.github/workflows/organization-selection.yml@<reviewed-40-character-commit-sha>
    with:
      repository_limit: "50"
    secrets:
      SEGH_ORG_SCAN_APP_ID: ${{ secrets.SEGH_ORG_SCAN_APP_ID }}
      SEGH_ORG_SCAN_APP_PRIVATE_KEY: ${{ secrets.SEGH_ORG_SCAN_APP_PRIVATE_KEY }}

  reconcile:
    if: always()
    needs:
      - scan
      - selection
    permissions:
      actions: read
      contents: read
      issues: write
    uses: dceoy/segh/.github/workflows/dashboard-reconcile.yml@<reviewed-40-character-commit-sha>
    with:
      stale_after_hours: "192"
      scan_result: ${{ needs.scan.result }}
```

The scanner workflow continues to publish normal per-repository dashboard updates after its matrix finishes. The final reconciliation workflow is intentionally idempotent: when the normal publication is complete it performs no issue write, while a missing plan, missing summary, failed selection, stale prior result, repository retirement, or identity mismatch is handled fail closed.

The default schedule is weekly. The recommended stale threshold is eight days (`192` hours), giving one day of tolerance beyond the normal weekly cadence. Set it between 24 and 720 hours according to the control repository's operating cadence.

The public `dceoy/segh` repository does not publish organization findings. Its direct scheduled scan job is skipped because the repository is public, and manual production execution fails closed.

## Security boundary

For every selected repository, the workflow:

1. uses a planning token with only Metadata and Contents read access;
2. resolves the default branch to an immutable commit before matrix emission;
3. mints a separate repository-scoped read-only token for exactly one matrix target;
4. checks out the exact commit with credential persistence, Git LFS, and submodules disabled;
5. removes tracked symlinks and rejects gitlinks, unmaterialized LFS pointers, unreadable tracked regular files, and incomplete checkouts;
6. installs scanners only from the trusted reusable-workflow revision;
7. ignores target-owned scanner configuration where supported;
8. never executes target scripts, actions, hooks, package managers, installers, builds, tests, or Terraform providers;
9. exposes the target token only to target checkout and Scorecard through a step-local environment variable;
10. uploads raw evidence and a separate bounded normalized summary;
11. publishes normal issues sequentially only after every matrix job has completed;
12. captures the complete App repository identity set in a separate read-only job; and
13. runs issue-write reconciliation without App secrets after both scan and selection jobs have finished, even when either job failed.

Tokens are not job outputs, are not persisted in Git configuration, and are masked before trusted shell commands use them. Scanner and selection jobs have no target write permission and cannot receive the dashboard publisher credential.

## Issue-backed dashboard

The private control repository contains exactly one managed issue for each repository ID that has been actively scanned or requires operator attention. Managed issues include stable hidden markers for the repository ID, current status, previous status, finding fingerprint, semantic result digest, renderer version/digest, and complete body integrity.

- `pass` closes the issue with `scan:pass`;
- `findings`, `incomplete`, and `error` keep the issue open with the corresponding status label;
- an archived or disabled repository with an existing dashboard is closed with `scan:retired` and an explicit selection reason;
- a repository removed from the GitHub App selection is closed with `scan:retired`;
- repository renames update the existing issue by repository ID;
- unchanged normalized results perform no issue or comment write;
- status or finding-fingerprint changes append one bounded history comment;
- missing, duplicate, malformed, or identity-mismatched summaries fail closed as `scan:error`;
- an App-selected repository missing from the immutable scan plan remains represented as `scan:error`;
- a failed run with no complete plan cannot leave a previous `scan:pass` dashboard looking current;
- when complete selection evidence is unavailable, dashboards older than the configured stale threshold are promoted to `scan:error` rather than treated as current;
- incrementing the renderer version migrates existing trusted issue bodies without making scan timestamps or run URLs part of no-op detection.

Reconciliation makes exactly one bounded decision for every repository ID in the selection snapshot and every existing managed dashboard issue. Per-repository issue writes are sequential and independently retried; failures are counted and the reconciliation job fails after attempting the remaining decisions. The job summary contains only organization-level counts for pass, findings, incomplete, error, retired, created, updated, unchanged, deferred, and failed publication operations.

The publisher manages only a fixed label set: five `scan:*` state labels and six bounded `finding:*` category labels. It preserves operator-owned labels.

Issue bodies contain only repository identity, immutable scan metadata, scanner status/counts, selected Scorecard scores, bounded remediation categories, and links to the private workflow run. Raw source excerpts, paths, secret values, scanner logs, and stack traces are excluded.

## Evidence

Each production matrix job retains `repository-scan-<repository-id>` for 14 days. Depending on the execution path, it contains:

- `target.json` with immutable target and workflow provenance;
- `scorecard-permissions.json` with the measured permission set and unavailable-evidence limitations;
- `scanner-versions.txt` and its log;
- `preflight.txt`;
- Scorecard, zizmor, actionlint, ShellCheck, and three independent Trivy outputs and logs;
- `summary.json`, the bounded non-sensitive dashboard input.

A separate `repository-summary-<repository-id>` artifact retains only `summary.json` for one day. The immutable scan plan and complete selection snapshot are likewise retained for one day. The selection snapshot contains only bounded repository identity/class metadata and no source or finding content. Raw evidence remains private and is not a stable public schema.

## Validation

Pull-request CI runs:

- data-driven scan credential-boundary tests;
- reconciliation workflow tests proving the selection job is read-only and the issue-write job receives no App or target credentials;
- dashboard normalization, transition, recovery, retirement, privacy, duplicate, no-op, missing-plan, and stale-failure tests;
- actionlint;
- zizmor;
- ShellCheck;
- YAML and JSON parsing;
- Aqua checksum verification;
- the production reusable scan workflow in guarded `validation_mode` across clean, finding, incomplete-content, checkout-failure, scanner-runtime-error, and no-target-code-execution fixtures, including expected normalized dashboard status.

Repository-contained CI cannot mint the external organization App token or prove private artifact visibility. Before deployment, run the exact reviewed commit from a private control repository and confirm installation enumeration, selection-snapshot upload, repository-scoped token generation, immutable private checkout, private artifact retention, issue create/update/close behavior, and fail-closed reconciliation after an intentionally failed plan. Publish only sanitized run references and conclusions.

## Non-goals

`segh` does not implement organization governance auditing, a general workflow-policy framework, GitHub Projects integration, a historical analytics database, continuous target-push scanning, or compatibility with the former CLI and source-scan reconciliation contracts.
