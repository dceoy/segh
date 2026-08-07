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

The GitHub App installation selection is authoritative. Planning excludes disabled and archived repositories, includes explicitly selected forks, sorts targets deterministically, validates repository identity and visibility, and resolves every default branch to a lowercase 40-character commit SHA.

Planning fails closed on malformed pagination, duplicate identities, empty or oversized selections, unavailable default branches, unresolved commits, or invalid immutable SHAs.

## Credential architecture

Organization discovery, target scanning, and issue publication use separate credential domains:

```text
plan
  └─ organization installation token, read-only

scan matrix
  └─ one repository-scoped installation token per target, read-only

publish-dashboard
  └─ private control-repository GITHUB_TOKEN with actions: read,
     contents: read, and issues: write
```

No job receives both scan credentials and an issue-write credential. The publisher receives no configured secrets and can write issues only in the private caller repository.

See [CREDENTIALS.md](CREDENTIALS.md) for the complete permission mapping, Scorecard limitations, publisher contract, private-control-repository requirements, and migration guidance.

## Operation

Consume `.github/workflows/organization-scan.yml` from a **private execution or control repository**. This is mandatory because artifacts and dashboard issues can contain private repository identities and security status.

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

A caller should pin the reusable workflow to a reviewed commit and grant the maximum permissions required by its isolated jobs:

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
```

The called workflow narrows the scanner jobs back to read-only permissions. Only the final publisher job receives `issues: write`.

The public `dceoy/segh` repository does not publish organization findings. Its direct scheduled job is skipped because the repository is public, and manual production execution fails closed.

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
11. publishes issues sequentially only after every matrix job has completed.

Tokens are not job outputs, are not persisted in Git configuration, and are masked before trusted shell commands use them. Scanner jobs have no write permission and cannot receive the publisher credential.

## Issue-backed dashboard

The private control repository contains exactly one managed issue for each immutable repository ID. Managed issues include stable hidden markers for the repository ID, current status, previous status, finding fingerprint, semantic result digest, renderer version/digest, and complete body integrity.

- `pass` closes the issue with `scan:pass`;
- `findings`, `incomplete`, and `error` keep the issue open with the corresponding status label;
- a repository removed from the active plan is closed with `scan:retired`;
- repository renames update the existing issue by repository ID;
- unchanged normalized results perform no issue or comment write;
- status or finding-fingerprint changes append one bounded history comment;
- missing, duplicate, malformed, or identity-mismatched summaries fail closed as `scan:error`;
- incrementing the renderer version migrates existing trusted issue bodies without making scan timestamps or run URLs part of no-op detection.

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

A separate `repository-summary-<repository-id>` artifact retains only `summary.json` for one day. The authoritative publication plan is likewise retained for one day. Raw evidence remains private and is not a stable public schema.

## Validation

Pull-request CI runs:

- data-driven workflow credential-boundary tests;
- dashboard normalization, transition, recovery, retirement, privacy, duplicate, and no-op tests;
- actionlint;
- zizmor;
- ShellCheck;
- YAML and JSON parsing;
- Aqua checksum verification;
- the production reusable workflow in guarded `validation_mode` across clean, finding, incomplete-content, checkout-failure, scanner-runtime-error, and no-target-code-execution fixtures, including expected normalized dashboard status.

Repository-contained CI cannot mint the external organization App token or prove private artifact visibility. Before deployment, run the exact reviewed commit from a private control repository and confirm installation enumeration, repository-scoped token generation, immutable private checkout, private artifact retention, and issue create/update/close behavior. Publish only sanitized run references and conclusions.

## Non-goals

`segh` does not implement organization governance auditing, a general workflow-policy framework, GitHub Projects integration, a historical analytics database, continuous target-push scanning, or compatibility with the former CLI and source-scan reconciliation contracts. Complete organization-wide stale-state reconciliation remains separate work.
