# segh

`segh` is a workflow-only organization source scanner. It runs a small, pinned scanner profile against immutable default-branch commits selected by a read-only GitHub App installation.

The repository intentionally contains no CLI, Go implementation, governance policy engine, report renderer, custom REST client, source-scan reconciler, or normalized evidence schema.

## Scanner profile

The workflow installs exactly five checksum-pinned tools through trusted Aqua configuration:

- OpenSSF Scorecard for informational supply-chain posture evidence;
- zizmor for tracked GitHub Actions workflows and action definitions;
- actionlint for tracked workflow validation with trusted ShellCheck configuration;
- ShellCheck for tracked regular shell files and supported shell shebangs;
- Trivy for independent vulnerability, secret, and misconfiguration scans.

Scorecard runs against the immutable repository and commit with `--show-details`. Its aggregate score is not a gate. The repository job fails when Scorecard cannot execute or does not produce valid non-empty JSON. No SARIF is uploaded and no custom score threshold is implemented.

## Repository selection

The GitHub App installation selection is authoritative. Planning excludes disabled and archived repositories, includes explicitly selected forks, sorts targets deterministically, validates repository identity and visibility, and resolves every default branch to a lowercase 40-character commit SHA.

Planning fails closed on malformed pagination, duplicate identities, empty or oversized selections, unavailable default branches, unresolved commits, or invalid immutable SHAs.

## Credential architecture

Organization discovery, target scanning, and future issue publication use separate credential domains:

```text
plan
  └─ organization installation token, read-only

scan matrix
  └─ one repository-scoped installation token per target, read-only

publish-dashboard (future #74 implementation)
  └─ private control-repository GITHUB_TOKEN with issues: write
```

No job may receive both scan credentials and an issue-write credential. The current workflow does not implement dashboard publication or scheduled reconciliation from #74 and #76.

See [CREDENTIALS.md](CREDENTIALS.md) for the complete permission mapping, Scorecard limitations, publisher contract, private-control-repository requirements, and migration guidance.

## Operation

Consume `.github/workflows/organization-scan.yml` from a **private execution or control repository**. This is mandatory because artifacts can contain private repository identities, paths, dependency information, findings, and scanner logs.

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

A caller should pin the reusable workflow to a reviewed commit:

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
      contents: read
      checks: read
      issues: read
      pull-requests: read
    uses: dceoy/segh/.github/workflows/organization-scan.yml@<reviewed-40-character-commit-sha>
    with:
      repository_limit: "50"
      max_parallel: "4"
    secrets:
      SEGH_ORG_SCAN_APP_ID: ${{ secrets.SEGH_ORG_SCAN_APP_ID }}
      SEGH_ORG_SCAN_APP_PRIVATE_KEY: ${{ secrets.SEGH_ORG_SCAN_APP_PRIVATE_KEY }}
```

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
10. uploads only the bounded `results` directory.

Tokens are not job outputs, are not persisted in Git configuration, and are masked before trusted shell commands use them. Job-level permissions are explicit. Scanner jobs have no write permission and cannot receive a future publisher credential.

## Evidence

Each production matrix job retains `repository-scan-<repository-id>` for 14 days. Depending on the execution path, it contains:

- `target.json` with immutable target and workflow provenance;
- `scorecard-permissions.json` with the measured permission set and unavailable-evidence limitations;
- `scanner-versions.txt` and its log;
- `preflight.txt`;
- Scorecard, zizmor, actionlint, ShellCheck, and three independent Trivy outputs and logs.

These files are raw private evidence, not a stable public schema. They must remain in a private workflow execution context whenever any target is private or internal.

## Validation

Pull-request CI runs:

- data-driven workflow credential-boundary tests;
- actionlint;
- zizmor;
- ShellCheck;
- YAML and JSON parsing;
- Aqua checksum verification;
- the production reusable workflow in guarded `validation_mode` across clean, finding, incomplete-content, checkout-failure, scanner-runtime-error, and no-target-code-execution fixtures.

Repository-contained CI cannot mint the external organization App token or prove private artifact visibility. Before deploying a changed permission profile, run the exact reviewed commit from a private control repository and confirm installation enumeration, repository-scoped token generation, immutable private checkout, and one private Scorecard scan. Publish only sanitized run references and conclusions.

## Non-goals

`segh` does not implement issue dashboards, scheduled dashboard reconciliation, organization governance auditing, a general workflow-policy framework, or compatibility with the former CLI and source-scan reconciliation contracts.
