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

Scorecard runs against the immutable GitHub repository and commit with `--show-details`. Its aggregate score is not a gate. The repository job fails only when Scorecard cannot execute or does not produce valid non-empty JSON. No SARIF is uploaded and no score threshold is implemented.

## Repository selection

The GitHub App installation selection is authoritative.

Planning:

- excludes disabled and archived repositories;
- includes selected forks rather than applying an additional fork filter;
- sorts targets deterministically by full repository name;
- validates repository ID, full name, owner, name, visibility, fork status, and default branch;
- resolves every default branch to a lowercase 40-character commit SHA;
- rejects malformed pagination, duplicate identities, empty selections, unresolved commits, and selections larger than `repository_limit` before emitting the matrix.

A selected fork is scanned because the App installation explicitly selected it. Fork status is retained in immutable target metadata.

## Operation

Use `.github/workflows/organization-scan.yml` from a **private control repository**. This is mandatory because GitHub Actions artifacts inherit the visibility of the caller repository and can contain sensitive findings.

Configure a GitHub App with this repository-level read permission set:

- Metadata;
- Contents;
- Issues;
- Pull requests;
- Checks.

This set follows the OpenSSF Scorecard private-repository guidance for commit and SAST detection and is also sufficient for immutable checkout and the other scanners. `Actions` and `Administration` are intentionally not requested because repository-contained validation and current upstream guidance do not demonstrate that they are required. A real private App-backed deployment must confirm the final set before #78 can close.

Install the App on the authoritative repository selection, then add these secrets to the private control repository:

- `SEGH_READ_APP_ID`
- `SEGH_READ_APP_PRIVATE_KEY`

A scheduled caller should pin the reusable workflow to a reviewed commit:

```yaml
---
name: Organization source scan
on:
  schedule:
    - cron: "17 3 * * 0"
  workflow_dispatch:
permissions:
  contents: read
jobs:
  scan:
    uses: dceoy/segh/.github/workflows/organization-scan.yml@<reviewed-40-character-commit-sha>
    with:
      repository_limit: "50"
      max_parallel: "4"
    secrets:
      SEGH_READ_APP_ID: ${{ secrets.SEGH_READ_APP_ID }}
      SEGH_READ_APP_PRIVATE_KEY: ${{ secrets.SEGH_READ_APP_PRIVATE_KEY }}
```

The public `dceoy/segh` repository does not publish organization findings. Its direct scheduled job is skipped because the repository is public; manual execution fails closed.

## Security boundary

For every selected repository, the workflow:

1. resolves the default branch to an immutable commit SHA before matrix emission;
2. mints a repository-scoped read-only token;
3. checks out the exact commit with credential persistence, Git LFS, and submodules disabled;
4. removes tracked symlinks and rejects gitlinks, unmaterialized LFS pointers, unreadable tracked regular files, and checkouts without tracked regular files;
5. installs scanners only from the trusted workflow revision;
6. ignores target-owned scanner configuration and ignore files where the tools support this;
7. executes only trusted scanner command lines and never invokes target scripts, actions, hooks, package managers, installers, builds, tests, or Terraform providers;
8. uploads private raw evidence after scanner findings and runtime errors whenever target metadata exists.

Native GitHub Actions step and matrix-job conclusions distinguish planning, checkout/preflight, scanner finding, and scanner runtime failures. `segh` does not create a custom status taxonomy or aggregate result engine.

## Evidence

Each production matrix job retains `repository-scan-<repository-id>` for 14 days. Depending on the execution path, it contains:

- `target.json` with repository ID, full name, visibility, fork status, default branch, immutable commit, workflow run ID and attempt, and trusted workflow repository and SHA;
- `scanner-versions.txt` and its log;
- `preflight.txt`;
- `scorecard.json`, `scorecard.log`, and `scorecard-status.txt`;
- `zizmor.json` and `zizmor.log`;
- `actionlint.jsonl` and `actionlint.log`;
- `shellcheck.json`, `shellcheck.log`, and `shellcheck-status.txt`;
- `trivy-vulnerability.json` and `trivy-vulnerability.log`;
- `trivy-secret.json` and `trivy-secret.log`;
- `trivy-misconfiguration.json` and `trivy-misconfiguration.log`.

These files are raw private evidence, not a stable public schema.

## Validation

Pull-request CI invokes the real reusable workflow in guarded `validation_mode`. It uses deterministic controlled fixtures for:

- clean and no-relevant-file repositories;
- zizmor, actionlint syntax, embedded shell, and standalone ShellCheck findings;
- Trivy vulnerability, secret, and misconfiguration findings;
- tracked symlink removal, gitlink rejection, and Git LFS pointer rejection;
- immutable checkout failure;
- scanner runtime failure while earlier scanner evidence remains available;
- the production matrix-bound predicate;
- proof that target package scripts, actions, hooks, installers, builds, tests, and Terraform providers are not executed.

PR CI cannot validate GitHub App installation enumeration, real repository-scoped token creation, private checkout, or artifact privacy. Those checks require a private control repository pinned to the exact candidate commit. Record only sanitized run URLs and conclusions; never expose secrets or private artifact contents.

## Non-goals

`segh` does not audit organization rulesets, classic branch protection, Actions settings, Dependabot, dependency graphs, `SECURITY.md`, or other GitHub governance controls. It does not maintain compatibility with the former CLI, configuration schemas, suppressions, `inventory.json`, `audit.json`, `report.md`, `scan-manifest.json`, `scan-summary.json`, or normalized source-scan status evidence.
