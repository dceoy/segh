# segh

`segh` is a workflow-only organization source scanner. It runs a small, pinned scanner profile against the immutable default-branch commits of repositories selected by a read-only GitHub App installation.

The repository intentionally contains no CLI, Go implementation, governance policy engine, report renderer, custom REST client, or source-scan reconciler.

## Scanner profile

The workflow runs exactly five established tools:

- OpenSSF Scorecard for informational supply-chain posture evidence;
- zizmor for GitHub Actions security analysis;
- actionlint for workflow validation, with ShellCheck integration;
- ShellCheck for tracked standalone shell files;
- Trivy for vulnerability, secret, and misconfiguration scanning.

Scorecard JSON is always retained. Its aggregate score is not a gate; only failure to run Scorecard reliably fails the repository scan. Findings from the other scanners use their native exit codes and therefore fail the corresponding matrix job.

## Operation

Use `.github/workflows/organization-scan.yml` from a **private control repository**. This is mandatory because GitHub Actions artifacts inherit the visibility of the workflow repository and can contain sensitive findings.

Configure a GitHub App with only repository metadata and contents read access, install it on the authoritative repository selection, and add these secrets to the private control repository:

- `SEGH_READ_APP_ID`
- `SEGH_READ_APP_PRIVATE_KEY`

A scheduled caller can pin the reusable workflow to a reviewed commit:

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

The public `dceoy/segh` repository does not publish organization findings. Its direct scheduled job is skipped because the repository is public; manual execution fails closed. A private caller or private deployment activates scheduled and manual scans.

## Security boundary

For every selected repository, the workflow:

1. resolves the default branch to an immutable commit SHA;
2. mints a repository-scoped read-only token;
3. checks out the exact commit with credentials, Git LFS, and submodules disabled;
4. removes tracked symlinks and rejects submodules, unmaterialized LFS pointers, and checkouts without regular tracked files;
5. installs the five scanner binaries from pinned Aqua packages with required checksums;
6. runs only trusted scanner commands and never executes target repository code;
7. uploads raw scanner output and immutable target metadata as a private per-repository artifact.

A scanner finding, checkout failure, preflight rejection, or scanner runtime error is represented by the native GitHub Actions matrix-job conclusion. `segh` does not create a custom status format or aggregate exit-code taxonomy.

## Evidence

Each matrix job retains `repository-scan-<repository-id>` for 14 days. Depending on the execution path, it contains:

- `target.json` with repository identity, default branch, and immutable commit;
- `preflight.txt`;
- `scorecard.json` and `scorecard.log`;
- `zizmor.json` and `zizmor.log`;
- `actionlint.jsonl` and `actionlint.log`;
- `shellcheck.json` and `shellcheck.log`;
- `trivy.json` and `trivy.log`.

## Non-goals

`segh` does not audit organization rulesets, classic branch protection, Actions settings, Dependabot, dependency graphs, `SECURITY.md`, or other GitHub governance controls. It does not maintain compatibility with the former CLI, configuration schemas, suppressions, `inventory.json`, `audit.json`, `report.md`, `scan-manifest.json`, or normalized source-scan status evidence.
