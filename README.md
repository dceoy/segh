# segh

`segh` audits GitHub Enterprise organization governance and periodically scans
selected default-branch commits. It is designed for private repositories
without GitHub Code Security or GitHub Secret Protection licenses.

The supported baseline is:

- the CLI inventories GitHub-native organization and repository controls;
- deterministic policy evaluation produces private governance evidence;
- periodic source scans resolve immutable default-branch commits;
- the periodic scan matrix delegates repository scanning to a reviewed,
  full-SHA-pinned `dceoy/gha-for-devops` reusable workflow;
- scanner JSON, text, and logs are retained as private Actions artifacts;
- dependency graph, Dependabot alerts, and Dependabot security updates remain
  GitHub-native controls; and
- no scanner result is sent to the GitHub Code Scanning service.

## Quick start

`segh audit --config segh.yaml` is the one operator workflow: configure,
validate, audit, read the evidence.

```bash
# 1. Configure
cp segh.example.yaml segh.yaml
# edit organization and policies

# 2. Validate offline, no GitHub credentials required
go build -o bin/segh ./cmd/segh
bin/segh audit --config segh.yaml --validate-only

# 3. Audit
export GH_TOKEN=...
export SEGH_GITHUB_INSTALLATION_ID=...
bin/segh audit --config segh.yaml

# 4. Read the evidence
cat segh-results/report.md
```

`audit` strictly validates the version 5 configuration before making API
requests, collects one authoritative inventory, evaluates policy, and writes
`segh-results/inventory.json`, `segh-results/audit.json`, and
`segh-results/report.md`. When `source_scan.enabled` is true, the same execution
also resolves immutable default-branch commits and writes
`segh-results/scan-manifest.json`. Only schema version 5 is accepted; older
versions and removed fields are rejected without aliases or migration logic.

Exit codes are `0` success, `1` policy or source-scan findings, `2` invalid
configuration or arguments, `3` authentication or permission failure, `4`
incomplete coverage, and `5` runtime failure.

`segh.example.yaml` shows the recommended starter fields only; see
[Policies](docs/policies.md) for suppressions and advanced, commonly-defaulted
configuration, and the embedded JSON Schema
(`schema/segh-config-v5.schema.json`) for the complete reference.

The organization workflow uses the same `audit` executable route to reconcile
repository artifacts after the matrix completes; see
[Workflows](docs/workflows.md).

## Scope boundary

`segh` does not scan pull requests, run security jobs for merge queues, or
publish pull-request security checks. Pull-request and merge-queue security
enforcement are outside this repository's scope and must be provided
independently where required.

## Organization audit and periodic source scan

The organization audit is read-only. Its GitHub App inventories Actions policy,
rulesets, branch protection, dependency graph, Dependabot coverage, and
repository metadata. It does not clone repositories or run scanners during
governance collection. When `source_scan.enabled` is true, the same audit
execution reuses its selected inventory, records every default branch's exact
commit SHA, and delegates each target to `gha-for-devops`'s pinned
`repository-security-scan.yml` reusable workflow. The upstream workflow mints
its own repository-scoped token, checks out the recorded commit, runs the
static-analysis policy, classifies the repository result, and publishes the
identity-bound `status.json`. `segh` retains only organization-specific
inventory collection, commit resolution, bounded matrix control, identity
reconciliation, and aggregate output. Repository scripts, package installers,
submodules, Git LFS objects, and Terraform providers are never executed or
initialized.

Source scanning writes separate `scan-manifest.json`, `scan-summary.json`, and
per-repository evidence. Findings, incomplete content or checkout coverage, and
scanner runtime errors remain distinct from the existing governance schemas and
exit semantics.

`GH_HOST` selects GHE.com or GitHub Enterprise Server and defaults to
`github.com`. The matching short-lived App token and installation ID are
required for a live audit. See
[GitHub App permissions](docs/github-app-permissions.md).

## Cost and limitations

This design requires GitHub Enterprise seats and enough GitHub Actions capacity.
It does not require GitHub Code Security or GitHub Secret Protection licenses.

The tradeoff is deliberate: there is no server-side secret push prevention,
GitHub security-alert lifecycle or organization security overview,
CodeQL-equivalent deep interprocedural SAST, or native finding dismissal,
campaign, fingerprint, baseline, and severity-gate UI. Scanner artifacts are
the periodic source-scan evidence boundary.

## Documentation

- [Architecture](docs/architecture.md)
- [Workflows](docs/workflows.md)
- [GitHub App permissions](docs/github-app-permissions.md)
- [Policies](docs/policies.md)
- [Output schemas](docs/output-schemas.md)
- [Remediation](docs/remediation.md)
