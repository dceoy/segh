# segh

`segh` audits GitHub Enterprise organization governance and periodically scans
selected default-branch commits. It is designed for private repositories
without GitHub Code Security or GitHub Secret Protection licenses.

The supported baseline is:

- organization rulesets and ordinary required checks enforce merges;
- zizmor audits GitHub Actions;
- actionlint validates GitHub Actions semantics and invokes ShellCheck for
  embedded shell;
- ShellCheck validates standalone tracked shell scripts;
- Checkov gates infrastructure-as-code misconfigurations;
- Trivy gates secrets and dependency vulnerabilities;
- scanner JSON, text, and logs are retained as Actions artifacts;
- OpenSSF Scorecard is informational;
- dependency graph, Dependabot alerts, and Dependabot security updates remain
  GitHub-native controls; and
- no scanner result is sent to the GitHub Code Scanning service.

## Quick start

Copy the example and edit the organization and policies:

```bash
cp segh.example.yaml segh.yaml
export GH_TOKEN=...
export SEGH_GITHUB_INSTALLATION_ID=...
go build -o bin/segh ./cmd/segh
bin/segh audit --config segh.yaml
```

`audit` strictly validates the version 4 configuration before making API
requests, collects inventory, evaluates policy, and writes:

- `segh-results/inventory.json`
- `segh-results/audit.json`
- `segh-results/report.md`

Use `bin/segh audit --config segh.yaml --validate-only` for offline validation.
Only schema version 4 is accepted. Older versions and removed fields are
rejected without aliases or migration logic.

## Commands and exit codes

| Command        | Purpose                                                  |
| -------------- | -------------------------------------------------------- |
| `audit`        | Validate, inventory, evaluate policy, and write evidence |
| `scan-plan`    | Resolve selected repositories to immutable commits       |
| `scan-summary` | Validate and aggregate repository scan evidence          |

Exit codes are `0` success, `1` policy violations, `2` invalid configuration or
arguments, `3` authentication or permission failure, `4` incomplete coverage,
and `5` runtime failure.

## Pull-request gate

Keep the existing `PR security / scan` required workflow active until the
trusted `Repository security` replacement in
[`dceoy/gha-for-devops`](https://github.com/dceoy/gha-for-devops) has direct
pull-request and merge-group triggers and its organization-ruleset rollout is
verified. `segh` already uses the reviewed upstream scanner for periodic
organization scans; remove the local PR workflow only in the follow-up
migration.

## Organization audit and periodic source scan

The organization audit is read-only. Its GitHub App inventories Actions policy,
rulesets, branch protection, custom properties, dependency graph, Dependabot
coverage, and repository metadata. It does not clone repositories or run
scanners during governance collection. When `source_scan.enabled` is true, the
scheduled control workflow reuses that selected inventory, records every
default branch's exact commit SHA, and scans each checkout with the pinned
`gha-for-devops` static-analysis policy. Repository scripts, package installers,
submodules, Git LFS objects, and Terraform providers are never executed or
initialized.

Source scanning writes separate `scan-manifest.json`, `scan-summary.json`, and
per-repository evidence. Findings, incomplete content or checkout coverage, and
scanner runtime errors remain distinct from the existing governance schemas and
exit semantics.

`GH_HOST` selects GHE.com or GitHub Enterprise Server and defaults to
`github.com`.
The matching short-lived App token and installation ID are required for a live
audit. See [docs/github-app-permissions.md](docs/github-app-permissions.md).

## Cost and limitations

This design requires GitHub Enterprise seats and enough GitHub Actions capacity.
It does not require GitHub Code Security or GitHub Secret Protection licenses.

The tradeoff is deliberate: there is no server-side secret push prevention,
GitHub security-alert lifecycle or organization security overview,
CodeQL-equivalent deep interprocedural SAST, or native finding dismissal,
campaign, fingerprint, baseline, and severity-gate UI. Scanner artifacts and
ordinary check results are the evidence and enforcement boundary.

## Documentation

- [Architecture](docs/architecture.md)
- [Workflows and rollout](docs/workflows.md)
- [GitHub App permissions](docs/github-app-permissions.md)
- [Policies](docs/policies.md)
- [Output schemas](docs/output-schemas.md)
- [Remediation](docs/remediation.md)
