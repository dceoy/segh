# segh

`segh` is a focused security-governance audit tool for GitHub organizations. It
inventories coverage by GitHub-native controls, selects repositories using
organization metadata and custom properties, evaluates explicit policy and
time-bounded suppressions, and writes deterministic compliance reports.

Scanner execution, SARIF publication, and merge enforcement belong to GitHub
Actions, Code Scanning, Security Configurations, and organization rulesets.
`segh` does not clone repositories, run scanners, publish SARIF, generate
GitHub App JWTs, or reconstruct pull-request baselines.

## Quick start

Requirements are Go 1.23 or later, the GitHub CLI, and a read-only `GH_TOKEN`.

```console
cp segh.example.yaml segh.yaml
export GH_TOKEN=...
go build -o bin/segh ./cmd/segh
bin/segh validate
bin/segh inventory
bin/segh audit
bin/segh report
```

The governance-only configuration is version 2. Version 1 scanner, execution,
publication, and pull-request sections are intentionally rejected; remove them
when migrating.

The token must be authorized for the configured organization and host. In
GitHub Actions, generate it with `actions/create-github-app-token`; do not store
an installation token or App private key in `segh` configuration.

## Commands and stable exit codes

| Command | Purpose |
|---|---|
| `validate` | Strict configuration validation |
| `inventory` | Capability-aware coverage assessment of native controls |
| `audit` | Deterministic policy and suppression evaluation |
| `report` | Consolidated JSON and Markdown compliance report |
| `remediate` | Guidance only; no settings mutation |

Exit codes are `0` success, `1` policy violations, `2` invalid configuration or
arguments, `3` authentication/permission failure, `4` partial or unsupported
coverage, and `5` runtime failure.

## GitHub-native scanner enforcement

The supplied central pull-request workflow runs checksum-pinned zizmor and
Trivy binaries plus the pinned OpenSSF Scorecard action. Each SARIF file is
uploaded through `github/codeql-action/upload-sarif` with a stable scanner
category from a separate publication job and also retained as an artifact.
Configure an organization ruleset to require the central workflow and Code
Scanning results for selected repositories; Code Scanning merge protection
owns severity thresholds and required-tool enforcement.

Organization audits are read-only. The supplied audit workflow uses
`actions/create-github-app-token` and exposes the result only as `GH_TOKEN` to
the inventory step. GitHub CLI owns authentication, pagination, transport, and
GHES hostname handling; `segh` adds bounded exponential retries for transient
transport, server, and rate-limit failures.

See [architecture](docs/architecture.md), [workflow rollout](docs/workflows.md),
[App permissions](docs/github-app-permissions.md), and
[policy mapping](docs/policies.md).

## Development

```console
make fmt
make test
make lint
make build
```
