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

Requirements are Go 1.23 or later, the GitHub CLI, a read-only `GH_TOKEN`, and
the matching GitHub App installation ID.

```console
cp segh.example.yaml segh.yaml
export GH_TOKEN=...
export SEGH_GITHUB_INSTALLATION_ID=...
go build -o bin/segh ./cmd/segh
bin/segh audit --config segh.yaml
```

`audit` is the only operational command. It validates the schema version 3
configuration before making any API request, collects inventory, evaluates
policy, and writes `segh-results/inventory.json`, `audit.json`, and `report.md`.
Use `bin/segh audit --config segh.yaml --validate-only` for offline validation.
Versions 1 and 2 and removed keys are rejected rather than migrated.

The token must be authorized for the configured organization. `GH_HOST` selects
GitHub Enterprise Server and defaults to `github.com`; the normalized effective
host is recorded in inventory evidence. In GitHub Actions, generate the token
with `actions/create-github-app-token`; do not store an installation token or
App private key in `segh` configuration.

## Commands and stable exit codes

| Command | Purpose |
|---|---|
| `audit` | End-to-end validation, inventory, policy evaluation, and evidence generation |

Exit codes are `0` success, `1` policy violations, `2` invalid configuration or
arguments, `3` authentication/permission failure, `4` partial or unsupported
coverage, and `5` runtime failure.

## GitHub-native scanner enforcement

The supplied central pull-request workflow runs checksum-pinned zizmor and
Trivy binaries plus the pinned OpenSSF Scorecard action with a read-only token.
Each SARIF file is retained as an artifact. A protected `workflow_run`
publisher installed in every target repository validates the central workflow
identity and artifact metadata, then uploads through
`github/codeql-action/upload-sarif` with a stable scanner category. It checks
out the exact analyzed commit without credentials solely to preserve SARIF
fingerprints and never executes pull-request code, so publication also works
for fork and Dependabot pull requests. The central source repository is
excluded from its own scanner and publisher. Configure an organization ruleset
to require the central workflow and Code Scanning results for selected target
repositories; Code Scanning merge protection owns severity thresholds and
required-tool enforcement.

Organization audits are read-only. The supplied audit workflow uses
`actions/create-github-app-token` and exposes its short-lived token and
non-secret installation ID to the audit step. GitHub CLI owns
authentication, pagination, transport, and GHES hostname handling; `segh` adds
bounded exponential retries for transient transport, server, and rate-limit
failures.

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
