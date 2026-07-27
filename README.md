# segh

`segh` is a thin SecOps orchestration and compliance-audit toolkit for GitHub
Enterprise organizations. It inventories repositories, compares GitHub settings
with an explicit policy, runs established scanners without executing repository
code, publishes compatible SARIF, and produces deterministic organization
reports.

It deliberately does **not** implement a SAST engine, vulnerability database,
web UI, dependency updater, or settings controller. Use GitHub Code Security
Configurations, CodeQL default setup, secret scanning, push protection,
Dependabot, Actions policies, and organization rulesets as the primary controls.

## Quick start

Requirements are Go 1.23 or later and the scanner binaries pinned by
[`aqua.yaml`](aqua.yaml).

```console
cp segh.example.yaml segh.yaml
aqua install
uv sync --frozen --project tools
export PATH="$PWD/tools/.venv/bin:$PATH"
go build -o bin/segh ./cmd/segh
bin/segh --help
bin/segh validate
bin/segh inventory
bin/segh audit
bin/segh scan --inventory segh-results/inventory.json
bin/segh report \
  --inventory segh-results/inventory.json \
  --audit segh-results/audit.json \
  --scan segh-results/scan.json
```

Configuration rejects unknown fields. Existing tokens are disabled unless
`auth.allow_existing_token` is explicitly enabled; GitHub App installation
tokens are otherwise generated on demand and retained only in memory.

## Commands and stable exit codes

| Command | Purpose |
|---|---|
| `inventory` | Paginated organization inventory with bounded enrichment |
| `audit` | Deterministic expected-state policy evaluation |
| `scan` | Fixed adapters for zizmor, Trivy misconfiguration, Scorecard, and optional Semgrep |
| `publish` | Context-validated SARIF upload and asynchronous status polling |
| `batch` / `merge` | Deterministic organization batches and isolated-result aggregation |
| `report` | Consolidated JSON and Markdown |
| `remediate` | Guidance only; no settings mutation |
| `pr-gate` | Baseline comparison and gating of newly introduced findings |

Exit codes are `0` success, `1` policy/blocking findings, `2` invalid
configuration or arguments, `3` authentication/permission failure, `4`
partial or unsupported coverage, and `5` scanner/runtime failure.

## Security model

- Target repositories are shallow-cloned at the default branch into a unique
  temporary directory. Builds, package managers, hooks, and repository scripts
  are never run.
- Scanner commands and arguments are fixed in Go. Configuration cannot supply
  shell commands. Subprocess environments are rebuilt from a small allowlist;
  only Scorecard receives a read-only API token.
- Changed-file paths are accepted in NUL-delimited form, normalized, checked
  against traversal and escaping symlinks, size-bounded, and copied into an
  isolated scan tree.
- Git credentials are supplied only to the `git` subprocess through an
  ephemeral environment entry and are never logged or inherited by scanners.
- Scanner wall-clock, CPU, address-space, repository, total-run, and concurrency
  bounds are configurable. CPU/address-space enforcement uses Linux `prlimit`
  and fails closed when requested but unavailable.
- Scanner jobs use read-only credentials. A separate publication command/job
  receives `security_events: write` or the GitHub App equivalent.
- SARIF upload validates repository, full commit SHA, full ref, stable category,
  and input size. Unsupported code scanning is reported as `unsupported`, while
  artifacts remain available.

See [the architecture and operations guide](docs/architecture.md),
[minimal GitHub App permissions](docs/github-app-permissions.md),
[policy mapping](docs/policies.md), and [workflow rollout](docs/workflows.md).

## Development

```console
make fmt
make test
make lint
make build
```

The CI workflow runs formatting, vet, tests, lint, and a reproducible build.
Application-code SAST is intentionally delegated to GitHub CodeQL default setup.
