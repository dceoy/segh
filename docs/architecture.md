# Architecture and result model

## Boundaries

The `cmd/segh` package only selects a command and stable exit code. Internal
packages intentionally separate:

- `github`: short-lived authentication, retrying REST access, capability-aware
  inventory;
- `policy`: explicit deterministic comparisons and expiring suppressions;
- `scanner`: fixed external-tool adapters and isolated worktrees;
- `sarif` / `publication`: native finding preservation and GitHub publication;
- `gate`: fingerprint-based baseline comparison;
- `batch` / `merge` / `report`: deterministic execution and consolidation.

There is no dynamic plugin or rule engine. External commands are fixed arrays
passed directly to the operating system, never to a shell.

## Normalized state

Inventory observations have a `state` of `available`, `unknown`, or
`unsupported`, plus the source endpoint and a bounded reason. Policy records
use `pass`, `fail`, `unknown`, `unsupported`, or `exempt`. Missing permissions
and unavailable GHES capabilities can therefore never silently become a pass.

Scanner states are:

- `clean`: scanner completed and emitted valid SARIF with no findings;
- `findings`: scanner completed and emitted one or more findings;
- `failed`: timeout, invalid SARIF, version mismatch, or runtime failure;
- `skipped`: disabled or no supported files;
- `planned`: dry-run selection without a clone or scanner execution.

Aqua verifies the native scanners and developer tools against its pinned
registry metadata. Optional Semgrep is locked with hashes for its complete
Python dependency graph in `tools/uv.lock`; add `tools/.venv/bin` to `PATH` only
when organization-specific Semgrep rules are enabled.

Each run records its ID, configuration SHA-256, selected count, per-repository
queue/start/end/duration, scanner version/duration, errors, and coverage.
GitHub API retries and rate-limit events are structured JSON log events.

## Determinism and persistence

Inventory, policy, scanner, batch, and report arrays are sorted by repository
and stable identifier. JSON is the canonical automation format; optional JSONL
contains one normalized record per line. Markdown is an operator summary, and
raw SARIF remains an artifact. The toolkit does not create a database.

Schemas are versioned in each top-level document. Incompatible versions are
rejected rather than guessed. Artifacts should be retained only for the
configured period; private source worktrees are always temporary and are never
uploaded or cached.

## Capability differences

REST, web, and GraphQL endpoints are explicit for GitHub Enterprise Cloud or
Server. REST endpoints returning feature-unavailable responses are recorded as
`unsupported`; permission or ambiguous responses are `unknown`. SARIF upload
has a separate `unsupported` result and retains the source SARIF. This is
especially important on GHES installations without code scanning licensing or
newer organization ruleset and Code Security Configuration APIs.
