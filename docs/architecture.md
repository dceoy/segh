# Architecture

`segh` has two read-only organization-level contracts with separate evidence.
It has no pull-request or merge-queue execution path and publishes no
pull-request checks.

```text
Organization audit
  ├─ GitHub REST inventory
  ├─ deterministic governance evaluation
  └─ inventory.json + audit.json + report.md

Periodic organization source scan
  ├─ immutable targets from the authoritative inventory
  ├─ bounded reusable-workflow matrix
  ├─ repository evidence from dceoy/gha-for-devops
  └─ scan-manifest.json + scan-summary.json + repository artifacts
```

## Source-scan responsibility boundary

The removed `scan-plan` and `scan-summary` routes previously split one control
flow into three CLI executions. Their responsibilities now map as follows:

| Responsibility | Owner |
| --- | --- |
| Configuration validation, inventory collection, repository selection | `segh audit` governance path |
| Default-branch SHA resolution, deterministic target ordering, matrix bound, `scan-manifest.json` | `segh audit` organization controller |
| Target token, checkout, preflight, scanners, repository classification, `status.json` | pinned `gha-for-devops` workflow |
| Artifact discovery, planned-identity matching, missing/duplicate/malformed evidence, aggregate counts and bounded summary | `segh audit` organization reconciliation mode |
| Re-reading configuration or inventory between planning stages | deleted duplication |

A concrete upstream-aggregation prototype was rejected: a generic upstream
workflow would need to accept `segh`'s organization manifest, discover a whole
matrix's artifacts, reproduce manifest-specific identity checks, and return a
second adapter contract. That moves rather than removes the organization logic
and increases total workflow, adapter, test, and documentation surface. The
adopted prototype instead keeps the existing small manifest-aware reconciler
local while eliminating both standalone commands, one configuration reload, one
inventory serialization/read boundary, a second App-token mint, and two
executable routes.

## Trust boundaries

The organization audit receives a short-lived, read-only GitHub App token. It
validates configuration before API access, bounds response sizes, retries
transient failures, and treats unavailable evidence as `unknown` or
`unsupported`, never as a pass. When lock-file policy is enabled, it reads only
the default-branch tree and matched manifest content through the REST API; it
never checks out or executes repository content.

When source scanning is enabled, the same audit execution reuses the collected
inventory and resolves each selected default branch through the API. It records
the returned lowercase 40-character SHA in a separate manifest. Each target is
then delegated to the pinned `repository-security-scan.yml` reusable workflow.
That workflow mints a repository-scoped token, checks out only the recorded SHA
with credentials, LFS, and submodules disabled, runs its trusted scanner
pipeline, classifies the repository, and publishes identity-bound
`status.json`. Tracked symlinks are removed; submodule gitlinks and Git LFS
pointers make coverage incomplete.

The organization reconciler parses status artifacts as untrusted input. It
requires the planned repository ID, full name, default branch, and commit SHA to
match exactly and fails closed on missing, duplicate, malformed, unsupported,
or mismatched evidence. It does not install scanners or reproduce
repository-level classification.

## Scope boundary

Pull-request source scanning, merge-queue security enforcement, and
pull-request check publication are intentionally outside `segh`. The
organization source-scan controller does not expose compatibility wrappers,
feature flags, or event-specific aliases for those removed responsibilities.

## Dependency evaluations

Configuration is structurally validated against the embedded version 5 JSON
Schema before typed decoding and duration conversion. The maintained
`github.com/santhosh-tekuri/jsonschema/v6` validator compiles that schema
in-memory without runtime network or filesystem access. A strict date-time
format override preserves the typed configuration contract. Its adoption
removed the handwritten schema evaluator and its duplicated test surface.

`github.com/cli/go-gh/v2/pkg/api` was evaluated for REST transport but rejected.
Its high-level decoder does not provide the required pre-decode response bound,
automatic retries, or endpoint pagination; its lower-level API would retain
those custom layers while adding configuration surface. The standard-library
transport keeps explicit bounds, retries, typed errors, cancellation, and
GitHub.com/GHE.com/GHES host mapping without subprocess execution.

`github.com/google/go-github/v89` `v89.0.0` was then evaluated on the reduced
repository after the PR-security and source-scan-controller simplifications.
The candidate and retained snapshots ran the same 323-line parity suite and the
complete repository test corpus. The retained implementation measured 280
production lines plus 734 directly associated test lines (1,014 total), while
the parity-oriented candidate measured 318 plus the same 734 tests (1,052
total), a 38-line increase. Aggregate cyclomatic complexity increased from 72
to 80, maximum complexity remained 12, and the candidate could not preserve the
retained 64 KiB error-body materialization bound without another transport
layer. The candidate was rejected and removed. The final tree keeps only 154
lines of focused production-contract regressions; the complete responsibility
inventory, reduced-main snapshot SHAs, workflow runs, measurements, and parity
matrix are recorded in [the GitHub REST client evaluation](github-client-evaluation.md).

## Inventory model

Repository enumeration is checked against the App installation's authoritative
selection and accessible count. Selection is limited to archived/disabled/fork
class exclusions and explicit repository include/exclude lists.

Per-repository inventory covers Actions policy, dependency graph, Dependabot,
effective rulesets and branch protection, pull-request and status-check
requirements, force-push/deletion restrictions, and `SECURITY.md`. There are no
inventory fields for CodeQL, code-scanning alerts, secret scanning, push
protection, or GitHub Security Configurations.

## Determinism and failure behavior

Configuration version 5 is the only governance contract. Repository, error,
policy, manifest, and summary arrays are sorted by stable identity.
`audit.json` is the canonical governance result; `inventory.json` is observation
evidence; and `report.md` is its bounded operator rendering.

Source-scan evidence has a separate schema version and exit classification.
Unresolved commits, inaccessible repositories, incomplete checkout content,
missing status files, identity mismatches, malformed evidence, scanner
findings, and scanner runtime errors remain distinguishable without changing a
governance observation or policy result.

A forbidden or failed governance endpoint remains incomplete evidence. A policy
over that observation becomes `unknown` or `unsupported`, and incomplete
coverage takes precedence over ordinary governance findings.

## Platform boundary

The CLI supports GitHub.com, GHE.com, and GitHub Enterprise Server through
`GH_HOST`. The supplied cross-repository Actions workflow is pinned for
GitHub.com. GHES operators must mirror the trusted source and verify their
server and runners support each pinned action.
