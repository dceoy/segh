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

| Responsibility | Owner |
| --- | --- |
| Configuration validation, inventory collection, repository selection | `segh audit` governance path |
| Default-branch SHA resolution, deterministic target ordering, matrix bound, `scan-manifest.json` | `segh audit` organization controller |
| Target token, checkout, preflight, scanners, repository classification, `status.json` | pinned `gha-for-devops` workflow |
| Artifact discovery, planned-identity matching, missing/duplicate/malformed evidence, aggregate counts and bounded summary | `segh audit` organization reconciliation mode |

## Trust boundaries

The organization audit receives a short-lived, read-only GitHub App token. It
validates configuration before API access, bounds response sizes, retries
transient failures, and treats unavailable evidence as `unknown` or
`unsupported`, never as a pass.

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
pull-request check publication are intentionally outside `segh`. Periodic
organization source scanning is the only source-scanning path maintained here.

## Dependencies and transport

Configuration is structurally validated against the embedded version 5 JSON
Schema before typed decoding and duration conversion. The maintained
`github.com/santhosh-tekuri/jsonschema/v6` validator compiles that schema
in-memory without runtime network or filesystem access. A strict date-time
format override preserves the typed configuration contract.

GitHub REST access uses the Go standard library with explicit response bounds,
retry and backoff policy, cancellable waits, token redaction, and
GitHub.com/GHE.com/GHES host mapping. Endpoint pagination, ordering, and
availability classification remain caller-owned.

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
