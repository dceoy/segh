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

## Intentional retained boundaries

Two infrastructure-specific components are intentional architecture rather than
unfinished migration work:

| Boundary | Minimal retained contract | Deliberately outside the boundary |
| --- | --- | --- |
| Bounded GitHub REST client | Read-only `GET`; fixed GitHub.com endpoint; response and error-body bounds; bounded retries and backoff; primary and secondary rate-limit handling; cancellable waits and request deadlines; redirect rejection; token redaction; bounded diagnostics; the small error classifications used by current callers | General repository abstractions, generated service layers, GraphQL, credential discovery, persistent caches, telemetry, background processing, and SDK compatibility adapters |
| Manifest-aware source-scan reconciler | Validate the immutable manifest; discover `status.json`; match repository ID, full name, default branch, and commit SHA exactly; reject missing, duplicate, malformed, unexpected, or mismatched evidence; produce deterministic counts and render at most 50 error entries; preserve findings, incomplete coverage, and runtime errors as distinct outcomes | Repository checkout, scanner execution, repository-level classification, artifact publication, generic aggregation frameworks, and upstream ownership of organization identity reconciliation |

These boundaries may remain while their callers, data fields, comments, tests,
and surrounding compatibility surface continue to be deleted or simplified.
Neither boundary is a reason to preserve unused interfaces or broaden `segh`
into a framework.

Reconsidering either boundary requires both a material scope change and a new
measured prototype. The prototype must demonstrate a material net reduction in
production code, directly associated tests, dependencies, and operational
complexity while preserving every current security and evidence guarantee. A
replacement is not adopted through a speculative adapter, feature flag, dual
implementation, or unmeasured SDK substitution.

## Source-scan responsibility boundary

| Responsibility | Owner |
| --- | --- |
| Configuration validation, inventory collection, repository selection | `segh audit` governance path |
| Default-branch SHA resolution, deterministic target ordering, matrix bound, `scan-manifest.json` | `segh audit` organization controller |
| Target token, checkout, preflight, scanners, repository classification, `status.json` | pinned `gha-for-devops` workflow |
| Artifact discovery, planned-identity matching, missing/duplicate/malformed evidence, aggregate counts and 50-entry summary | `segh audit` organization reconciliation mode |

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
match exactly and fails closed on missing, duplicate, malformed, unexpected,
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

GitHub REST access is GitHub.com-only and uses the Go standard library. The API
base is the direct constant `https://api.github.com`; no host-selection or URL
rewriting layer exists. The client retains explicit response and error-body
bounds, bounded retry and backoff policy, primary and secondary rate-limit
handling, cancellable waits, request deadlines, redirect rejection, token
redaction, and bounded diagnostics. Endpoint pagination, deterministic ordering,
and availability classification remain caller-owned.

The evidence `github_host` field remains constrained to the constant
`github.com` so inventory and source-scan manifests continue to reject stale or
foreign-platform evidence without retaining generalized host parsing.

## Inventory model

Repository enumeration is checked against the App installation's authoritative
selection and accessible count. Selection is limited to archived/disabled/fork
class exclusions and explicit repository include/exclude lists.

Per-repository inventory covers Actions policy, dependency graph, Dependabot,
effective rulesets, pull-request and status-check/workflow requirements,
force-push/deletion restrictions, and `SECURITY.md`. There are no inventory
fields for CodeQL, code-scanning alerts, secret scanning, push protection, or
GitHub Security Configurations.

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

GitHub.com is the sole runtime platform. The REST endpoint is fixed to
`https://api.github.com`; no runtime platform-selection, hostname parsing, or
API-base rewriting layer is maintained.
