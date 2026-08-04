# Architecture

`segh` has two read-only paths with separate evidence contracts.

```text
Organization audit
  ├─ GitHub REST inventory
  ├─ deterministic policy evaluation
  └─ inventory.json + audit.json + report.md

Periodic organization source scan
  ├─ selected inventory repositories
  ├─ immutable default-branch commit manifest
  ├─ bounded repository scanner matrix
  ├─ pinned scanner from dceoy/gha-for-devops
  └─ scan-manifest.json + scan-summary.json + repository evidence
```

## Trust boundaries

The organization audit receives a short-lived, read-only GitHub App token. It
uses that token directly over HTTPS, bounds response sizes, retries transient
failures, and treats unavailable evidence as `unknown` or `unsupported`, never
as a policy pass.

The periodic scan resolves each selected repository's default branch through
the API before checkout and records the returned full commit SHA in a separate
manifest. Each matrix job mints a new token limited to that one repository,
checks out only the recorded SHA with credentials, LFS, and submodules disabled,
and treats the checkout only as static input. Tracked symlinks are removed;
submodule gitlinks and Git LFS pointers make coverage incomplete. Scanner
configuration and binaries come only from a full, reviewed
`dceoy/gha-for-devops` commit pinned in the workflow.

## Dependency evaluations

Configuration is decoded first into a generic YAML representation and validated
against the embedded, published
`schema/segh-config-v5.schema.json`. Typed decoding and duration conversion run
only after structural validation. The Go layer retains only repository-glob
validation because it must use the same `path.Match` semantics as policy
evaluation.

`github.com/santhosh-tekuri/jsonschema/v6` was evaluated as a general draft
2020-12 validator. It supports the required draft and embedded resources, but a
general validator dependency plus YAML error adaptation did not reduce the
maintained surface for this fixed, single-schema CLI. The runtime therefore uses
a focused evaluator for only the keywords present in the embedded schema. This
keeps the JSON Schema authoritative without runtime schema downloads or a
second handwritten set of enums, uniqueness checks, required-policy checks, or
duration patterns.

`github.com/cli/go-gh/v2/pkg/api` was evaluated for REST transport. Its
high-level response decoding does not provide segh's required pre-decode size
bound, automatic retries, or endpoint pagination. Using its lower-level request
method would retain those custom layers while adding the module's configuration
surface, so it did not produce a material net simplification. The adopted
standard-library transport removes all `gh api` subprocess execution, CLI
stderr parsing, credential-environment translation, and fake-executable tests
while retaining explicit response bounds, retry delays, typed status errors,
context cancellation, and the narrow `API` inventory seam.

## Inventory model

Repository enumeration is checked against the App installation's authoritative
`repository_selection` and accessible repository count. Selection is limited to
class exclusions (archived, disabled, forks) and explicit repository
include/exclude lists; there is no visibility, topic, or organization
custom-property selector.

Per-repository inventory covers:

- Actions enablement, allowed actions, default token permission, fork approval,
  and SHA-pinning enforcement;
- dependency graph, Dependabot alerts, and Dependabot security updates;
- effective rulesets and classic branch protection;
- required pull requests and status checks;
- force-push and deletion restrictions; and
- `SECURITY.md`.

There are no inventory fields or API paths for CodeQL, code-scanning alerts,
secret scanning, push protection, or GitHub Security Configurations.

## Determinism and failure behavior

Configuration version 5 is the only accepted governance contract. Repository,
error, policy, source-scan manifest, and source-scan summary arrays are sorted
by stable identifiers. `audit.json` is the canonical compliance result;
`inventory.json` is observation evidence; and `report.md` is the operator
rendering.

Source-scan evidence has its own schema version. Missing status files, identity
mismatches, malformed evidence, inaccessible repositories, and unresolved
commits fail closed without changing any governance observation or policy
result.

A failed or forbidden endpoint remains incomplete evidence. A configured policy
over that observation becomes `unknown` or `unsupported`, and the command exits
with incomplete coverage before considering ordinary policy failures.

## Platform boundary

The CLI supports GitHub.com, GHE.com, and GitHub Enterprise Server through
`GH_HOST`.
The supplied cross-repository Actions workflows are pinned for GitHub.com.
GHES operators must mirror the trusted source and validate that their server and
runner support each pinned action.
