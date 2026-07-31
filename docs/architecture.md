# Architecture

`segh` has two independent read-only paths.

```text
Organization audit
  ├─ GitHub REST inventory
  ├─ deterministic policy evaluation
  └─ inventory.json + audit.json + report.md

Organization ruleset required workflow
  ├─ trusted segh scanner configuration
  ├─ untrusted pull-request checkout
  ├─ zizmor + actionlint/ShellCheck + Checkov + two Trivy scans
  └─ ordinary required check + retained JSON/text/log artifacts
```

## Trust boundaries

The central ruleset workflow is the policy boundary. Scanner versions are
checksum-verified through Aqua, action dependencies are pinned to full commit
SHAs, and both workflow wrappers invoke the same composite action from the
trusted `segh` checkout. The pull-request checkout is only scanner input. It
cannot supply the composite action, scanner script, actionlint, ShellCheck,
Checkov, Trivy, or zizmor configuration, exclusions, or wrapper scripts.

The scanner job has only `contents: read`. It does not receive an App private
key, installation token, publication credential, or write permission. Fork and
Dependabot pull requests use the same unprivileged path.

The organization audit receives a short-lived, read-only GitHub App token. It
uses that token directly over HTTPS, bounds response sizes, retries transient
failures, and treats unavailable evidence as `unknown` or `unsupported`, never
as a policy pass.

## Dependency evaluations

Configuration is decoded first into a generic YAML representation and validated
against the embedded, published
`schema/segh-config-v4.schema.json`. Typed decoding and duration conversion run
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
`repository_selection` and accessible repository count. Organization custom
properties are collected once and joined by repository ID with the full name
validated independently.

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

Configuration version 4 is the only accepted contract. Repository, error, and
policy result arrays are sorted by stable identifiers. `audit.json` is the
canonical compliance result; `inventory.json` is observation evidence; and
`report.md` is the operator rendering.

A failed or forbidden endpoint remains incomplete evidence. A configured policy
over that observation becomes `unknown` or `unsupported`, and the command exits
with incomplete coverage before considering ordinary policy failures.

## Platform boundary

The CLI supports GitHub.com, GHE.com, and GitHub Enterprise Server through
`GH_HOST`.
The supplied cross-repository Actions workflows are pinned for GitHub.com.
GHES operators must mirror the trusted source and validate that their server and
runner support each pinned action.
