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
  ├─ zizmor + three independent Trivy scans
  └─ ordinary required check + retained JSON/text/log artifacts
```

## Trust boundaries

The central ruleset workflow is the policy boundary. Scanner versions are
checksum-verified through Aqua, action dependencies are pinned to full commit
SHAs, and scanner arguments come from the trusted `segh` checkout. The
pull-request checkout is only scanner input. It cannot supply Trivy
configuration, ignore files, or zizmor configuration.

The scanner job has only `contents: read`. It does not receive an App private
key, installation token, publication credential, or write permission. Fork and
Dependabot pull requests use the same unprivileged path.

The organization audit receives a short-lived, read-only GitHub App token. It
uses GitHub CLI for authentication and REST transport, bounds response sizes,
retries transient failures, and treats unavailable evidence as `unknown` or
`unsupported`, never as a policy pass.

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

The CLI supports GitHub.com and GitHub Enterprise Server through `GH_HOST`.
The supplied cross-repository Actions workflows are pinned for GitHub.com.
GHES operators must mirror the trusted source and validate that their server and
runner support each pinned action.
