# Architecture

## Boundary

`segh` owns organization-specific governance:

- repository selection from visibility, topics, explicit lists, and custom
  properties;
- coverage and drift assessment for Security Configurations, Actions policy,
  rulesets, and repository protections;
- explicit `available`, `unsupported`, and `unknown` capability states;
- deterministic policy evaluation and reports;
- owned, justified, repository-scoped suppressions with optional expiry.

GitHub-native tooling owns generic security infrastructure:

```text
Organization ruleset / central required workflow
  ├─ pinned scanner tools and actions
  ├─ github/codeql-action/upload-sarif (one category per scanner)
  └─ retained raw SARIF artifacts

Code Scanning merge protection
  └─ required analyses and severity thresholds

Security Configurations and organization policy
  └─ CodeQL, secret scanning, push protection, dependency and Actions controls

segh
  └─ native-control inventory → policy evaluation → compliance report
```

The Go CLI contains no scanner process runner, clone manager, SARIF parser or
publisher, fingerprint gate, GitHub App signer, custom HTTP transport, batcher,
or workflow engine.

## API and authentication

Inventory normalization remains in Go because it combines several
capability-sensitive GitHub endpoints into stable observations. Requests are
delegated to `gh api`. Repository enumeration uses
`gh api --paginate --slurp`; every request uses `--hostname` derived from
`github.web_url`. The GitHub CLI owns token discovery, REST transport, and
pagination. `segh` retries transient transport failures, HTTP 429/5xx
responses, and explicit rate-limit responses with bounded exponential backoff.

`GH_TOKEN` is required. GitHub Actions generates it from a read-only App using
`actions/create-github-app-token`; local use requires an externally supplied
token. No private key or long-lived installation token is parsed or cached by
`segh`.

## Determinism and capability states

Repository and policy arrays are sorted by stable identifiers. JSON is the
canonical automation format, optional JSONL contains one record per line, and
Markdown is an operator summary. Incompatible schema versions are rejected.

Unavailable endpoints never silently pass policy:

- `available` means the control was observed;
- `unsupported` means the endpoint or feature is absent;
- `unknown` means permission, ambiguity, or another failure prevented a
  reliable observation.

## GitHub Enterprise Server

Inventory supports GHES through the configured web hostname and records missing
features as `unsupported` or `unknown`. The direct scanner workflow remains
usable where its pinned Actions and Code Scanning are supported. On GHES
versions without Code Scanning or compatible action support, raw SARIF remains
an Actions artifact, but GitHub-native publication and merge enforcement are
reduced or unavailable. `segh` does not restore a custom upload fallback.
