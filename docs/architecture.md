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
  ├─ read-only pinned scanner tools and actions
  └─ retained raw SARIF artifacts

Protected per-target workflow_run follow-up
  ├─ validates the central workflow ID and artifact metadata
  └─ github/codeql-action/upload-sarif (one category per scanner)

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

The central ruleset workflow is disabled in its own source repository because
an ordinary source-repository pull request controls that run's workflow
revision. Every target repository installs the publisher on its protected
default branch and pins the accepted central workflow identity in a repository
variable. This keeps the write-capable follow-up in the repository where the
ruleset scan runs without trusting a same-named workflow supplied by a pull
request.

## API and authentication

Inventory normalization remains in Go because it combines several
capability-sensitive GitHub endpoints into stable observations. Requests are
delegated to `gh api`; every request uses `--hostname` derived from
`github.web_url`. Repository enumeration decodes one page at a time, each
independently bounded, rather than accumulating every page behind a single
response cap. The GitHub CLI owns token discovery and REST transport; `segh`
drives pagination itself and retries transient transport failures, HTTP
429/5xx responses, and explicit rate-limit responses with bounded exponential
backoff.

`GH_TOKEN` is required. GitHub Actions generates it from a read-only App using
`actions/create-github-app-token`; local use requires an externally supplied
token. No private key or long-lived installation token is parsed or cached by
`segh`.

## Determinism and capability states

Repository and policy arrays are sorted by stable identifiers. JSON is the
canonical automation format, and the consolidated Markdown report is the
operator summary. Incompatible schema versions are rejected.

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
