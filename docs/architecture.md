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
delegated to `gh api`; every request uses `--hostname` derived from `GH_HOST`,
defaulting to `github.com`. Repository enumeration decodes one page at a time.
Organization custom-property values and Code Security Configuration
associations use GitHub CLI pagination and are joined to enumeration by
repository ID with the full name independently validated. The GitHub CLI owns
token discovery and REST transport; `segh` retries transient transport
failures, HTTP 429/5xx responses, and explicit rate-limit responses with
bounded exponential backoff.

Custom properties are collected once from
`GET /orgs/{org}/properties/values`; no per-repository fallback exists. The
configured Code Security Configuration is resolved once, and
`GET /orgs/{org}/code-security/configurations/{id}/repositories` is the sole
code-security governance observation. Missing, duplicate, malformed, or
inconsistent organization data stays unknown or incomplete rather than
silently changing repository selection or policy.

`GH_TOKEN` and its matching `SEGH_GITHUB_INSTALLATION_ID` are required for
inventory. GitHub Actions generates both from a read-only App using
`actions/create-github-app-token`; local use requires an externally supplied
token and installation ID. The ID lets `segh` verify authoritative
organization installation metadata without accepting an App private key. No
private key or long-lived installation token is parsed or cached by `segh`.

## Determinism and capability states

Repository, error, and policy arrays are sorted by stable identifiers.
`audit.json` is the canonical automation result, while `inventory.json` is raw
observation evidence and `report.md` is the operator rendering. Incompatible
schema versions are rejected.

Unavailable endpoints never silently pass policy:

- `available` means the control was observed;
- `unsupported` means the endpoint or feature is absent;
- `unknown` means permission, ambiguity, or another failure prevented a
  reliable observation.

## End-to-end command

`segh audit` is the only operational command. It strictly loads configuration
before authentication or API access, then collects inventory, evaluates policy,
validates the in-memory relationship between both results, and writes exactly
`inventory.json`, `audit.json`, and `report.md`. `--validate-only` stops after
offline configuration validation. The removed staged commands and artifact
read-back paths have no compatibility wrappers.

## GitHub Enterprise Server

Inventory supports GHES through `GH_HOST` and records the normalized effective
hostname in evidence. Missing features remain `unsupported` or `unknown`. The
direct scanner workflow remains
usable where its pinned Actions and Code Scanning are supported. On GHES
versions without Code Scanning or compatible action support, raw SARIF remains
an Actions artifact, but GitHub-native publication and merge enforcement are
reduced or unavailable. `segh` does not restore a custom upload fallback.

The supplied cross-repository organization-audit workflow is scoped to a
GitHub.com-hosted control repository because its trusted source is the public
`dceoy/segh` repository. It fails explicitly on GHES instead of reusing a GHES
token across hosts. GHES Actions deployments must adapt the workflow to a
protected same-host source mirror or an equivalently verified release artifact;
this does not change the CLI's GHES audit support.
