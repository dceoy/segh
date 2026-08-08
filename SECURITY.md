# Security policy

## Trust model

The `segh` workflow implementation is trusted; scanned repositories are untrusted input. Production scans must run from a private control repository at a reviewed immutable `segh` commit.

The scanner checks out target source only as data. It does not execute target workflows, scripts, hooks, package managers, builds, tests, Terraform providers, submodules, or Git LFS objects.

## Credential isolation

Organization discovery and target scanning use short-lived GitHub App installation tokens with read-only permissions. Dashboard publication uses the caller repository's `GITHUB_TOKEN` with issue-write permission and never receives the scan App credential or a target token.

See [CREDENTIALS.md](CREDENTIALS.md) for the exact permission sets.

## Toolchain

Scanner binaries are installed with Aqua using required checksums. GitHub Actions are pinned to full commit SHAs. CI uses actionlint and zizmor for generic workflow validation and ShellCheck for shell code.

## Data handling

Raw scanner evidence can contain sensitive repository information and is retained only as private workflow artifacts in the control repository. Dashboard issues contain bounded normalized status/count information and must not include source excerpts, private paths, secret values, scanner logs, or stack traces.

The dashboard intentionally has no custom integrity ledger, transition journal, or stale/retired reconciliation database. The current successful workflow run is authoritative and overwrites the managed issue state for repositories it scans.

## Reporting vulnerabilities

Report security issues through GitHub's private vulnerability reporting mechanism when available. Do not disclose credentials, private repository data, or exploitable details in public issues.
