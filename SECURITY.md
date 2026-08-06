# Security Policy

## Supported version

Only the current `main` branch is supported. The reusable workflow must be consumed at a reviewed immutable revision, and every action and scanner dependency remains checksum- or commit-pinned.

## Reporting a vulnerability

Report vulnerabilities through GitHub private vulnerability reporting for this repository. Do not include credentials, private scanner artifacts, repository source, or undisclosed findings in a public issue.

## Operational requirements

Organization scans must run from a private control repository. Store `SEGH_READ_APP_PRIVATE_KEY` only as an Actions secret.

The GitHub App repository permission set is read-only Metadata, Contents, Issues, Pull requests, and Checks. This matches current OpenSSF Scorecard private-repository guidance and supports immutable checkout. `Actions` and `Administration` are not granted without observed private-run evidence that a required check needs them. Confirm the least-privilege set in a real private App-backed run before closing #78.

The App installation selection is authoritative. Disabled and archived repositories are excluded. Selected forks are included and identified as forks in immutable target metadata. Planning fails before matrix emission on malformed pagination or identity data, empty or oversized selections, missing default branches, unresolved commits, and invalid SHAs.

The workflow treats selected repositories as untrusted input. It uses repository-scoped tokens, disables credential persistence, LFS hydration, and submodules, removes tracked symlinks, rejects incomplete content, ignores target-owned scanner configuration where supported, and never executes target repository code.

OpenSSF Scorecard is informational, but inability to execute or produce valid non-empty JSON fails the repository job. zizmor, actionlint, ShellCheck, and the three independent Trivy classes retain native exit behavior. Later scanners and artifact upload use `always()` so diagnostic evidence remains available after findings and runtime errors.

Raw artifacts can expose source paths, dependency details, secrets, and security findings. Keep them private, restrict Actions access, use the shortest practical retention period, and delete affected artifacts after credential rotation or incident response.

## Private deployment validation

Repository-contained PR validation does not possess the GitHub App secrets. Before enabling a candidate revision or closing #78, invoke it from a private control repository pinned to the exact commit and confirm:

- installation repository enumeration and fork policy;
- repository-scoped token creation with the documented permission set;
- private OpenSSF Scorecard execution;
- immutable private checkout;
- private artifact retention and expected raw files;
- fail-closed rejection with a deliberately low `repository_limit`.

Publish only sanitized run URLs, target classifications, expected conclusions, and file-presence confirmation.
