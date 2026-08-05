# Security Policy

## Supported version

Only the current `main` branch is supported. The workflow and every action or scanner dependency must be consumed at a reviewed immutable revision.

## Reporting a vulnerability

Report vulnerabilities through GitHub private vulnerability reporting for this repository. Do not include credentials, private scanner artifacts, repository source, or undisclosed findings in a public issue.

## Operational requirements

Organization scans must run from a private control repository. Store `SEGH_READ_APP_PRIVATE_KEY` only as an Actions secret and grant the GitHub App no more than repository metadata and contents read access.

The workflow treats selected repositories as untrusted input. It resolves immutable commits, uses repository-scoped read-only tokens, disables credential persistence, Git LFS, and submodules, removes tracked symlinks, rejects incomplete content, ignores target-owned scanner configuration where supported, and never executes target repository code.

Raw scanner artifacts can expose source paths, dependency details, secrets, and security findings. Keep them private, restrict Actions access, use the shortest practical retention period, and delete affected artifacts after credential rotation or incident response.
