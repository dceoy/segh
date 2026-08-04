# GitHub App permissions

The organization audit and periodic source scan use a read-only GitHub App
installed on every repository in the organization.

| Permission                   | Access | Use                                                         |
| ----------------------------- | ------ | ----------------------------------------------------------- |
| Actions                       | Read   | Actions enablement and policy                               |
| Administration                | Read   | Rulesets, branch protection, Dependabot enablement          |
| Contents                      | Read   | Repository metadata, dependency graph export, `SECURITY.md`, dependency lock-file detection |
| Metadata                      | Read   | Repository enumeration and classification                   |
| Organization administration   | Read   | Authoritative App installation scope                        |

The workflow requests these permissions explicitly when minting its short-lived
installation token. It does not request Security events or any permission used
to read or manage CodeQL, code-scanning alerts, secret scanning, push
protection, or Security Configurations.

The dependency graph observation uses the repository SBOM export endpoint,
which requires Contents read. Dependabot alert and security-update enablement
use repository settings endpoints, which require Administration read. The audit
does not enumerate Dependabot alert findings, so a Vulnerability alerts
permission is not required by this implementation. When
`policies.dependencies.lock_files` is enabled, lock-file detection uses the
same Contents read permission to fetch a repository's default-branch tree and
matched manifest content; it makes no additional permission request.

The inventory and commit-resolution job receives the organization-wide token.
Each repository scan job invokes `dceoy/gha-for-devops`'s pinned
`repository-security-scan.yml` reusable workflow, which separately mints a
short-lived token restricted to the single matrix repository with only
Contents: Read and Metadata: Read and checks out the recorded commit with
`persist-credentials: false` itself; `segh`'s own workflow only forwards the
App's Client ID (`SEGH_READ_APP_CLIENT_ID`) and private key
(`SEGH_READ_APP_PRIVATE_KEY`) as `TARGET_APP_CLIENT_ID`/`TARGET_APP_PRIVATE_KEY`
secrets to that call. Scanner steps never receive the App private key: GitHub
masks it as a secret, and only the called workflow's token-minting step
consumes it.

## Installation scope

Install the App on **all repositories**, not a selected subset.
`actions/create-github-app-token` can only expand to repositories already in the
installation. `segh` finds the action-provided installation ID through the
organization installations endpoint and requires `repository_selection` to be
`all`. It also compares the installation's accessible count with organization
enumeration.

A mismatch makes inventory incomplete instead of silently omitting
repositories.

## Credential handling

The App private key is scoped to token-minting steps. Only short-lived tokens
and the non-secret installation ID reach `segh` or checkout. Configuration and
artifacts never contain the key or token, and the CLI does not cache either
credential.
