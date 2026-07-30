# GitHub App permissions

The organization audit uses a read-only GitHub App installed on every
repository in the organization.

| Permission | Access | Use |
|---|---|---|
| Actions | Read | Actions enablement and policy |
| Administration | Read | Rulesets, branch protection, Dependabot enablement |
| Contents | Read | Repository metadata, dependency graph export, `SECURITY.md` |
| Metadata | Read | Repository enumeration and classification |
| Organization administration | Read | Authoritative App installation scope |
| Organization custom properties | Read | Organization repository selection metadata |

The workflow requests these permissions explicitly when minting its short-lived
installation token. It does not request Security events or any permission used
to read or manage CodeQL, code-scanning alerts, secret scanning, push
protection, or Security Configurations.

The dependency graph observation uses the repository SBOM export endpoint,
which requires Contents read. Dependabot alert and security-update enablement
use repository settings endpoints, which require Administration read. The audit
does not enumerate Dependabot alert findings, so a Vulnerability alerts
permission is not required by this implementation.

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

The App private key is scoped to the token-minting step. Only the short-lived
token and non-secret installation ID reach `segh`. Configuration and artifacts
never contain the key or token, and the CLI does not cache either credential.
