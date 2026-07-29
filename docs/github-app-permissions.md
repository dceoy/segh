# GitHub App permissions

Install a read-only GitHub App on only the organization and repositories in
scope.

| Permission | Access | Purpose |
|---|---:|---|
| Metadata | Read | Repository enumeration and classification |
| Contents | Read | Default branch and `SECURITY.md` evidence |
| Actions | Read | Actions enablement, token defaults, and pin policy |
| Administration | Read | Rulesets, branch protection, and security settings |
| Repository custom properties | Read | Repository selection and classification |
| Security events | Read | CodeQL/default-setup state |
| Dependabot alerts | Read | Dependabot feature evidence |

Some plans and GHES versions combine or omit these permissions. The inventory
records affected observations as `unknown` or `unsupported`.

The audit workflow passes the App ID and private key only to the pinned
`actions/create-github-app-token` step and explicitly limits the installation
token to the read permissions above. Organization-wide inventory necessarily
grants the token access to every repository in the App installation. The
workflow passes the short-lived result to `segh` through `GH_TOKEN`; `segh`
never accepts an App private key, installation ID, or publication credential.

SARIF publication uses the workflow's narrowly scoped `GITHUB_TOKEN` with
`security-events: write` and the pinned CodeQL upload action. Do not add
publication permissions to the inventory App.

Never grant contents write, workflows write, administration write, or
organization-owner privileges to the inventory App.
