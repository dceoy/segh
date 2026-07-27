# GitHub App permissions

Install a GitHub App on only the organizations and repositories in scope. Use
short-lived installation tokens; do not store an installation token as a
long-lived Actions secret.

Recommended read permissions for inventory and scanning:

| Permission | Access | Purpose |
|---|---:|---|
| Metadata | Read | Repository enumeration and classification |
| Contents | Read | Default branch, workflow files, `SECURITY.md`, shallow clone |
| Actions | Read | Actions enablement, token defaults, fork approval, pin policy |
| Administration | Read | Rulesets, branch protection, custom properties |
| Security events | Read | Code scanning/default setup and security status |
| Secret scanning alerts | Read | Capability and enablement evidence where required |
| Dependabot alerts | Read | Dependabot feature evidence |

Some GitHub plans and GHES versions combine or omit these permissions. `segh`
will report affected observations as `unknown` or `unsupported`.

SARIF publication additionally needs **Security events: write** for target
repositories. Use a separate publication App; do not add that permission to the
read App. The supplied workflows use `SEGH_READ_APP_*` in inventory/scanner jobs
and `SEGH_PUBLISH_APP_*` only in publication jobs. The latter downloads SARIF
but does not check out or execute target repository code.

The App private key is supplied through `SEGH_GITHUB_APP_PRIVATE_KEY` only to
the step generating installation tokens. A private-key file, when used, must
have no group/other permission bits. Existing tokens require both
`auth.allow_existing_token: true` and the configured token environment
variable; this fallback is intended only for development.

Never give the App contents write, workflows write, administration write, or
organization owner privileges for inventory/scanning. Configure separate
installations if the publication scope must be narrower.
