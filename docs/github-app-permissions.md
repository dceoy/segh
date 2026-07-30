# GitHub App permissions

Install a read-only GitHub App on only the organization and repositories in
scope.

| Permission | Access | Purpose |
|---|---:|---|
| Metadata | Read | Repository enumeration and classification |
| Contents | Read | Default branch and `SECURITY.md` evidence |
| Actions | Read | Actions enablement, token defaults, and pin policy |
| Administration | Read | Rulesets and branch protection |
| Organization custom properties | Read | Organization-level repository selection metadata |
| Organization administration | Read | Installation scope and Code Security Configuration associations |

Some plans and GHES versions combine or omit these permissions. The inventory
records affected observations as `unknown` or `unsupported`.

The audit workflow passes the App ID and private key only to the pinned
`actions/create-github-app-token` step and explicitly limits the installation
token to the read permissions above. Organization-wide inventory necessarily
grants the token access to every repository in the App installation. The
workflow passes the short-lived result through `GH_TOKEN` and the action's
non-secret installation ID through `SEGH_GITHUB_INSTALLATION_ID`; `segh` never
accepts an App private key or publication credential.

**Install the App on all repositories, not a selected subset.** `owner:` on
`actions/create-github-app-token` expands to every repository *in the
installation*, not every repository in the organization; a selected-repository
installation would silently limit the audit to that subset. `segh audit`
finds the action-provided installation ID in
`GET /orgs/{org}/installations`, whose documented response includes
`repository_selection`, and fails closed (`Complete: false`, exit code 4) when
it is not `all`. It separately cross-checks
`GET /installation/repositories` `total_count` against organization
enumeration. Organization Administration is requested only at read level for
this metadata lookup.

Custom-property values come only from the paginated organization endpoint.
Code-security governance comes only from the approved configuration and its
repository association statuses. Consequently, the inventory App does not need
Security events, Dependabot alerts, or repository custom-properties access.

SARIF publication uses a protected per-target-repository `workflow_run`
follow-up's narrowly scoped `GITHUB_TOKEN` with `security-events: write` and the
pinned CodeQL upload action. Before downloading artifacts, the follow-up
requires the triggering workflow ID to match the target repository's
`SEGH_PR_SECURITY_WORKFLOW_ID` variable. It then validates the analyzed commit,
checks it out without credentials to preserve SARIF fingerprints, and never
executes pull-request code. Do not add publication permissions to the scanner
workflow or inventory App.

Never grant contents write, workflows write, repository Administration write,
or organization Administration write to the inventory App.
