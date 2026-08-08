# Credential boundary

`segh` separates organization discovery and target scanning from dashboard issue writes. No job receives both the organization scan App credential and issue-write permission.

## Organization scan App

Install one GitHub App on the organization repositories that `segh` should scan. The workflow consumes these secrets only in planning and per-target token-minting steps:

- `SEGH_ORG_SCAN_APP_ID`
- `SEGH_ORG_SCAN_APP_PRIVATE_KEY`

The planning token requests only Metadata read and Contents read. It enumerates the App installation repositories and resolves each selected default branch to an immutable commit SHA.

Each matrix target receives a separate repository-scoped token with the measured read-only permissions required by checkout and OpenSSF Scorecard:

| Permission | Access |
| --- | --- |
| Metadata | Read |
| Contents | Read |
| Checks | Read |
| Issues | Read |
| Pull requests | Read |

The target token is passed only to the target checkout and Scorecard. Checkout disables credential persistence, Git LFS, and submodules.

## Dashboard publisher

Dashboard publication uses only the private caller repository's built-in `GITHUB_TOKEN`:

| Permission | Access | Purpose |
| --- | --- | --- |
| Actions | Read | Download the current run's plan and summary artifacts |
| Contents | Read | Check out the reviewed publisher implementation |
| Issues | Write | Create/update managed dashboard issues |

The publisher receives no configured secrets, organization App credential, or target token. It publishes only to `${{ github.repository }}` and requires the caller repository to be private. Managed dashboard label definitions are an operational prerequisite in that private repository and are not provisioned at runtime.

## Caller contract

Reusable-workflow callers must grant the maximum permission set required by the called jobs: `actions: read`, `contents: read`, `checks: read`, `issues: write`, and `pull-requests: read`. The reusable workflow narrows each job internally.

Run production scans only from a private control repository. Do not place private repository identities, paths, source excerpts, scanner logs, finding details, or secret values in a public repository's issues, summaries, or artifacts.
