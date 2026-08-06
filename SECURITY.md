# Security Policy

## Supported version

Only the current `main` branch is supported. Consume the reusable workflow at a reviewed immutable revision. Actions and scanner dependencies must remain commit- or checksum-pinned.

## Reporting a vulnerability

Use GitHub private vulnerability reporting for this repository. Do not include credentials, private repository identities, source paths, scanner artifacts, or undisclosed findings in a public issue.

## Credential boundaries

Organization scans must run from a private execution or control repository.

Configure the organization scan GitHub App through these Actions secrets:

- `SEGH_ORG_SCAN_APP_ID`
- `SEGH_ORG_SCAN_APP_PRIVATE_KEY`

The planning job receives a short-lived installation token with only Metadata and Contents read access. Each matrix scan job mints another short-lived token scoped to exactly one target repository with Metadata, Contents, Checks, Issues, and Pull requests read access.

Target tokens have no write permission. Tokens are not job outputs, are not persisted by checkout, and are exposed only through phase-specific step-local environment variables. Scanner jobs cannot receive an issue-write credential.

A future dashboard publisher from #74 must prefer the private control repository's built-in `GITHUB_TOKEN` with job-level `issues: write`. It must not receive the organization App identity, planning token, or per-target scan token. A separate publisher App is permitted only when the local token is insufficient and must be installed only on the private control repository.

See [CREDENTIALS.md](CREDENTIALS.md) for the full trust-boundary and migration contract.

## Scorecard limitations

The retained private-repository Scorecard profile requests:

- Metadata: read;
- Contents: read;
- Checks: read;
- Issues: read;
- Pull requests: read.

`Actions` and `Administration` are not granted without measured evidence that a retained check needs them. As a result, administrator-only classic branch-protection fields and the experimental Webhooks check are unavailable. The workflow records these limitations in `scorecard-permissions.json`; unavailable evidence must not be treated as proof of complete coverage.

Repeat a private App-backed validation whenever the pinned Scorecard version, enabled checks, or permission profile changes.

## Untrusted target handling

The workflow treats every target repository as untrusted input. It:

- resolves an immutable default-branch commit before scanning;
- disables checkout credential persistence, Git LFS hydration, and submodules;
- removes tracked symlinks;
- rejects gitlinks, unmaterialized LFS pointers, unreadable tracked regular files, and incomplete checkouts;
- installs scanners only from the trusted reusable-workflow revision;
- ignores target-owned scanner configuration where supported;
- never executes target scripts, actions, hooks, package managers, installers, builds, tests, Terraform providers, or generated commands;
- uploads only the bounded `results` directory.

Authentication headers and secret values must remain masked. Do not add environment dumps, shell tracing, token-bearing command output, or arbitrary workspace uploads.

## Public/private safety boundary

`dceoy/segh` is public. Production scans and raw evidence must remain in a private execution context whenever any selected target is private or internal.

A future dashboard publisher must fail closed rather than publish private target names, paths, source excerpts, logs, or findings to a public issue repository. The public source repository must not be used as a dashboard target for private scan results.

## Deployment validation

Repository-contained pull-request CI validates workflow structure and controlled scanner fixtures but does not possess the external organization App secrets.

Before deploying a candidate revision, invoke it from a private control repository pinned to the exact commit and confirm:

- complete public and private repository planning;
- one repository-scoped token per target;
- immutable private checkout without persisted credentials;
- one private OpenSSF Scorecard scan with the documented permissions;
- scanner execution without write access;
- private artifact retention and token redaction in representative failures;
- fail-closed rejection from a public execution or dashboard context.

Publish only sanitized run references, target classifications, expected conclusions, and bounded file-presence confirmation.
