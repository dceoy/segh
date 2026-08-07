# Security Policy

## Supported version

Only the current `main` branch is supported. Consume the reusable workflow at a reviewed immutable revision. Actions and scanner dependencies must remain commit- or checksum-pinned.

## Reporting a vulnerability

Use GitHub private vulnerability reporting for this repository. Do not include credentials, private repository identities, source paths, scanner artifacts, or undisclosed findings in a public issue.

## Merge protection boundary

`dceoy/segh` remains under personal ownership. The authoritative pull-request boundary is therefore a base-sourced `pull_request_target` workflow plus a repository ruleset required check issued by a dedicated GitHub App.

`.github/workflows/trusted-boundary.yml` is loaded from the current `main` revision. It checks out trusted base and candidate revisions separately, rejects ordinary pull requests that change the trusted workflow, `scripts/preflight.sh`, or `scripts/validate-workflow-boundary.rb`, compares the complete tracked path/object-type/file-mode shape to the base revision, and evaluates the candidate with the base validator. It does not execute candidate-owned code.

The workflow's built-in `GITHUB_TOKEN` has only `contents: read`. A separate GitHub App installed only on `dceoy/segh` has Metadata read, Checks write, and Commit statuses write. The Commit statuses permission exists only so GitHub can offer that App as the repository ruleset's expected status-check source; the workflow-minted runtime token requests only Metadata read and Checks write. The App credentials are stored only in the `trusted-boundary` Actions environment, whose deployment branch policy must allow `main` and reject pull-request refs and feature branches.

After validation, the dedicated App publishes `Trusted workflow-only boundary attestation` on the pull-request head SHA. Bootstrap the required-check binding only after this App has emitted at least one representative attestation, then configure the default-branch repository ruleset to require that exact check with strict status-check behavior and bind the expected source to the dedicated App integration ID. A same-named check from GitHub Actions or another integration is not an accepted trust signal.

Changing the trusted workflow, validator, preflight script, App installation or permissions, `trusted-boundary` environment policy or secrets, or required-check ruleset is an administrator-only break-glass operation. Such changes are outside the ordinary pull-request trust boundary and must be treated as explicit security-sensitive maintenance.

See [CREDENTIALS.md](CREDENTIALS.md) for the exact App permissions, environment secrets, ruleset binding, and bootstrap procedure.

## Credential boundaries

Organization scans must run from a private execution or control repository.

Configure the organization scan GitHub App through these Actions secrets:

- `SEGH_ORG_SCAN_APP_ID`
- `SEGH_ORG_SCAN_APP_PRIVATE_KEY`

The planning job receives a short-lived installation token with only Metadata and Contents read access. Each matrix scan job mints another short-lived token scoped to exactly one target repository with Metadata, Contents, Checks, Issues, and Pull requests read access.

Target tokens have no write permission. Tokens are not job outputs, are not persisted by checkout, and are exposed only through phase-specific step-local environment variables. Scanner jobs cannot receive an issue-write credential or the trusted-boundary App credential.

The dashboard publisher uses the private control repository's built-in `GITHUB_TOKEN` with job-level `actions: read`, `contents: read`, and `issues: write`. It binds `SEGH_DASHBOARD_REPOSITORY` to `${{ github.repository }}` and receives no configured secrets, organization App identity, planning token, per-target scan token, or trusted-boundary credential. Cross-repository publication and a separate publisher App are not supported by this credential contract.

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

The dashboard publisher must fail closed rather than publish private target names, paths, source excerpts, logs, or findings to public issues. The dashboard target is fixed to the private caller repository, so the caller visibility guard validates the actual publication target. The public source repository must not be used as an execution or dashboard repository for private scan results.

The dedicated merge-boundary check contains only public pull-request policy state and a link to the public workflow run. It must never include scanner evidence or private control-repository data.

## Deployment validation

Repository-contained pull-request CI validates workflow structure and controlled scanner fixtures but does not possess the external organization App secrets or the trusted-boundary App credentials.

Before deploying a candidate scanner revision, invoke it from a private control repository pinned to the exact commit and confirm:

- complete public and private repository planning;
- one repository-scoped token per target;
- immutable private checkout without persisted credentials;
- one private OpenSSF Scorecard scan with the documented permissions;
- scanner execution without write access;
- private artifact retention and token redaction in representative failures;
- fail-closed rejection from a public execution or dashboard context.

Before considering the merge boundary fully deployed, also confirm on representative positive and negative pull requests that:

- `Trusted workflow-only boundary` is loaded from `main`;
- the dedicated App creates the attestation on the candidate head SHA before ruleset source binding is configured;
- the repository ruleset subsequently accepts only that App as the expected check source;
- a same-named GitHub Actions check does not satisfy the rule;
- a change to a trusted policy source is blocked;
- an added or removed tracked product path is blocked; and
- a disallowed product surface is blocked.

Publish only sanitized run references, target classifications, expected conclusions, and bounded file-presence confirmation.
