# Security Policy

## Supported version

Only the current `main` branch is supported. Consume reusable workflows at a reviewed immutable commit. Remote actions and scanner dependencies must remain commit- or checksum-pinned.

## Reporting a vulnerability

Use GitHub private vulnerability reporting. Do not disclose credentials, private repository identities, source paths, scanner artifacts, or undisclosed findings in a public issue.

## Trust model

`segh` treats target repositories as untrusted input and separates read-only scan credentials from write-capable control-plane credentials.

For every target, the workflow resolves an immutable commit, mints a token scoped to that repository, disables persisted checkout credentials, Git LFS, and submodules, removes tracked symlinks, rejects unsupported repository shapes, installs scanners only from the trusted `segh` revision, and never executes target scripts, actions, hooks, package managers, installers, builds, tests, or Terraform providers.

Scanner evidence may contain sensitive organization information and must remain in a private control repository. Dashboard bodies are bounded summaries; they must not include source excerpts, private paths, secrets, logs, or stack traces.

The exact token permissions and consumers are defined in [CREDENTIALS.md](CREDENTIALS.md).

## Merge protection

The authoritative PR boundary for `dceoy/segh` is the native GitHub Actions job check `Trusted workflow-only boundary`, produced by the base-sourced `pull_request_target` workflow. The default-branch repository ruleset should require that exact check.

The trusted workflow compares the candidate's tracked path/type/mode shape with the protected base, protects its trusted workflow/validator/preflight sources, and evaluates the candidate with the base validator. Candidate-owned code is not executed.

The workflow uses the built-in `GITHUB_TOKEN` with only Contents read access. It does not mint a dedicated token, publish a custom check, create a commit status, or access configured secrets. No dedicated merge-boundary App, private key, or Actions environment is required.

This simplified personal-ownership model does not provide a distinct App identity from other GitHub Actions checks. A repository writer capable of creating another GitHub Actions check with the same name is inside the supported trust root. Repository-owner administrative control is therefore part of the security boundary. Changing the trusted workflow, validator, preflight script, or ruleset binding remains an explicit administrator break-glass operation.

## Scorecard limitations

The target App grants Metadata, Contents, Checks, Issues, and Pull requests read access. Actions and Administration are intentionally absent. Administrator-only classic branch-protection fields and the experimental Webhooks check are therefore unavailable and are recorded as limitations rather than silently treated as passing evidence.

Revalidate a private target whenever the Scorecard version, selected checks, or App permission profile changes.

## Public/private boundary

The public `dceoy/segh` repository is not a production scan or dashboard target. Organization scans, selection snapshots, raw evidence, normalized summaries, and managed dashboard issues must run in a private control repository.

Authentication values must remain masked. Do not add environment dumps, shell tracing, token-bearing command output, arbitrary workspace uploads, or direct publication of raw scanner findings.

## Deployment validation

Pull-request CI validates repository-contained structure and controlled fixtures, but it cannot prove external App installation scope, private repository access, or private artifact visibility.

Before deploying a reviewed scanner revision from the intended private control repository, verify:

- complete intended repository selection and immutable commit planning;
- one read-only repository-scoped token per target;
- immutable private checkout without persisted credentials;
- Scorecard execution with the documented read-only permission set;
- private artifact retention and token redaction on representative failures;
- fail-closed behavior when production publication would target a public repository.

For the merge boundary, verify representative positive and negative PRs show that the native `Trusted workflow-only boundary` check is associated with the current PR revision, trusted policy-source changes are blocked, tracked path additions/removals are blocked, and disallowed product surfaces are rejected. Confirm the repository ruleset requires `Trusted workflow-only boundary` after the migration.

Publish only sanitized run references, expected conclusions, and bounded file-presence confirmation.
