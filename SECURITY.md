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

The authoritative PR boundary for `dceoy/segh` is the base-sourced `Trusted workflow-only boundary` plus the dedicated-App check `Trusted workflow-only boundary attestation` required by the default-branch repository ruleset.

The trusted workflow compares the candidate's tracked path/type/mode shape with the protected base, protects its trusted workflow/validator/preflight sources, and evaluates the candidate with the base validator. Candidate-owned code is not executed.

The built-in workflow token is read-only. The attestation is published by a separate App installed only on `dceoy/segh`; its runtime token is limited to Metadata read and Checks write. App credentials exist only in the `trusted-boundary` environment restricted to `main`.

A same-named check from another integration is not an accepted trust signal. Changing the trusted workflow, validator, preflight script, App/environment configuration, or ruleset binding is an administrator break-glass operation.

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

For the merge boundary, verify representative positive and negative PRs show that the attestation is produced by the dedicated App on the candidate head SHA, only that App satisfies the required check, trusted policy-source changes are blocked, tracked path additions/removals are blocked, and disallowed product surfaces are rejected.

Publish only sanitized run references, expected conclusions, and bounded file-presence confirmation.
