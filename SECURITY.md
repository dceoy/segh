# Security Policy

## Supported version

Only the current `main` branch is supported. Consume reusable workflows at a reviewed immutable commit. Remote actions and scanner dependencies must remain commit- or checksum-pinned.

## Reporting a vulnerability

Use GitHub private vulnerability reporting. Do not disclose credentials, private repository identities, source paths, scanner artifacts, or undisclosed findings in a public issue.

## Trust model

`segh` treats target repositories as untrusted input and separates read-only scan credentials from write-capable control-plane credentials.

For every target, the workflow resolves an immutable commit, mints a token scoped to that repository, disables persisted checkout credentials, Git LFS, and submodules, removes tracked symlinks, rejects unsupported repository shapes, installs scanners only from the trusted `segh` revision, and never executes target scripts, actions, hooks, package managers, installers, builds, tests, or Terraform providers.

Scanner evidence may contain sensitive organization information and must remain in a private control repository. Dashboard bodies are bounded summaries; they must not include source excerpts, private paths, secrets, logs, or stack traces.

Repository contribution and merge protection are outside this threat model.

The exact token permissions and consumers are defined in [CREDENTIALS.md](CREDENTIALS.md).

## Scorecard limitations

The target App grants Metadata, Contents, Checks, Issues, and Pull requests read access. Actions and Administration are intentionally absent. Administrator-only classic branch-protection fields and the experimental Webhooks check are therefore unavailable and are recorded as limitations rather than silently treated as passing evidence.

Revalidate a private target whenever the Scorecard version, selected checks, or App permission profile changes.

## Public/private boundary

The public `dceoy/segh` repository is not a production scan or dashboard target. Organization scans, selection snapshots, raw evidence, normalized summaries, and managed dashboard issues must run in a private control repository.

Authentication values must remain masked. Do not add environment dumps, shell tracing, token-bearing command output, arbitrary workspace uploads, or direct publication of raw scanner findings.

## Deployment validation

Repository CI validates repository-contained structure and controlled fixtures, but it cannot prove external App installation scope, private repository access, or private artifact visibility.

Before deploying a reviewed scanner revision from the intended private control repository, verify:

- complete intended repository selection and immutable commit planning;
- one read-only repository-scoped token per target;
- immutable private checkout without persisted credentials;
- Scorecard execution with the documented read-only permission set;
- private artifact retention and token redaction on representative failures;
- fail-closed behavior when production publication would target a public repository.

Publish only sanitized run references, expected conclusions, and bounded file-presence confirmation.
