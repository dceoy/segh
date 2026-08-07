# Credential and trust boundaries

`segh` separates repository discovery, per-repository scanning, and dashboard publication into distinct credential domains.

```text
plan
  └─ organization installation token, read-only

scan matrix
  └─ one repository-scoped installation token per matrix target, read-only

publish-dashboard
  └─ same private control repository's GITHUB_TOKEN with
     actions: read, contents: read, and issues: write
```

No job receives both a scan credential and an issue-write credential.

## GitHub App installation

Create one GitHub App for organization discovery and target scanning. Install it only on the repositories that form the authoritative scan set.

Store the App identity in the private execution or control repository as:

- `SEGH_ORG_SCAN_APP_ID`
- `SEGH_ORG_SCAN_APP_PRIVATE_KEY`

The private key must be an Actions secret. The App ID may also be stored as a secret so the reusable-workflow interface remains uniform.

The App requires only these repository permissions:

| Permission | Access | Consumer | Reason |
| --- | --- | --- | --- |
| Metadata | Read | plan and scan | Repository identity and metadata; implicitly available to installation tokens |
| Contents | Read | plan and scan | Resolve immutable commits, checkout the selected commit, and let Scorecard inspect repository content and history |
| Checks | Read | scan only | Scorecard CI-Tests and SAST evidence from check runs |
| Issues | Read | scan only | Scorecard private-repository GraphQL and project-history queries |
| Pull requests | Read | scan only | Scorecard code-review and commit-history queries |

Do not grant write permission to any target repository.

`Actions` is not requested. The retained Scorecard CLI profile obtains CI evidence from checks/statuses and does not call workflow-run or artifact APIs.

`Administration` is not requested. Consequently, Scorecard cannot measure classic branch-protection fields that require administrator access, and the experimental Webhooks check is unsupported. Every scan artifact records these limitations in `scorecard-permissions.json`; operators must not interpret unavailable administrator-only evidence as a complete assessment. Repository rules visible to a read-only token remain measurable.

The permission basis follows the current OpenSSF Scorecard private-repository guidance and check documentation:

- <https://github.com/ossf/scorecard-action#additional-permissions-for-private-repositories>
- <https://github.com/ossf/scorecard/blob/main/docs/checks.md#branch-protection>

A private App-backed validation run remains required whenever the pinned Scorecard version or enabled checks change.

## Planning credential

The `plan` job mints a short-lived installation token with only Metadata and Contents read access. It uses the token only to:

1. enumerate repositories selected by the App installation;
2. read repository metadata; and
3. resolve each default branch to one immutable commit SHA.

The token is not a job output, is not persisted in a checkout, and is never available to scanner or publisher code. The token action revokes it at job completion. The job uploads only the bounded, non-secret `matrix.json` publication plan.

## Per-repository scan credential

Each matrix job mints a new installation token with `owner: ${{ matrix.owner }}` and `repositories: ${{ matrix.name }}`. The token is therefore bounded to exactly one target repository and cannot be reused across matrix targets.

The target token is passed only to:

- the target checkout, with `persist-credentials: false`, `lfs: false`, and `submodules: false`; and
- OpenSSF Scorecard through the step-local `SEGH_TARGET_SCORECARD_TOKEN` environment variable.

The scanner job has no write permission. Target-controlled scripts, actions, hooks, package managers, builds, tests, Terraform providers, submodules, and installers are never executed.

The trusted scanner revision creates a bounded `summary.json` from scanner exit classes and native outputs. This summary contains counts, statuses, selected Scorecard scores, and immutable provenance, but no raw source excerpts, private paths, secret values, or logs.

## Dashboard publisher

The `publish-dashboard` job uses the private control repository's built-in `GITHUB_TOKEN` and publishes only to that same repository. Its explicit permissions are:

| Permission | Access | Reason |
| --- | --- | --- |
| Actions | Read | Download the current run's authoritative plan and normalized summary artifacts |
| Contents | Read | Check out the trusted publisher implementation at the immutable reusable-workflow revision |
| Issues | Write | Create labels and create, update, comment on, open, or close managed dashboard issues |

The job binds `SEGH_DASHBOARD_REPOSITORY` to `${{ github.repository }}` and checks the caller repository's actual private visibility before downloading or publishing results.

Cross-repository dashboard publication, personal access tokens, generic configured tokens, and a separate publisher GitHub App are outside this credential contract. If a later change needs a separately configured dashboard repository, it must first add a runtime API check of that repository's actual visibility and structural tests that fail when private or internal scan results could reach a public target.

The publisher receives no configured secrets, `SEGH_ORG_SCAN_APP_ID`, `SEGH_ORG_SCAN_APP_PRIVATE_KEY`, planning token, per-target token, or Scorecard token. Scanner jobs receive no issue-write credential. Issue and label API calls are sequential, bounded, and retried only for bounded transient or rate-limit failures.

Reusable-workflow callers must grant the maximum permission set required by all called jobs: `actions: read`, `contents: read`, `checks: read`, `issues: write`, and `pull-requests: read`. The called workflow then narrows each scanner job to `issues: read` and grants `issues: write` only to the publisher job.

## Public/private safety boundary

The source repository `dceoy/segh` is public. Organization scans, raw evidence, normalized summaries, and dashboard issues must run in a private execution or control repository.

The workflow fails closed when invoked from a public caller. Because the dashboard target is fixed to the caller repository, this visibility check validates the actual issue-publication target. Private repository names, paths, source excerpts, scanner logs, and finding details must not be placed in public issues, job summaries, or artifacts belonging to the public source repository.

## Removed names and migration

Remove these obsolete secrets or variables from control repositories and environments:

- `SEGH_READ_APP_ID`
- `SEGH_READ_APP_PRIVATE_KEY`
- `SEGH_PUBLISH_APP_ID`
- `SEGH_PUBLISH_APP_PRIVATE_KEY`
- any generic `GH_TOKEN`, `GITHUB_TOKEN`, `TARGET_TOKEN`, or `SCAN_TOKEN` secret created for cross-phase reuse
- any issue-write token installed on target repositories

The workflow uses `SEGH_PLAN_TOKEN` and `SEGH_TARGET_SCORECARD_TOKEN` only as step-local environment variables. Neither is a configured secret.
