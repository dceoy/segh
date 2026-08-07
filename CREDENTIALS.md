# Credential and trust boundaries

`segh` separates merge-boundary attestation, immutable scan planning, per-repository scanning, complete App-selection capture, and dashboard reconciliation into distinct credential domains.

```text
trusted pull-request boundary
  └─ dedicated repository App runtime token, metadata: read + checks: write
     (App installation also has statuses: write only for ruleset source eligibility)

scan plan
  └─ organization installation token, read-only

scan matrix
  └─ one repository-scoped installation token per matrix target, read-only

selection snapshot
  └─ organization installation token, read-only; no issue-write permission

dashboard publication / reconciliation
  └─ same private control repository's GITHUB_TOKEN with
     actions: read, contents: read, and issues: write; no configured secrets
```

No scan or selection job receives either the trusted-boundary check-write credential or an issue-write credential.

## GitHub App installation

Create one GitHub App for organization discovery and target scanning. Install it only on the repositories that form the authoritative scan set.

Store the App identity in the private execution or control repository as:

- `SEGH_ORG_SCAN_APP_ID`
- `SEGH_ORG_SCAN_APP_PRIVATE_KEY`

The private key must be an Actions secret. The App ID may also be stored as a secret so the reusable-workflow interface remains uniform.

The App requires only these repository permissions:

| Permission | Access | Consumer | Reason |
| --- | --- | --- | --- |
| Metadata | Read | scan plan, selection snapshot, scan | Repository identity and metadata; implicitly available to installation tokens |
| Contents | Read | scan plan, selection snapshot, scan | Enumerate the selected repositories, resolve immutable commits, checkout the selected commit, and let Scorecard inspect repository content and history |
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

## Trusted merge-boundary credential

`dceoy/segh` remains a personally owned repository, so the trusted merge boundary uses a dedicated GitHub App rather than an organization required-workflow rule.

Create a separate GitHub App for this boundary and install it **only** on `dceoy/segh`. Grant exactly:

| Permission | Access | Reason |
| --- | --- | --- |
| Metadata | Read | Required installation metadata |
| Checks | Write | Publish the trusted attestation on the pull-request head SHA |
| Commit statuses | Write | Make the App eligible to be selected as the repository ruleset's expected status-check source |

The Commit statuses permission is an installation-level eligibility requirement only. The trusted workflow does **not** request `statuses: write` when minting its short-lived installation token; the runtime token remains restricted to Metadata read and Checks write and therefore cannot create commit statuses.

Do not grant Contents, Actions, Issues, Pull requests, Administration, or any other repository permission to this App.

Create an Actions environment named `trusted-boundary`. Configure its deployment branch policy to allow only `main`; do not allow pull-request refs or feature branches. Store only these environment secrets there:

- `SEGH_BOUNDARY_APP_ID`
- `SEGH_BOUNDARY_APP_PRIVATE_KEY`

`.github/workflows/trusted-boundary.yml` is loaded from the protected base revision through `pull_request_target`. Its normal `GITHUB_TOKEN` remains `contents: read`. The workflow mints a repository-scoped dedicated-App token only after entering the `trusted-boundary` environment and passes that token only to the final attestation API call. Candidate code, candidate actions, target scanners, selection jobs, and dashboard jobs never receive it.

After trusted validation completes, the workflow writes one completed check named `Trusted workflow-only boundary attestation` to `github.event.pull_request.head.sha`. A success conclusion is emitted only when the trusted base checkout, candidate checkout, trusted policy comparison, and base-sourced validator all succeed. Failure in any of those phases produces a failed attestation; failure to obtain the environment credential produces no attestation and therefore fails closed once the check is required.

Bootstrap the ruleset binding in this order:

1. merge the trusted workflow and configure the dedicated App plus `trusted-boundary` environment;
2. open or update a representative pull request so the dedicated App emits `Trusted workflow-only boundary attestation` at least once;
3. configure the repository `branch-protection` ruleset for the default branch with a strict required-status-check rule for that exact check, selecting the dedicated App as the expected source/integration;
4. verify that a same-named check from GitHub Actions or another integration does not satisfy the rule.

The App must publish a check before it can be selected reliably as the expected source. Do not configure the GitHub Actions App as the expected source.

The first merge that introduces or deliberately changes the trusted workflow, `scripts/preflight.sh`, or `scripts/validate-workflow-boundary.rb` is an explicit bootstrap/break-glass operation: the already-merged base policy intentionally rejects such candidate changes. After the trusted App, environment, and ruleset are active, changing or bypassing any of them requires an explicit repository-owner administrative action and is outside the ordinary pull-request trust boundary. Record such actions as security-sensitive maintenance.

## Scan-planning credential

The `plan` job in `organization-scan.yml` mints a short-lived installation token with only Metadata and Contents read access. It uses the token only to:

1. enumerate repositories selected by the App installation;
2. read bounded repository identity metadata; and
3. resolve each active default branch to one immutable commit SHA.

The token is not a job output, is not persisted in a checkout, and is never available to scanner or dashboard code. The token action revokes it at job completion. The job uploads only the bounded `matrix.json` immutable scan plan.

## Complete-selection credential

`organization-selection.yml` independently mints the same narrow organization installation token with only Metadata and Contents read access. It does **not** resolve source commits or run scanners. Its sole purpose is to retain a bounded transient snapshot of the complete GitHub App repository selection so dashboard reconciliation can account for repository lifecycle changes even when immutable scan planning fails.

The snapshot contains only:

- immutable repository ID;
- current full name, owner, and repository name;
- visibility and fork state;
- archived and disabled state;
- default branch name; and
- an explicit `active` or `retired` disposition with a bounded reason.

It contains no source content, scanner output, secret values, governance policy data, or write credential. The selection job has `permissions: {}` and cannot update issues. The snapshot artifact is retained for one day.

The selection and scan workflows should run in parallel from the same reviewed `segh` revision. A repository selection change between their API calls is treated fail closed during final reconciliation rather than silently omitted.

## Per-repository scan credential

Each matrix job mints a new installation token with `owner: ${{ matrix.owner }}` and `repositories: ${{ matrix.name }}`. The token is therefore bounded to exactly one target repository and cannot be reused across matrix targets.

The target token is passed only to:

- the target checkout, with `persist-credentials: false`, `lfs: false`, and `submodules: false`; and
- OpenSSF Scorecard through the step-local `SEGH_TARGET_SCORECARD_TOKEN` environment variable.

The scanner job has no write permission. Target-controlled scripts, actions, hooks, package managers, builds, tests, Terraform providers, submodules, and installers are never executed.

The trusted scanner revision creates a bounded `summary.json` from scanner exit classes and native outputs. This summary contains counts, statuses, selected Scorecard scores, and immutable provenance, but no raw source excerpts, private paths, secret values, or logs.

## Dashboard publication credential

The normal `publish-dashboard` job inside `organization-scan.yml` and the final `dashboard-reconcile.yml` workflow use the private control repository's built-in `GITHUB_TOKEN`. Both are restricted to the same explicit permission set:

| Permission | Access | Reason |
| --- | --- | --- |
| Actions | Read | Download the current run's bounded plan, selection, and normalized summary artifacts |
| Contents | Read | Check out the trusted publisher/reconciler implementation at the immutable reusable-workflow revision |
| Issues | Write | Create labels and create, update, comment on, open, or close managed dashboard issues |

Both jobs bind the dashboard target to `${{ github.repository }}` and verify that the caller repository is private before downloading or publishing organization state.

The final reconciliation workflow receives **no configured secrets**. In particular it receives none of:

- `SEGH_ORG_SCAN_APP_ID`;
- `SEGH_ORG_SCAN_APP_PRIVATE_KEY`;
- `SEGH_BOUNDARY_APP_ID`;
- `SEGH_BOUNDARY_APP_PRIVATE_KEY`;
- the trusted-boundary App token;
- the planning token;
- a repository-scoped target token; or
- `SEGH_TARGET_SCORECARD_TOKEN`.

Scanner and selection jobs receive no issue-write credential. Cross-repository dashboard publication, personal access tokens, generic configured tokens, and a separate publisher GitHub App are outside this credential contract.

Issue and label API calls are sequential, bounded, and retried only for bounded transient or secondary-rate-limit failures. Final organization reconciliation attempts the remaining repository decisions after one publication operation fails, reports the failed-operation count, and fails the job after the bounded pass completes.

## Recommended caller boundary

Pin all three reusable workflows to the same reviewed 40-character `segh` commit:

```text
scan      ─┐
           ├─> reconcile (if: always())
selection ─┘
```

The caller permissions should be scoped per reusable-workflow job rather than granted globally:

- `scan`: `actions: read`, `contents: read`, `checks: read`, `issues: write`, `pull-requests: read` because the called workflow contains both read-only scan jobs and its isolated normal publisher;
- `selection`: `permissions: {}` plus only the two organization App secrets;
- `reconcile`: `actions: read`, `contents: read`, `issues: write`, with no secrets.

`reconcile` must use `if: always()` so a failed scan or selection job still triggers stale/error handling for existing managed dashboards. Pass `needs.scan.result` through the bounded `scan_result` input; do not expose tokens through outputs or generic environment variables.

## Public/private safety boundary

The source repository `dceoy/segh` is public. Organization scans, complete selection snapshots, raw evidence, normalized summaries, and dashboard issues must run in a private execution or control repository.

Every production workflow fails closed when its caller-side operation would expose organization state through a public dashboard target. Because the dashboard target is fixed to the caller repository, this visibility check validates the actual issue-publication target. Private repository names, paths, source excerpts, scanner logs, and finding details must not be placed in public issues, job summaries, or artifacts belonging to the public source repository.

The trusted merge-boundary check is intentionally public metadata about pull-request policy success or failure. It must not publish scanner evidence, private repository identities, secret values, or other private control-repository data.

## Removed names and migration

Remove these obsolete secrets or variables from control repositories and environments:

- `SEGH_READ_APP_ID`
- `SEGH_READ_APP_PRIVATE_KEY`
- `SEGH_PUBLISH_APP_ID`
- `SEGH_PUBLISH_APP_PRIVATE_KEY`
- any generic `GH_TOKEN`, `GITHUB_TOKEN`, `TARGET_TOKEN`, or `SCAN_TOKEN` secret created for cross-phase reuse
- any issue-write token installed on target repositories

The workflows use `SEGH_PLAN_TOKEN`, `SEGH_SELECTION_TOKEN`, and `SEGH_TARGET_SCORECARD_TOKEN` only as step-local environment variables. None is a configured secret or workflow output. The dedicated merge-boundary App credentials are separate environment secrets and must never be copied into a control repository, scanner job, selection job, publisher job, or reconciliation job.
