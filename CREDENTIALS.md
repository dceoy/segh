# Credential and trust boundaries

`segh` separates write-capable control-plane operations from read-only organization scanning and scopes runtime tokens to the minimum access needed for each phase. Organization discovery and per-target scanning use the same organization scan App credentials to mint distinct short-lived installation tokens; dashboard publication uses its caller-scoped `GITHUB_TOKEN`.

```text
scan planning / selection snapshot
  -> organization scan App
     token: metadata read + contents read

scan matrix
  -> one organization scan App token scoped to exactly one target
     metadata/contents/checks/issues/pull-requests read

dashboard publication / reconciliation
  -> private control repository GITHUB_TOKEN
     actions read + contents read + issues write
```

No target repository receives write permission. Scanner and selection jobs never receive dashboard write credentials.

## Organization scan App

Create one GitHub App for repository discovery and scanning, and install it only on the authoritative target set. Store these Actions secrets in the private control repository:

- `SEGH_ORG_SCAN_APP_ID`
- `SEGH_ORG_SCAN_APP_PRIVATE_KEY`

Grant only:

| Permission | Access | Used for |
| --- | --- | --- |
| Metadata | Read | Repository identity and installation metadata |
| Contents | Read | Selection, immutable commit resolution, checkout, Scorecard source/history inspection |
| Checks | Read | Scorecard CI and SAST evidence |
| Issues | Read | Scorecard private-repository queries |
| Pull requests | Read | Scorecard review/history queries |

Do not grant Actions, Administration, or any write permission. The retained Scorecard profile therefore does not claim administrator-only classic branch-protection evidence or the experimental Webhooks check. These limitations are recorded in `scorecard-permissions.json` and must not be interpreted as complete coverage.

Repeat a private App-backed validation whenever the pinned Scorecard version, selected checks, or permission profile changes.

### Planning and selection tokens

The scan planner and selection-snapshot workflow mint short-lived installation tokens with only Metadata and Contents read access.

The planner uses its token only to enumerate the App selection, validate bounded repository metadata, and resolve active default branches to immutable commit SHAs. The selection workflow independently records the complete bounded App selection and lifecycle state; it does not inspect source content or scanner output.

Neither token is a job output or a persisted checkout credential.

### Per-target token

Each matrix job mints a fresh installation token scoped to exactly `matrix.owner/matrix.name`. It is passed only to:

- target checkout with `persist-credentials: false`, `lfs: false`, and `submodules: false`; and
- OpenSSF Scorecard through the step-local `SEGH_TARGET_SCORECARD_TOKEN` variable.

Other scanners operate on the already checked-out workspace and receive no target token. Target-owned executable content is never run.

## Dashboard credential

Dashboard publication uses the private caller repository's built-in `GITHUB_TOKEN` with:

| Permission | Access | Used for |
| --- | --- | --- |
| Actions | Read | Read the bounded run artifacts needed for reconciliation |
| Contents | Read | Check out the trusted publisher/reconciler revision |
| Issues | Write | Manage dashboard labels, issues, and bounded history comments |

The dashboard target is fixed to `${{ github.repository }}` and production publication requires that repository to be private. Cross-repository dashboard publication, personal access tokens, and a separate publisher App are outside the supported contract.

The reconciliation workflow receives no configured secrets, organization App credential, or target token. Issue operations are sequential, bounded, and retried only for bounded transient/rate-limit failures.

## Caller contract

The simplest supported caller invokes `organization-dashboard.yml` from a private control repository at a reviewed immutable `segh` revision. The caller job grants the maximum permissions needed by the nested scan/reconcile jobs:

- `actions: read`
- `contents: read`
- `checks: read`
- `issues: write`
- `pull-requests: read`

Only the two organization App secrets are forwarded. Nested selection and scanner jobs reduce permissions further, and reconciliation receives no App secrets.

If the lower-level reusable workflows are composed directly instead, run scan and selection from the same reviewed revision and invoke reconciliation with `if: always()` so a failed scan cannot leave an earlier passing dashboard looking current.

## Public/private boundary

`dceoy/segh` is public; production organization state is not. Run scans, selection capture, evidence retention, and dashboard publication only from a private control repository.

Do not place private repository identities, paths, source excerpts, scanner logs, finding details, or secret values in public issues, job summaries, or public artifacts.
