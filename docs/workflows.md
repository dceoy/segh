# Workflows and rollout

## Pull-request security

`.github/workflows/pr-security.yml` is the single supported merge-time security
workflow. Install it as an organization ruleset required workflow for the
selected private repositories, then require its stable
`PR security / scan` check.

The job checks out:

1. the trusted `dceoy/segh` workflow revision; and
2. the exact pull-request head as untrusted scanner input.

It then runs these blocking gates:

| Gate                    | Threshold                                            | Machine output | Human output |
| ----------------------- | ---------------------------------------------------- | -------------- | ------------ |
| zizmor                  | medium+ severity, high confidence, strict collection | JSON           | plain text   |
| actionlint + ShellCheck | every non-exempt workflow or embedded-shell finding  | —              | plain text   |
| standalone ShellCheck   | every non-exempt tracked-shell finding               | —              | GCC text     |
| Checkov                 | every centrally enabled IaC check                    | JSON           | CLI text     |
| Trivy vulnerability     | high, critical                                       | JSON           | table        |
| Trivy secret            | every severity                                       | JSON           | table        |

Each scanner status is captured without stopping later scans. The workflow
uploads `pr-security-reports`, writes bounded human-readable summaries, and only
then fails the ordinary check if any scanner found a threshold violation or
encountered an execution error.

Before any gate runs, a dedicated step deletes every tracked symlink from the
pull-request checkout and records what it removed in
`rejected-symlinks.txt`, with a `::warning::` annotation per path. `git
ls-files` and directory-walking scanners alike would otherwise resolve a
pull-request-controlled symlink to a path outside `_target` (for example
into `_segh` or runner files); removing tracked symlinks up front closes
that off for every gate, including Checkov, whose directory scan has no
git-aware candidate list to filter.

actionlint scans only tracked, non-symlink `.github/workflows/*.yml` and
`.yaml` files and uses the installed ShellCheck CLI for embedded `run:`
blocks. Standalone ShellCheck scans every tracked, non-symlink regular file:
`*.sh`, `*.bash`, and `*.bats` files unconditionally, plus any other tracked
file (executable or not) whose first line is a shebang naming a
ShellCheck-supported interpreter (`sh`, `ash`, `dash`, `bash`, `ksh`,
`ksh88`, `ksh93`, `oksh`, `bats`, or `busybox` followed by one of
those). An empty relevant file set is recorded as a successful skip.

Checkov runs offline with `--skip-download` and an explicit IaC-only framework
allowlist. It does not scan packages, images, secrets, GitHub Actions, or source
code, does not use a Prisma Cloud API key, and does not upload results. A
zero-resource scan is recorded as a successful skip. Failed checks and inline
suppressions remain visible in the retained JSON and CLI reports.

OpenSSF Scorecard runs in a separate `scorecard` job with
`continue-on-error: true`. It is informational and must not be selected as a
required ruleset check.

Target repositories need no local security workflow, publication variable, or
write permission. Fork and Dependabot pull requests use the same read-only job.
Scanner output is retained only as ordinary workflow artifacts.

`scan` also triggers on `merge_group`, scanning the merge queue's own head SHA
(not an individual pull request's), so a target repository that requires
`PR security / scan` via an organization ruleset can still complete a queued
merge; GitHub creates no check for `merge_group` commits on workflows that
only listen for `pull_request`, which would otherwise stall the queue.

### Source-repository enforcement

`scan` excludes `dceoy/segh` itself: an organization ruleset pins target
repositories to a trusted `dceoy/segh` commit, but a pull request against
`dceoy/segh` could otherwise supply its own "trusted" checkout of this file.
`.github/workflows/pr-security-self.yml` runs the same gates for `dceoy/segh`
instead, triggered only by `pull_request_target` so its job definition always
comes from the base branch.

`dceoy/segh` does not support a merge queue: `pr-security-self.yml` declares
no `merge_group` trigger, and `publish-self-check` publishes only against
`github.event.pull_request.head.sha`, which does not exist on a `merge_group`
event. Enabling a merge queue on `dceoy/segh` without first adding that
support would let a merge-group commit land with neither `scan-self` nor the
published head-commit check ever running against it.

`pull_request_target` runs with `GITHUB_SHA` set to the base branch's commit,
not the pull request's head, so the check run GitHub Actions creates
automatically for the `scan-self` job does not attach to the commit branch
protection evaluates. A separate `publish-self-check` job, which never checks
out pull-request content, therefore publishes an explicit check run named
`segh source scan (head commit)` pinned to the pull request's head SHA once
`scan-self` completes. Require that check (not the job-level
`PR security / scan-self` context, which evaluates the wrong commit) on
`dceoy/segh`'s own branch protection or ruleset.

`publish-self-check` cannot publish with the default `github.token`: that
token's identity is the shared "GitHub Actions" App available to every
workflow in the repository, including one an ordinary same-repository pull
request adds under the `pull_request` trigger. A repository secret is not a
sufficient substitute either, because `pull_request` (unlike
`pull_request_target`) already exposes repository secrets to
same-repository pull requests. The job instead mints a token from a
dedicated GitHub App, gated by an environment whose deployment-branch policy
allows only the base branch. `pull_request_target` runs with `github.ref`
set to that base branch, so this job can reach the environment secrets; an
ordinary `pull_request` job runs against an ephemeral merge ref that never
matches the policy, so GitHub denies it those secrets before it can mint a
forged token.

Before requiring `segh source scan (head commit)` on `dceoy/segh`:

1. Create a GitHub App scoped to Checks: Write and Metadata: Read only, and
   install it on the `dceoy/segh` repository.
2. Create a repository environment named `self-scan-publisher` and restrict
   its deployment branches to the base branch (`main`) only, with no other
   repository able to satisfy that policy.
3. Add the Client ID as the `self-scan-publisher` environment's
   `SEGH_SCAN_PUBLISHER_CLIENT_ID` variable (not a secret: a Client ID is not
   sensitive) and the private key as its `SEGH_SCAN_PUBLISHER_APP_PRIVATE_KEY`
   secret. Use environment-scoped values, not repository-level ones, for
   both.
4. In the required-check configuration, pin `segh source scan (head commit)`
   to this App's numeric App ID (shown on the App's settings page; distinct
   from the Client ID used in step 3 to mint the token), not only its name,
   so a same-named check published by the default App identity cannot
   satisfy it.

This rollout cannot be exercised or verified from within a pull request
against `dceoy/segh`: `pull_request_target` only takes effect once its
workflow definition is on the base branch, and the App, environment, and
required-check App pinning are one-time repository configuration outside
this repository's tracked files.

## Scanner policy ownership

The ruleset workflow passes actionlint, ShellCheck, Checkov, and Trivy
configuration only from the trusted `segh` checkout. The actionlint
configuration owns accepted diagnostic exclusions and organization runner
labels. The ShellCheck configuration owns accepted standalone and embedded
shell exclusions. The Checkov configuration owns the explicit IaC framework
allowlist and accepted Checkov ID exclusions; its pinned release plus that
reviewed exclusion list is the deterministic offline policy baseline.

The workflow supplies `/dev/null` for Trivy's target-repository configuration
and ignore inputs and supplies its secret configuration from the trusted
checkout. Vulnerability databases use Trivy's standard download and cache
behavior. Pull-request files cannot weaken thresholds, add centrally accepted
exclusions, load external Checkov policies, enable hosted enforcement rules, or
replace scanner commands with wrapper scripts.

Change scanner versions, thresholds, or exclusions only through review in the
protected `segh` repository. Keep the workflow and job names stable so ruleset
enforcement does not drift.

## Tool licensing

| Tool       | Pinned version | License    | Redistribution obligation                                                  |
| ---------- | -------------- | ---------- | -------------------------------------------------------------------------- |
| actionlint | v1.7.12        | MIT        | Preserve its copyright and permission notice.                              |
| ShellCheck | v0.11.0        | GPL-3.0    | GPL source and license obligations apply if its binary is redistributed.   |
| Checkov    | 3.3.8          | Apache-2.0 | Preserve its license and notices and identify redistributed modifications. |

All three may be used internally on commercial repositories without a license
fee. `segh` downloads their unmodified CLI release artifacts at workflow runtime
and does not vendor modified ShellCheck source or binaries. Running ShellCheck
as an analyzer does not make the target repository's source GPL-covered.

## Organization audit

`.github/workflows/organization-audit.yml` runs from a private control
repository.

1. Add a reviewed 40-character commit from protected `dceoy/segh` `main` to
   `config/segh-source-commit`.
2. Install a read-only GitHub App on every repository in the organization.
3. Add the App ID as `SEGH_READ_APP_ID` and private key as
   `SEGH_READ_APP_PRIVATE_KEY`.
4. Store the version 4 policy in `config/organization.yaml`.
5. Run `Organization security governance audit`.

The workflow verifies the pinned source is reachable from protected `main`,
mints a short-lived App token, requires a private control repository, runs one
`segh audit`, adds `report.md` to the job summary, and retains all three evidence
artifacts.

## Rollout verification

Before making the scanner check required:

1. Run a clean pull request and confirm `PR security / scan` succeeds.
2. In test branches, introduce one detectable zizmor finding, invalid workflow
   expression, embedded shell diagnostic, standalone shell diagnostic, enabled
   Checkov failure, high-severity vulnerable dependency, and secret.
3. Confirm each case fails the same stable required check.
4. Confirm repositories with no workflows, shell scripts, or supported IaC
   resources record successful skips.
5. Confirm all JSON, text, log, and status files remain downloadable on failure.
6. Confirm a fork pull request and a Dependabot pull request use no privileged
   follow-up.
7. Enable the required workflow/check rule for the intended repository set.

GitHub's current ruleset documentation is the authority for organization
required-workflow availability and limits.
