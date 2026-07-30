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

| Gate | Threshold | Machine output | Human output |
|---|---|---|---|
| zizmor | medium+ severity, high confidence, strict collection | JSON | plain text |
| Trivy misconfiguration | high, critical | JSON | table |
| Trivy vulnerability | high, critical | JSON | table |
| Trivy secret | every severity | JSON | table |

Each scanner status is captured without stopping later scans. The workflow
uploads `pr-security-reports`, writes bounded human-readable summaries, and only
then fails the ordinary check if any scanner found a threshold violation or
encountered an execution error.

OpenSSF Scorecard runs in a separate `scorecard` job with
`continue-on-error: true`. It is informational and must not be selected as a
required ruleset check.

Target repositories need no local security workflow, publication variable, or
write permission. Fork and Dependabot pull requests use the same read-only job.
Scanner output is retained only as ordinary workflow artifacts.

## Scanner policy ownership

The ruleset workflow supplies `/dev/null` for Trivy's target-repository
configuration and ignore inputs, and supplies its secret configuration from the
trusted `segh` checkout. Misconfiguration checks use the scanner's pinned
bundle, while vulnerability databases use Trivy's standard download and cache
behavior. Pull-request files cannot weaken thresholds or add ignore rules.

Change scanner versions, thresholds, or exclusions only through review in the
protected `segh` repository. Keep the workflow and job names stable so ruleset
enforcement does not drift.

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
2. In test branches, introduce one detectable workflow issue, secret,
   high-severity vulnerable dependency, and high-severity misconfiguration.
3. Confirm each case fails the same stable required check.
4. Confirm all JSON, text, log, and status files remain downloadable on failure.
5. Confirm a fork pull request and a Dependabot pull request use no privileged
   follow-up.
6. Enable the required workflow/check rule for the intended repository set.

GitHub's current ruleset documentation is the authority for organization
required-workflow availability and limits.
