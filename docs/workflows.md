# GitHub Actions rollout

## Organization governance audit

Copy `.github/workflows/organization-audit.yml` into a private control
repository and configure:

- `SEGH_READ_APP_ID`
- `SEGH_READ_APP_PRIVATE_KEY`

The App-token action creates a short-lived token for the organization.
`GH_TOKEN` and the action's non-secret installation ID reach `segh`; the App
private key stays scoped to the token step. The job inventories native-control
coverage, evaluates policy, writes a deterministic report, and retains the
evidence. It does not clone or scan organization repositories.

The workflow deliberately refuses to run from a public control repository
because organization inventory and exceptions can be sensitive. Add a schedule
only after copying it to the private control repository.

## Central pull-request scanning

`.github/workflows/pr-security.yml` is the centrally managed `pull_request`
workflow. It checks out its own trusted `github.workflow_sha` separately from
the target repository, installs checksum-pinned scanner binaries with Aqua,
runs scanners directly, and retains:

| Scanner | Code Scanning category |
|---|---|
| zizmor | `zizmor` |
| Trivy misconfiguration | `trivy` |
| OpenSSF Scorecard | `scorecard` |

Scorecard runs in a separate least-privilege job with the pull request checked
out at the workspace root, which is the target that its local pull-request mode
analyzes. Every SARIF file is retained as an artifact, including when Code
Scanning is unavailable. Because `workflow_run` is repository-local, copy
`.github/workflows/publish-pr-security.yml` into every target repository's
protected default branch. This trusted follow-up has `security-events: write`.
It first validates that the triggering workflow ID matches the repository
variable `SEGH_PR_SECURITY_WORKFLOW_ID`, then downloads only that run's
fixed-name artifacts, validates the retained pull-request number and head SHA,
checks out the base repository's `refs/pull/<number>/head`, and verifies that
the checkout matches the analyzed commit. This lets the base repository token
read private-fork pull-request content without direct access to the fork. The
publisher explicitly opts into the checkout action's protected
`workflow_run` fork path only after validating the artifact metadata. The
checkout has no persisted credentials and exists solely so the upload action
can preserve SARIF fingerprints; no pull-request code is executed. This
preserves publication for fork and Dependabot pull requests while the scanner
remains read-only, and rejects artifacts from a pull-request-controlled
same-named workflow. The upload action waits for GitHub processing.

Keep the scanner workflow on a protected branch in the central source
repository. Configure an organization ruleset to require that repository,
branch, and workflow file for the repositories selected by organization
policy. Exclude `dceoy/segh` itself from the rule: its ordinary
`pull_request` copy is intentionally skipped because a source-repository PR
controls that workflow revision. GitHub also recommends disabling the
individual workflow in the source repository.

`pr-security.yml` only subscribes to `pull_request` and does not support merge
queues. A `merge_group` event carries no pull request number or stable ref:
`publish-pr-security.yml` resolves its analyzed commit through
`refs/pull/<number>/head`, which a merge group never has, and the queue's own
ref is deleted once the group is decided, so the `workflow_run` follow-up
could not reliably re-resolve it. Do not enable a required merge queue on a
repository where this ruleset workflow is required until this is addressed.

For each target repository:

1. Install the publisher workflow on its protected default branch.
2. Run the central ruleset workflow once in evaluate or non-blocking mode.
3. Read the run's immutable workflow ID:

   ```console
   gh api repos/OWNER/REPOSITORY/actions/runs/RUN_ID --jq .workflow_id
   ```

4. Create the repository Actions variable
   `SEGH_PR_SECURITY_WORKFLOW_ID` with that numeric value.
5. Re-run the scanner and confirm the publisher uploads all three categories.

The scanner installs configuration from its immutable `github.workflow_sha`,
never from the pull request under test. The target publisher is loaded from the
target's default branch, and the workflow-ID check prevents a pull request from
substituting another artifact producer.

## Merge enforcement

Use GitHub Code Scanning merge protection in the organization ruleset. Require
the scanner analyses expected for the repository set and configure blocking
severity thresholds there. This removes the need for a base/current double
scan, custom fingerprints, rename remapping, and a separate `pr-gate` status.

Roll out without a check gap:

1. Add the central required workflow in evaluate or non-blocking mode.
2. Install the protected publisher and pin the observed workflow ID in every
   target repository.
3. Confirm all SARIF categories appear, including for a private repository and
   a fork or Dependabot pull request.
4. Add Code Scanning merge protection and confirm coverage across the selected
   repositories.
5. Enable the intended blocking severities.
6. Remove legacy scanner and gate workflows only after the new checks are
   required.

GitHub documents required workflow rules and Code Scanning merge protection in
the repository ruleset documentation:
<https://docs.github.com/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets>.
