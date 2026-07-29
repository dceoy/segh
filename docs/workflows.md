# GitHub Actions rollout

## Organization governance audit

Copy `.github/workflows/organization-audit.yml` into a private control
repository and configure:

- `SEGH_READ_APP_ID`
- `SEGH_READ_APP_PRIVATE_KEY`

The App-token action creates a short-lived token for the organization. Only
`GH_TOKEN` reaches `segh`; the App private key stays scoped to the token step.
The job inventories native-control coverage, evaluates policy, writes a
deterministic report, and retains the evidence. It does not clone or scan
organization repositories.

The workflow deliberately refuses to run from a public control repository
because organization inventory and exceptions can be sensitive. Add a schedule
only after copying it to the private control repository.

## Central pull-request scanning

`.github/workflows/pr-security.yml` is the centrally managed `pull_request`
workflow. It checks out its own trusted `github.workflow_sha` separately from
the target repository, installs checksum-pinned scanner binaries with Aqua,
runs scanners directly, and uploads:

| Scanner | Code Scanning category |
|---|---|
| zizmor | `zizmor` |
| Trivy misconfiguration | `trivy` |
| OpenSSF Scorecard | `scorecard` |

Every SARIF file is also retained as an artifact, including when Code Scanning
is unavailable. `.github/workflows/publish-pr-security.yml` is a trusted
`workflow_run` follow-up with `security-events: write`; it downloads only the
triggering run's artifact, never checks out or executes pull-request code, and
uploads against the pull-request head SHA. This preserves publication for fork
and Dependabot pull requests while the scanner remains read-only. The upload
action waits for GitHub processing.

Keep the workflow on a protected branch in the central repository. Configure an
organization ruleset to require that repository, branch, and workflow file for
the repositories selected by organization policy. The workflow installs
scanner configuration from its own immutable `github.workflow_sha`, never from
the pull request under test.

## Merge enforcement

Use GitHub Code Scanning merge protection in the organization ruleset. Require
the scanner analyses expected for the repository set and configure blocking
severity thresholds there. This removes the need for a base/current double
scan, custom fingerprints, rename remapping, and a separate `pr-gate` status.

Roll out without a check gap:

1. Enable the direct scanner workflow and confirm all SARIF categories appear.
2. Add Code Scanning merge protection and the central required workflow in
   report-only/non-blocking rollout mode where available.
3. Confirm coverage across the selected repositories.
4. Enable the intended blocking severities.
5. Remove legacy scanner and gate workflows only after the new checks are
   required.

GitHub documents required workflow rules and Code Scanning merge protection in
the repository ruleset documentation:
<https://docs.github.com/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets>.
