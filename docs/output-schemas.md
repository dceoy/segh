# Output schemas

`segh audit` writes three version 5 artifacts.

## `inventory.json`

Inventory contains organization metadata, selected and excluded repository
counts, sorted repository observations, and bounded collection errors.
Observations use:

```json
{
  "state": "available",
  "value": true,
  "source": "vulnerability_alerts"
}
```

`state` is `available`, `unknown`, or `unsupported`. Repository fields include
Actions, dependency graph, Dependabot, branch governance, and security-policy
observations. There are no Advanced Security feature or configuration fields.

## `audit.json`

Audit is the canonical automation result. It contains schema version,
organization, generation time, repository counts, policy counts, final
coverage, and sorted policy results. Each result contains repository, policy ID,
status, severity, observed and expected values, evidence source, remediation,
and an optional applied suppression. Status is `pass`, `fail`, `unknown`,
`unsupported`, `exempt`, `warning`, or `notice`; only `fail` counts toward the
findings exit code, and only `unknown`/`unsupported` count toward partial
coverage.

## `report.md`

The Markdown report is a deterministic operator rendering of repository counts,
coverage, policy counts, and all non-passing results.

Artifacts are generated and cross-validated in one process. No artifact embeds
a full copy of another, and removed schema versions are not translated.

## Periodic source-scan evidence

Source scanning does not add fields to `inventory.json` or `audit.json`.
`scan-manifest.json` uses source-scan schema version 1 and records every selected
repository ID, owner, name, visibility, default branch, resolved 40-character
commit SHA, and whether it was scheduled. Failed commit resolution preserves
the selected identity with no commit or schedule and adds a sorted planning
error, so incomplete selections remain countable.

Every repository artifact contains `status.json`, published by the pinned
upstream `repository-security-scan.yml` reusable workflow in its own shape
(hyphenated `result`, `repository-id` (string), `repository`, `default-branch`,
`commit-sha` keys; no schema version field), with the same repository and
commit identity plus an aggregate result (`pass`, `findings`, `incomplete`, or
`error`). The upstream scanner's complete JSON, text, log, and per-tool status
files remain beside it.

`scan-summary.json` parses every repository's upstream `status.json` as
untrusted input, converts it into `segh`'s own `RepositoryScanStatus` shape,
validates it against the manifest, rejects missing, duplicate, malformed, or
mismatched evidence, and reports separate passed, findings, incomplete, and
runtime-error counts. Its bounded operator rendering is `scan-report.md`.

Artifacts can contain sensitive secret findings and repository paths. Keep the
control repository and Actions artifacts private and retain them only for the
configured bounded period.
