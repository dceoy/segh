# Output schemas

`segh audit` always writes three version 5 governance artifacts. When source
scanning is enabled, the same execution also writes the separate version 1
`scan-manifest.json`. Reconciliation later writes `scan-summary.json` and its
bounded Markdown rendering without changing the governance schemas.

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

Audit is the canonical governance result. It contains schema version,
organization, generation time, repository counts, policy counts, final
coverage, and sorted policy results. Each result contains repository, policy ID,
status, severity, observed and expected values, evidence source, remediation,
and an optional applied suppression. Status is `pass`, `fail`, `unknown`,
`unsupported`, `exempt`, `warning`, or `notice`; only `fail` counts toward the
governance findings exit classification, and only `unknown`/`unsupported`
degrade governance coverage.

## `report.md`

The Markdown report is a deterministic operator rendering of repository counts,
coverage, policy counts, and all non-passing governance results.

The three governance artifacts are generated and cross-validated in one
process. No artifact embeds a full copy of another, and removed schema versions
are not translated.

## `scan-manifest.json`

The manifest uses source-scan schema version 1 and records every selected
repository ID, owner, name, visibility, default branch, resolved lowercase
40-character commit SHA, and whether it was scheduled. Failed commit resolution
preserves the selected identity with no commit or schedule and adds a sorted
planning error, so incomplete selections remain countable. Repository ordering
and the 256-target matrix bound are deterministic.

## Repository `status.json`

Each repository artifact is produced by the pinned upstream
`repository-security-scan.yml`, not by `segh`. Its exact contract has no schema
version and uses the hyphenated keys `result`, `repository-id` (string),
`repository`, `default-branch`, and `commit-sha`. Result is `pass`, `findings`,
`incomplete`, or `error`. Complete scanner JSON, text, logs, and per-tool status
files remain beside it in the private artifact.

## `scan-summary.json` and `scan-report.md`

The organization reconciliation mode parses every upstream status as untrusted
input, converts it to `segh`'s versioned repository-status shape, and validates
repository ID, full name, default branch, and commit SHA against the manifest.
Missing, duplicate, malformed, unsupported, or mismatched evidence fails closed.
The summary reports separate selected, scanned, passed, findings, incomplete,
and runtime-error counts. `scan-report.md` is bounded to aggregate counts and at
most 50 error labels; complete details remain in private JSON and repository
artifacts.

Artifacts can contain sensitive secret findings and repository paths. Keep the
control repository and Actions artifacts private and retain them only for the
bounded workflow period.
