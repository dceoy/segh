# Output schemas

`segh audit` writes three version 4 artifacts.

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
Actions, dependency graph, Dependabot, branch governance, custom properties,
and security-policy observations. There are no Advanced Security feature or
configuration fields.

## `audit.json`

Audit is the canonical automation result. It contains schema version,
organization, generation time, repository counts, policy counts, final
coverage, and sorted policy results. Each result contains repository, policy ID,
status, severity, observed and expected values, evidence source, remediation,
and an optional applied suppression.

## `report.md`

The Markdown report is a deterministic operator rendering of repository counts,
coverage, policy counts, and all non-passing results.

Artifacts are generated and cross-validated in one process. No artifact embeds
a full copy of another, and removed schema versions are not translated.

## Periodic source-scan evidence

Source scanning does not add fields to `inventory.json` or `audit.json`.
`scan-manifest.json` uses source-scan schema version 1 and records the selected
repository ID, full name, visibility, default branch, exact 40-character commit
SHA, and selection reason. Failed commit resolution and incomplete inventory
coverage are explicit sorted errors rather than successful targets.

Every repository artifact contains `status.json` with the same repository and
commit identity, an aggregate result (`pass`, `findings`, `incomplete`, or
`error`), and seven scanner/component records. Each record preserves the tool
version, exit status, classification, and finding count. Complete JSON, text,
log, and status files remain beside it.

`scan-summary.json` validates every repository status against the manifest,
rejects missing, duplicate, malformed, or mismatched evidence, and reports
separate passed, findings, incomplete, and runtime-error counts. Its bounded
operator rendering is `scan-report.md`.

Pull-request scanner evidence uses the same neutral repository scanner but is
still workflow evidence, not part of the governance or source-scan schemas.
Artifacts can contain sensitive secret findings and repository paths. Keep the
control repository and Actions artifacts private and retain them only for the
configured bounded period.
