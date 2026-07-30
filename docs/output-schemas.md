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

Pull-request scanner JSON, text, status, and log files are workflow evidence,
not part of the `segh` configuration or audit schema.
