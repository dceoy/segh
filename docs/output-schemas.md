# Output schemas and retention

Top-level schema versions:

| Output | Version | Primary records |
|---|---:|---|
| Inventory | 1 | normalized repositories and capability observations |
| Audit | 1 | policy status/evidence/remediation |
| Scan | 1 | repository timing, scanner status, findings count, result paths |
| Report | 1 | inventory/audit/scan/publication plus aggregate counts |

JSON object outputs are deterministic and intended for automation. When
`output.jsonl` is enabled, inventory, audit, and scan also emit record-oriented
JSONL. Markdown is suitable for `$GITHUB_STEP_SUMMARY`. Native scanner SARIF is
not translated or flattened before publication, preserving rule IDs,
severities, locations, fingerprints, and help metadata.

`report --previous-scan <scan.json>` records previous/current finding totals
and a delta without treating the prior artifact as a database or source of
truth. Pull-request gating uses native fingerprints rather than aggregate
counts.

`report --expected-repositories <n>` marks summary coverage `partial` when no
scan input is supplied, or when the supplied scan covers fewer than `n`
distinct repositories, so a matrix batch that never produced a `scan.json`
cannot leave an incomplete organization audit report as `complete`. Pass the
batch plan's repository count (not the organization inventory's selected
count), since a targeted `workflow_dispatch` run intentionally scans fewer
repositories than the full inventory. The default `-1` disables this check.
Coverage is a summary label only; it does not change the `report` command's
exit code.

Recommended retention is 14 days and must comply with organization policy.
SARIF upload status and unsupported paths remain in the report. Do not retain
private source clones, App private keys, installation tokens, or scanner
environments as artifacts.
