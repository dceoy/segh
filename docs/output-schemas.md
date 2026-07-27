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

Recommended retention is 14 days and must comply with organization policy.
SARIF upload status and unsupported paths remain in the report. Do not retain
private source clones, App private keys, installation tokens, or scanner
environments as artifacts.
