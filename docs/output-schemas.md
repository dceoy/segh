# Output schemas

`segh` produces three schema-version 2 JSON documents:

- `inventory.json`: selected and excluded repositories, capability-aware native
  control observations, and bounded collection errors;
- `audit.json`: sorted policy results, suppressions, and status counts;
- `report.json`: the inventory and audit plus a deterministic coverage summary.

The `report` command is the sole producer of the consolidated Markdown operator
summary. Inventory and audit commands write only their canonical JSON evidence.
Repository custom-property values retain GitHub's `null`, string, or string-array
shape. A scalar `selectors.custom_properties` value matches an equal scalar or
membership in a multi-select array.

Scanner and SARIF schemas are intentionally absent. Raw SARIF is owned and
retained by the central security workflow, and GitHub Code Scanning is the
finding and merge-enforcement system of record.

Version 2 removes scanner execution, publication, and PR-gate fields from the
configuration and result pipeline. Version 1 inputs are rejected rather than
silently reinterpreted.
