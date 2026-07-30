# Output schemas

`segh audit` produces three version 3 artifacts:

- `inventory.json`: selected and excluded repositories, capability-aware native
  control observations, and bounded collection errors;
- `audit.json`: the canonical machine-readable compliance result, containing
  repository counts, policy counts, final coverage, and sorted policy results;
- `report.md`: a deterministic operator rendering of the in-memory inventory
  and audit result.

Repository custom-property values retain GitHub's `null`, string, or string-array
shape inside one typed observation with `state`, `value`, `source`, and
`reason`. A scalar `selectors.custom_properties` value matches an equal scalar
or membership in a multi-select array.

No JSON artifact nests a complete copy of another artifact. Artifacts are
generated and cross-validated in one process and are never read back to
simulate removed command boundaries. Schema versions 1 and 2 are rejected;
there is no migration or compatibility path.

Scanner and SARIF schemas are intentionally absent. Raw SARIF is owned and
retained by the central security workflow, and GitHub Code Scanning is the
finding and merge-enforcement system of record.
