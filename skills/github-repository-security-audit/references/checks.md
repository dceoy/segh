# Audit checks

`github-controls.json` contains one object per control. Every object has
`id`, `state`, `reason`, `required_permission`, and an `evidence` reference.
The state vocabulary is intentionally small:

- `pass`: the API returned valid evidence consistent with the control.
- `finding`: the API returned valid evidence of a security-negative state.
- `unknown`: the property was not observable because of permissions,
  unsupported product semantics, or an endpoint that cannot answer the
  question for this repository.
- `error`: the request or the successful response was malformed, or evidence
  could not be trusted.

An `unknown` control must never be interpreted as disabled or enabled. An
`error` control must never be silently omitted from the report.

## Repository and revision evidence

`repository_metadata` records the validated repository identity, visibility,
fork/archive state, and default branch. `immutable_default_branch` records
the commit object resolved from that branch. The checkout and all scanner
evidence must use that exact lowercase 40-character SHA.

`effective_branch_rules` records the response from
`GET /repos/{owner}/{repo}/rules/branches/{branch}`. A valid empty rules
array is observable evidence, but it is not a hard finding because this skill
does not invent an organization-wide branch-protection baseline.

`code_security_configuration` records the associated code-security
configuration when GitHub exposes one. Association is evidence, not a claim
that every setting in that configuration has been enabled. A documented 200
response with an attached configuration is `pass: association-observed`; a
204 response is `pass: no-association`. Other successful response shapes are
malformed evidence.

## GitHub Actions controls

`actions_permissions` reads `GET /repos/{owner}/{repo}/actions/permissions`.
`sha_pinning_required: false` is a finding. A missing property is unknown;
the audit does not infer a setting from an incomplete response.

`workflow_permissions` reads
`GET /repos/{owner}/{repo}/actions/permissions/workflow`.

- `default_workflow_permissions: write` is a finding.
- `can_approve_pull_request_reviews: true` is a finding.
- Missing properties are unknown.

Both controls require administration read access in the report because the
repository-level settings are permission-dependent.

## Repository security controls

The repository metadata `security_and_analysis` object is used only when it
is present and well-formed. An omitted object is recorded as
`unknown: insufficient-permission`; it is not treated as disabled.

- `secret_scanning` with status `disabled` is a finding.
- `secret_scanning_push_protection` with status `disabled` is a finding.
- `enabled` is a pass; an absent or unrecognized status is unknown/error as
  described by the evidence state rules.

The following feature endpoints require administration read access. A
successful 2xx response is recorded as enabled. A 403 is an
insufficient-permission unknown. A 404 is recorded as
`unknown: not-observable`: although some endpoint documentation uses 404 for
a disabled feature, the same response can be returned when the credential
cannot observe an administration-gated resource, and this audit does not
establish that permission separately.

- `vulnerability_alerts` — `GET /repos/{owner}/{repo}/vulnerability-alerts`
- `dependabot_security_updates` — `GET /repos/{owner}/{repo}/automated-security-fixes`
- `private_vulnerability_reporting` —
  `GET /repos/{owner}/{repo}/private-vulnerability-reporting`

Private-vulnerability reporting is only a finding-oriented control for public
repositories in this skill. For private and internal repositories it is
recorded as `unknown: unsupported`, because this audit does not impose a
policy baseline for that product mode.

All other non-success responses are errors unless the endpoint-specific
permission or not-observable handling above applies. In particular, a 404
from rules or code-security-configuration is not generalized into a disabled
security setting.
