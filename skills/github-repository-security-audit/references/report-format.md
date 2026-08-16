# Report format

Write a concise Markdown report from the retained native evidence. Keep the
following sections in this order:

## Target

State the exact `owner/repository`, visibility, default branch, and immutable
commit SHA from `target.json`. State whether the checkout preflight completed.

## Critical/high

List only security-impacting critical or high findings supported by native
scanner evidence or a `finding` GitHub control. Include the control/scanner
ID, affected path or setting, evidence file, and a concrete remediation.

## Medium/low

List medium and low findings with the same evidence and remediation details.
Do not turn Scorecard scores into findings or invent a threshold that is not
present in the native result.

## GitHub security controls

Summarize every control from `github-controls.json`, including pass, finding,
unknown, and error states. Explain the reason and required permission for
unknown/error controls. A missing permission is a coverage gap, not a pass.

## Source scanners

Report the native result for Scorecard, zizmor, actionlint, ShellCheck,
Checkov, Trivy vulnerability, and Trivy secret scans. Preserve the distinction
between findings and execution/evidence errors. Checkov is the only IaC
misconfiguration scanner; do not duplicate a Checkov IaC finding as a Trivy
misconfiguration finding.

## Coverage gaps / permissions

Use `coverage-gaps.json`, preflight logs, scanner status files, and native
logs. Call out missing GitHub permissions, unsupported endpoints, untracked
or rejected target content, renderer failures, parser errors, and any scanner
that did not run. Never describe an incomplete audit as clean.

## Recommended remediations

Order recommendations by risk and tie each one to a finding or coverage gap.
Prefer repository-level settings, workflow changes, dependency updates, or
scanner-native fixes that directly address the evidence. Keep informational
observations separate from required remediation.

## Severity guidance

Use severity from native scanner output when it is present. For GitHub
controls, use critical/high only when the observable setting creates a direct
security boundary failure (for example, write-default workflow tokens or
disabled secret push protection); otherwise use medium/low and explain the
policy context. If severity cannot be established from evidence, say so
instead of fabricating one.
