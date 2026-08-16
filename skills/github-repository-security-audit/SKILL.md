---
name: github-repository-security-audit
description: Audit one GitHub repository's immutable default-branch revision with pinned source scanners and read-only GitHub security controls, retaining machine-readable evidence for an agent-written report.
---

# GitHub repository security audit

Use this skill when a user asks for a focused security audit of one GitHub
repository. The audit is deliberately standalone: it does not enumerate an
organization, publish issues, modify repository settings, or reuse the
production organization workflow at runtime.

## Run the audit

From the repository containing this skill, run:

```bash
.agents/skills/github-repository-security-audit/scripts/audit.sh \
  --repo OWNER/REPO \
  --output ./security-audit
```

Omit `--repo` only when the current working directory is itself the target
repository. `gh` must be authenticated with enough read access to inspect the
repository and its security controls. The script uses `gh api --method GET`
for GitHub control requests and never writes to GitHub. The `--output`
directory must be new or empty; an existing evidence directory is rejected so
that results from separate audits cannot be mixed.

The script resolves the default branch to a lowercase 40-character commit
SHA, checks out only that detached revision with credentials and submodules
disabled, runs the locked toolchain from this directory, and stores evidence
outside the checkout. Target files are never executed. A failed preflight,
scanner, parser, renderer, API response, or evidence check must remain an
error or coverage gap; do not turn it into a pass in the report.

The first run may install the exact versions in `mise.toml`; use `--locked` as
the script does. The lockfile is skill-local so this audit does not depend on
the repository's root runtime configuration.

The pinned Checkov release provides a Darwin x86_64 binary but no Darwin
arm64 binary. On Apple Silicon macOS, the audit therefore requires Rosetta 2
for the locked Checkov tool; it fails before toolchain installation with a
clear prerequisite error when x86_64 execution is unavailable.

## Interpret the evidence

Read `summary.json`, `github-controls.json`, `coverage-gaps.json`, and the
native scanner files before writing a report. Then read:

- `references/checks.md` for the meaning of every GitHub control and its
  permission-dependent `unknown` state.
- `references/report-format.md` for the required report sections and severity
  rules.

Use native scanner evidence rather than inventing scores or thresholds:

- Scorecard is informational evidence. Its scores do not become findings.
- Checkov owns IaC misconfiguration findings. Trivy is limited to
  vulnerabilities and secrets.
- `unknown` means the control was not observable with the available
  permission or product semantics; it is a coverage gap, not evidence of
  enablement or disablement.
- `error` means evidence integrity or execution failed and the affected
  conclusion cannot be trusted.

The final report should identify the audited repository, commit SHA, critical
and high findings, medium and low findings, GitHub security controls, source
scanner results, coverage/permission gaps, and recommended remediations. Keep
the raw output directory private when it contains private repository data.
