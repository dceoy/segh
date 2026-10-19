---
name: repository-security-audit
description: Audit one GitHub repository's immutable default-branch revision with repository-managed source scanners and read-only GitHub security controls, retaining machine-readable evidence for an agent-written report.
---

# GitHub repository security audit

Use this skill when a user asks for a focused security audit of one GitHub
repository. The audit is deliberately standalone: it does not enumerate an
organization, publish issues, modify repository settings, or reuse the
production organization workflow at runtime.

## Run the audit

From the repository containing this skill, run:

```bash
.agents/skills/repository-security-audit/scripts/audit.sh \
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
disabled, runs the skill-local mise toolchain, and stores evidence
outside the checkout. Target files are never executed. A failed preflight,
scanner, parser, renderer, API response, or evidence check must remain an
error or coverage gap; do not turn it into a pass in the report.

The detached checkout is kept under the audit's private temporary directory
and removed when the audit exits. The clone fetches complete Git history,
including historical blobs, so TruffleHog can scan past commits after the
remote has been removed. This can increase download size for large
repositories; incomplete Git history must not count as a clean secret scan.
Git operations after cloning ignore system and global configuration,
including environment-injected configuration parameters, before
target-controlled attributes can select filters.

The first run may install the current latest tool versions declared in the
skill-local `mise.toml`, independently of the host repository's mise configuration.
`MISE_CEILING_PATHS` prevents loading host project-level configs. No `mise.lock` is used. The resulting tool versions are captured in
`scanner-versions.txt` because subsequent audits may resolve newer releases.

The entry point `audit.sh` handles GitHub controls, the checkout/preflight
boundary, evidence interpretation, and summary generation. **All native source scanner commands** are dispatched by
`scripts/run-scanners.sh` to one tool-specific entry point in `scripts/scanners/`.
The Checkov and ShellCheck entries retain their trusted policy enforcement;
shared Git index selection lives in `scripts/scanners/common.sh`. Scanner findings and execution failures are recorded
separately so that incomplete coverage cannot appear clean.

The skill additionally runs **OSV-Scanner** for dependency vulnerabilities,
**Semgrep OSS** for SAST, and **TruffleHog** for Git-history secrets.
All three tools are executed natively; OSV-Scanner, TruffleHog and uv
(the `uvx` runner for pinned Semgrep) are installed from the skill-local
`mise.toml` with `latest` version selectors. Docker is not required.
Missing or incompatible executables are audit errors, not silent skips.
OSV's vulnerability feed and Semgrep's rule registry require network access.

TruffleHog disables both verification and updates. Its findings are
unverified candidates. Native execution does not provide network isolation;
use an externally restricted host when strict offline scanning is required.
Raw secret values are discarded, and only detector, file, line and commit
metadata are retained.
Temporary checkout ignore files are removed before these extra scanners
so that target-owned ignore directives cannot suppress their coverage.

The audit currently requires Rosetta 2 on Apple Silicon macOS for the
Darwin x86_64 Checkov binary; it fails before toolchain installation when
x86_64 execution is unavailable.

ShellCheck runs through the skill-local trusted wrapper. It removes external
source loading and rejects target-owned ShellCheck directives so target files
cannot change the scanner's analysis policy.

## Interpret the evidence

Read `summary.json`, `github-controls.json`, `coverage-gaps.json`, and the
native scanner files before writing a report. Then read:

- `references/checks.md` for the meaning of every GitHub control and its
  permission-dependent `unknown` state.
- `references/report-format.md` for the required report sections and severity
  rules.

Use native scanner evidence rather than inventing scores or thresholds:

- Scorecard is informational evidence. Its scores do not become findings.
- Checkov and Trivy both report IaC misconfigurations independently; Trivy
  runs vulnerability, secret, and misconfiguration scans in one invocation.
  Target-owned Trivy inline suppression directives (including legacy tfsec aliases)
  are rejected as scanner errors; conservative matching can also reject directive-shaped
  documentation or string literals. Terraform/OpenTofu module declarations (including
  local modules) in `.tf`, `.tofu`, `.tf.json`, and `.tofu.json` are also rejected before
  Trivy runs, preventing target-controlled module downloads. Unparseable configurations
  fail closed. These cases leave all three Trivy categories as errors, not clean scans.
  Cross-tool overlaps are possible and must not be described as distinct
  confirmed vulnerabilities without inspecting their native evidence.
- OSV-Scanner reports vulnerable dependency versions. Exit code 128 means no
  supported dependencies were detected (`skipped`), not a clean scan.
- Semgrep uses the trusted `p/default` rules with telemetry disabled.
- TruffleHog findings are **unverified** Git-history secret candidates;
  never present them as confirmed live credentials.
- `unknown` means the control was not observable with the available
  permission or product semantics; it is a coverage gap, not evidence of
  enablement or disablement.
- `error` means evidence integrity or execution failed and the affected
  conclusion cannot be trusted.

The final report should identify the audited repository, commit SHA, critical
and high findings, medium and low findings, GitHub security controls, source
scanner results, coverage/permission gaps, and recommended remediations. Keep
the raw output directory private when it contains private repository data.
