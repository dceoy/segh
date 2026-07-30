# Remediation and settings ownership

`segh` is read-only. Policy results identify the owning GitHub setting:

- organization or enterprise Actions policy for Actions controls;
- repository dependency settings for dependency graph and Dependabot;
- organization rulesets, or classic branch protection where necessary, for
  pull requests, required checks, force pushes, and deletion; and
- repository or inherited community-health files for `SECURITY.md`.

Merge-time scanner findings are remediated in the pull-request branch. Full
machine and human reports remain in the `pr-security-reports` artifact. A
ruleset exception or policy suppression should be narrow, owned, justified, and
time-bounded.

Changes to scanner versions, thresholds, or exclusions belong in the protected
central `segh` repository. Target pull requests cannot supply those settings.
