# Remediation and settings ownership

`segh` is read-only. Policy results identify the owning GitHub setting:

- organization or enterprise Actions policy for Actions controls;
- repository dependency settings for dependency graph and Dependabot;
- organization rulesets, or classic branch protection where necessary, for
  pull requests, required checks, force pushes, and deletion; and
- repository or inherited community-health files for `SECURITY.md`.

Periodic findings are tied to the recorded default-branch commit in
`scan-manifest.json`. Remediate them in a normal pull request, then confirm a
later scheduled scan resolves and passes the corrected commit. Treat incomplete
coverage and scanner runtime errors as operational failures, not findings to
suppress.

Changes to scanner versions, thresholds, or exclusions belong in the protected
`dceoy/gha-for-devops` scanner source. Target repositories cannot supply those
settings.
