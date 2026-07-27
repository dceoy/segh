# Policy and native-control mapping

`segh` reports drift; it does not mutate settings. Prefer the native or delegated
control shown below.

| Policy prefix | Preferred enforcement/remediation |
|---|---|
| `actions.default_workflow_permissions` | Organization default `GITHUB_TOKEN` permission |
| `actions.allowed_actions` | Organization allowed Actions/source policy |
| `actions.full_sha` | Renovate digest pinning, then Actions SHA-pinning enforcement |
| `actions.sha_pinning_enforced` | Organization or enterprise Actions policy |
| `actions.renovate` | Organization Renovate onboarding using the checked-in preset |
| `actions.fork_pr_approval` | Organization/repository Actions fork approval setting |
| `code_security.*` | GitHub Code Security Configuration and CodeQL default setup |
| `repository.ruleset` | Organization ruleset covering the default branch |
| `repository.branch_protection` | Prefer ruleset; repository branch protection as fallback |
| `repository.security_md` | Repository file or organization default community health file |
| classification/visibility | Organization repository policy and reviewed exception |

Every result contains repository, policy ID, status, severity, observed and
expected values, evidence source, and remediation. Suppressions require policy,
owner, rationale, optional repository glob, and optional expiry. An expired
suppression is itself a failing record and cannot exempt the original result.

For Actions, inventory distinguishes `unpinned`, `pinned_stale`,
`pinned_current`, and `pinned_freshness_unknown`. Staleness is observable only
when a full SHA has a Renovate-style version comment and the referenced tag can
be resolved. Renovate remains the update authority.

## Actions pinning rollout

1. Audit mutable references and Renovate onboarding in report-only mode.
2. Extend `local>dceoy/segh:config/renovate-preset` and merge its digest-pinning
   PRs. Renovate preserves readable comments such as `# v7.0.1`.
3. Resolve or narrowly suppress remaining findings.
4. Set `require_sha_pinning_enforcement: true` only after repositories comply,
   then enable the organization/enterprise native enforcement control.

Do not preserve compatibility with mutable Action tags.
