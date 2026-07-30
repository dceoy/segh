# Policies

Version 4 policy sections are independent. A field is evaluated only when it is
present in configuration.

| Policy ID | Observation |
|---|---|
| `actions.enabled` | GitHub Actions enabled state |
| `actions.allowed_actions` | Organization or repository action allow policy |
| `actions.default_workflow_permissions` | Default `GITHUB_TOKEN` permission |
| `actions.sha_pinning_enforced` | Native full-SHA policy |
| `actions.fork_pr_approval` | Fork workflow approval policy |
| `dependencies.dependency_graph` | Dependency graph availability |
| `dependencies.dependabot_alerts` | Dependabot alerts enablement |
| `dependencies.dependabot_security_updates` | Dependabot security updates enablement |
| `repository.ruleset` | Effective default-branch ruleset |
| `repository.branch_protection` | Ruleset or classic protection |
| `repository.required_pull_request` | Pull request requirement |
| `repository.required_checks` | Ordinary status-check requirement |
| `repository.force_push_restricted` | Force pushes prohibited |
| `repository.deletion_restricted` | Branch deletion prohibited |
| `repository.security_md` | Security policy present or inherited |
| `repository.visibility` | Allowed visibility |
| `repository.archived` | Archived classification prohibited |
| `repository.fork` | Fork classification prohibited |
| `repository.template` | Template classification prohibited |

The dependency controls accept boolean expectations, so they can be configured
and audited independently:

```yaml
policies:
  dependencies:
    dependency_graph: true
    dependabot_alerts: true
    dependabot_security_updates: true
```

The model has no policy IDs for CodeQL, code scanning, secret scanning, push
protection, or Security Configurations.

## Status and suppressions

Policy status is `pass`, `fail`, `unknown`, `unsupported`, or `exempt`.
Unavailable or forbidden evidence never becomes a pass.

Suppressions require a policy ID, owner, rationale, and optional repository glob
and expiry. A matching unexpired suppression changes only a failure to
`exempt`. An expired suppression adds an explicit failure.
