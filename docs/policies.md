# Policies

Version 5 policy sections are independent. A field is evaluated only when it is
present in configuration.

`source_scan` is operational configuration rather than a governance policy. It
enables scheduled static scanning and bounds matrix concurrency and each
repository's timeout. Repository inclusion remains controlled by the existing
`selectors`: archived repositories and forks are excluded by default, and must
be admitted through an explicit selector change. Target repositories cannot
override scanner enablement, versions, thresholds, configuration, or accepted
exclusions.

| Policy ID                                  | Observation                                    |
| ------------------------------------------ | ---------------------------------------------- |
| `actions.enabled`                          | GitHub Actions enabled state                   |
| `actions.allowed_actions`                  | Organization or repository action allow policy |
| `actions.default_workflow_permissions`     | Default `GITHUB_TOKEN` permission              |
| `actions.sha_pinning_enforced`             | Native full-SHA policy                         |
| `actions.fork_pr_approval`                 | Fork workflow approval policy                  |
| `dependencies.dependency_graph`            | Dependency graph availability                  |
| `dependencies.dependabot_alerts`           | Dependabot alerts enablement                   |
| `dependencies.dependabot_security_updates` | Dependabot security updates enablement         |
| `repository.ruleset`                       | Effective default-branch ruleset               |
| `repository.branch_protection`             | Ruleset or classic protection                  |
| `repository.required_pull_request`         | Pull request requirement                       |
| `repository.required_checks`               | Ordinary status-check requirement              |
| `repository.force_push_restricted`         | Force pushes prohibited                        |
| `repository.deletion_restricted`           | Branch deletion prohibited                     |
| `repository.security_md`                   | Security policy present or inherited           |
| `repository.visibility`                    | Allowed visibility                             |
| `repository.archived`                      | Archived classification prohibited             |
| `repository.fork`                          | Fork classification prohibited                 |
| `repository.template`                      | Template classification prohibited             |

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
`exempt`. An expired suppression adds an explicit failure:

```yaml
suppressions:
  - policy: repository.security_md
    repository: example-org/legacy-*
    owner: security@example.com
    rationale: Migration is tracked in the security program.
    expires: 2026-12-31T00:00:00Z
```

## Advanced configuration

`inventory.concurrency` (default `4`) and `inventory.timeout` (default `30m`,
capped at `30m`) bound organization inventory collection.
`source_scan.concurrency` (default `4`) and `source_scan.timeout` (default
`30m`, capped at `6h`) bound the periodic scan matrix once
`source_scan.enabled` is `true`. `selectors.repositories` and
`selectors.exclude` accept explicit repository full names for auditable
allow/deny lists beyond the `exclude_archived`/`exclude_disabled`/
`exclude_forks` class exclusions. These are commonly left at their defaults;
`segh.example.yaml` omits them for that reason. The embedded JSON Schema
(`schema/segh-config-v5.schema.json`) is the complete, authoritative field
reference and drives editor completion.
