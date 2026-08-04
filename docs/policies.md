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
| `dependencies.lock_file`                   | Dependency manifest missing its lock/checksum file |
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

### Dependency lock files

`policies.dependencies.lock_files` is opt-in and off by default:

```yaml
policies:
  dependencies:
    lock_files: true
```

When enabled, `segh audit` fetches each selected repository's default-branch
file tree and, for the manifest kinds in the table below, reports a manifest
that declares dependencies but has no lock/checksum file beside it or at its
workspace/monorepo root. A manifest with no declared dependencies, or beside
an existing lock file, produces no result at all.

| Manifest         | Accepted lock/checksum files                                                   |
| ---------------- | -------------------------------------------------------------------------------- |
| `package.json`    | `package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`, `yarn.lock`, `bun.lock`, `bun.lockb` |
| `pyproject.toml`  | `uv.lock`, `poetry.lock`, `pdm.lock`                                              |
| `Pipfile`         | `Pipfile.lock`                                                                    |
| `Cargo.toml`      | `Cargo.lock`                                                                      |
| `go.mod`          | `go.sum`                                                                          |
| `Gemfile`         | `Gemfile.lock`                                                                    |
| `composer.json`   | `composer.lock`                                                                   |
| `mix.exs`         | `mix.lock`                                                                        |
| `pubspec.yaml`    | `pubspec.lock`                                                                    |
| `*.tf` (per directory) | `.terraform.lock.hcl`                                                       |
| `flake.nix`       | `flake.lock`                                                                      |

Each result carries `warning` or `notice` status instead of `pass`/`fail`, so
this check never fails the audit by itself: `notice` is used where the
ecosystem's own convention makes omitting the lock file a normal choice for a
published library (a Python or Rust package, for example), refined using a
signal the manifest itself provides where one exists (`composer.json`'s
`"type": "library"`, or whether a Go module has a `main.go`). `notice` is also
used when a repository's tree could not be evaluated (fetch failure or a
truncated tree response), so a lock-file evaluation gap is visible without
being treated as a policy violation. The remediation text names the expected
lock file and, where it can be inferred safely (the Node.js package manager
from a `packageManager` field or workspace config file; the Python tool from
`pyproject.toml`'s own `[tool.poetry]`/`[tool.pdm]` tables), a generation
command; segh never runs that command or generates a lock file itself.
`dependencies.lock_file` accepts the same repository-scoped suppressions as
any other policy.

## Status and suppressions

Policy status is `pass`, `fail`, `unknown`, `unsupported`, `exempt`, `warning`,
or `notice`. Unavailable or forbidden evidence never becomes a pass. Only
`fail` counts toward exit-code violations, and only `unknown`/`unsupported`
count toward partial coverage; `warning` and `notice` are informational and
change neither.

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
`source_scan.concurrency` (default `4`) bounds the periodic scan matrix's
parallelism once `source_scan.enabled` is `true`; each matrix repository's
scan duration is bounded by the pinned upstream reusable workflow instead of
a `segh` configuration field. `selectors.repositories` and
`selectors.exclude` accept explicit repository full names for auditable
allow/deny lists beyond the `exclude_archived`/`exclude_disabled`/
`exclude_forks` class exclusions. These are commonly left at their defaults;
`segh.example.yaml` omits them for that reason. The embedded JSON Schema
(`schema/segh-config-v5.schema.json`) is the complete, authoritative field
reference and drives editor completion.
