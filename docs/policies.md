# Policy mapping

Policies compare normalized observations with explicit expected state.

| Prefix | Primary native control |
|---|---|
| `actions.*` | Organization or enterprise Actions policy |
| `code_security.configuration` | Membership in one approved GitHub Code Security Configuration |
| `repository.*` | Organization rulesets or classic branch protection |

`actions.sha_pinning_enforced` audits GitHub's native SHA-pinning enforcement
state. `segh` no longer downloads and recursively parses repository workflow
files; organization Actions policy is authoritative for enforcement.

Policy status is `pass`, `fail`, `unknown`, `unsupported`, or `exempt`.
Unsupported capabilities and permission failures never become passes.

The configured security configuration is resolved by decimal ID or exact name;
zero or multiple matches fail closed. Repository association states `attached`
and `enforced` pass. `failed`, `detached`, `removed`, and
`removed_by_enterprise` fail. Transitional `attaching` and `updating` states
produce unknown coverage. `segh` does not independently reconstruct CodeQL,
secret scanning, push protection, dependency graph, or Dependabot settings.

Suppressions require a policy ID, owner, rationale, and optional repository
glob and expiry. A matching unexpired suppression produces `exempt`. An expired
suppression adds an explicit failure, so temporary exceptions cannot disappear
silently.
