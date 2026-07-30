# Policy mapping

Policies compare normalized observations with explicit expected state.

| Prefix | Primary native control |
|---|---|
| `actions.*` | Organization or enterprise Actions policy |
| `code_security.*` | GitHub Security Configuration and feature APIs |
| `repository.*` | Organization rulesets or classic branch protection |

`actions.sha_pinning_enforced` audits GitHub's native SHA-pinning enforcement
state. `segh` no longer downloads and recursively parses repository workflow
files; organization Actions policy is authoritative for enforcement.

Policy status is `pass`, `fail`, `unknown`, `unsupported`, or `exempt`.
Unsupported capabilities and permission failures never become passes.

Suppressions require a policy ID, owner, rationale, and optional repository
glob and expiry. A matching unexpired suppression produces `exempt`. An expired
suppression adds an explicit failure, so temporary exceptions cannot disappear
silently.
