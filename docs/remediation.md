# Remediation and settings ownership

`segh remediate --audit ...` produces a grouped plan and never writes GitHub
settings. Code Security Configurations, Actions policy, and branch governance
belong to GitHub-native organization or enterprise controls.

Safe Settings is justified only when a required setting is not expressible
through Code Security Configurations, organization/enterprise Actions policy,
or organization rulesets, and when the organization accepts another privileged
controller. Do not introduce Safe Settings merely to duplicate a native
control. If adopted, keep a reviewed declarative repository, dry-run changes,
narrow repository selectors, audit every mutation, and document rollback.

There is intentionally no settings `apply` mode in this version. Adding one
requires a separate design with an explicit command flag, dry-run output,
least-privilege write installation, immutable configuration revision, narrow
selectors, audit log, approval boundary, and tested rollback. A scheduled audit
must never silently become a settings mutation.
