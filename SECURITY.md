# Security policy

Report suspected vulnerabilities privately through the repository's GitHub
security-advisory interface.

The periodic organization workflow treats every target checkout as untrusted
data. It grants only `contents: read`, uses the pinned trusted scanner from
`dceoy/gha-for-devops`, disables target-provided scanner configuration and
exclusions, installs checksum-verified scanner versions, and retains reports as
ordinary workflow artifacts.

Install organization required workflows and rulesets only from reviewed commits
on protected `main`. Keep the App private key in Actions secrets, install the
read-only inventory App on every organization repository, and run organization
audits only from a private control repository.

Periodic scan artifacts can include detected secrets and sensitive repository
paths. Keep them private, use bounded retention, and do not copy their contents
into public issues or job summaries.

Scanner gates reduce risk but do not provide pre-receive secret blocking,
CodeQL-equivalent deep SAST, or a managed security-alert lifecycle. Rotate any
committed secret immediately.
