# Security policy

Report suspected vulnerabilities privately through the repository's GitHub
security-advisory interface.

The central pull-request workflow treats the target checkout as untrusted data.
It grants only `contents: read`, disables target-provided scanner
configuration and ignore files, installs checksum-verified scanner versions,
and retains reports as ordinary workflow artifacts.

Install organization required workflows and rulesets only from reviewed commits
on protected `main`. Keep the App private key in Actions secrets, install the
read-only inventory App on every organization repository, and run organization
audits only from a private control repository.

Scanner gates reduce risk but do not provide pre-receive secret blocking,
CodeQL-equivalent deep SAST, or a managed security-alert lifecycle. Rotate any
secret committed to Git immediately even when a pull-request check catches it.
