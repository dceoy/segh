# Security

Report suspected vulnerabilities privately through GitHub Security Advisories
for this repository. Do not include live GitHub App private keys, installation
tokens, repository source, or organization inventory in a public issue.

`segh` processes repository names and GitHub API responses as untrusted data.
The supplied scanner workflow also processes target repository contents and
SARIF as untrusted data. Install only the pinned scanner versions, retain Aqua
checksum verification, and give scanner jobs no unrelated secrets.

Install the SARIF publisher only on protected default branches in target
repositories, and set `SEGH_PR_SECURITY_WORKFLOW_ID` to the observed central
ruleset workflow ID. Do not enable the scanner or publisher in the central
workflow's source repository.

Rotate the GitHub App private key and revoke installations if a key or generated
token may have reached logs or artifacts. The App key is supplied only to the
token-generation action and must never reach `segh` or a scanner process.
