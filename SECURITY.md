# Security

Report suspected vulnerabilities privately through GitHub Security Advisories
for this repository. Do not include live GitHub App private keys, installation
tokens, repository source, or organization inventory in a public issue.

`segh` processes repository names, refs, filenames, workflow contents, scanner
output, and SARIF as untrusted data. A compromised scanner is outside the trust
boundary; install only the immutable versions in `aqua.yaml`, retain checksum
verification, and run organization scans on isolated runners with no unrelated
secrets.

Rotate the GitHub App private key and revoke installations if a key or generated
token may have reached logs, artifacts, repository content, or a scanner
environment.
