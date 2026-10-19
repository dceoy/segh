#!/usr/bin/env bash

set -euo pipefail

trusted=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
root=$(mktemp -d)
readonly trusted root
trap 'rm -rf -- "$root"' EXIT
mkdir -p "$root/bin" "$root/_target" "$root/results"
ln -s "$trusted" "$root/_trusted"
git -C "$root/_target" init -q
printf '%s\n' 'resource "fixture" "safe" {}' > "$root/_target/- input file.tf"
git -C "$root/_target" add -- '- input file.tf'
yq -r '.jobs.scan.steps[] | select(.id == "trivy") | .run' \
  "$trusted/.github/workflows/organization-scan.yml" > "$root/workflow.sh"
cat > "$root/bin/trivy" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
touch "$SCANNER_MARKER"
while (($#)); do
  if [[ "$1" == --output ]]; then
    printf '%s\n' '{"SchemaVersion":2,"Trivy":{},"Results":[]}' > "$2"
    break
  fi
  shift
done
STUB
cat > "$root/bin/mise" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
while [[ ${1:-} != -- ]]; do shift; done
shift
exec "$@"
STUB
chmod +x "$root/bin/trivy" "$root/bin/mise"
export PATH="$root/bin:$PATH" SCANNER_MARKER="$root/invoked"

# name | status | content | optional filename | optional diagnostic.
# Run every case through both production entry paths.
while IFS='|' read -r name expected content filename diagnostic; do
  filename=${filename:-- input file.tf}
  diagnostic=${diagnostic:-Rejected target-owned Trivy suppression directive:}
  input="$root/_target/$filename"
  mkdir -p -- "$(dirname -- "$input")"
  rm -f -- "$root/_target/- input file.tf"
  printf '%s\n' "${content//@NL@/$'\n'}" > "$input"
  git -C "$root/_target" add -- "$filename"
  for entry in workflow standalone; do
    rm -f -- "$SCANNER_MARKER"
    printf 'stale evidence\n' > "$root/results/trivy.json"
    set +e
    if [[ "$entry" == workflow ]]; then
      (cd -- "$root" && bash workflow.sh)
      status=$?
    else
      bash "$trusted/skills/repository-security-audit/scripts/scanners/trivy.sh" "$root/_target" "$root/results"
      status=$(cat "$root/results/trivy-status.txt")
    fi
    set -e
    [[ "$status" == "$expected" ]] || { printf 'Failed %s/%s: %s\n' "$entry" "$name" "$status" >&2; exit 1; }
    if [[ "$expected" == 2 ]]; then
      [[ ! -e "$SCANNER_MARKER" && ! -s "$root/results/trivy.json" ]]
      grep -F "$diagnostic" "$root/results/trivy.log" > /dev/null
    else
      [[ -e "$SCANNER_MARKER" ]]
      jq -e '.Results == []' "$root/results/trivy.json" > /dev/null
    fi
    printf 'passed %s/%s\n' "$entry" "$name"
  done
  git -C "$root/_target" rm -qf -- "$filename"
done <<'CASES'
clean|0|resource "fixture" "safe" {}
hash|2|# trivy:ignore:AVD-TEST
compact|2|#trivy:ignore:*
legacy|2|#tfsec:ignore:*
slash|2|//trivy:ignore:*
block|2|/* tfsec:ignore:* */
trailing|2|value = true # trivy:ignore:*
bare|2|trivy:ignore:*
reordered|2|#trivy:exp:2221-01-02:ignore:*
conditional|2|#tfsec:ignore:AVD-TEST[port=443]
http|2|module "remote" { source = "http://169.254.169.254/module.zip" }|- input file.tf|Rejected target-owned Trivy Terraform module declaration:
git|2|module "remote" { source = "git::https://example.invalid/module.git" }|nested/file with spaces.tf|Rejected target-owned Trivy Terraform module declaration:
registry|2|module "remote" { source = "hashicorp/consul/aws" }||Rejected target-owned Trivy Terraform module declaration:
local|2|module "local" { source = "./child" }||Rejected target-owned Trivy Terraform module declaration:
escape|2|module "local" { source = "../outside" }||Rejected target-owned Trivy Terraform module declaration:
absolute|2|module "local" { source = "/tmp/outside" }||Rejected target-owned Trivy Terraform module declaration:
computed|2|module "remote" { source = var.remote }||Rejected target-owned Trivy Terraform module declaration:
comments|2|module /* } */ "remote" /* { */ { source = "https://example.invalid/a.zip" }||Rejected target-owned Trivy Terraform module declaration:
heredoc|2|locals {@NL@text = <<EOT@NL@} module fake {@NL@EOT@NL@}@NL@module "remote" { source = "https://example.invalid/a.zip" }||Rejected target-owned Trivy Terraform module declaration:
overwrite|2|module "remote" { source = "https://example.invalid/a.zip" }@NL@module = null||Rejected target-owned Trivy Terraform module declaration:
tofu|2|module "remote" { source = "https://example.invalid/a.zip" }|nested/main.tofu|Rejected target-owned Trivy Terraform module declaration:
json|2|{"module":{"remote":{"source":"https://example.invalid/a.zip"}}}|main.tf.json|Rejected target-owned Trivy Terraform module declaration:
escaped-json|2|{"mod\u0075le":{"remote":{"source":"https://example.invalid/a.zip"}}}|main.tofu.json|Rejected target-owned Trivy Terraform module declaration:
duplicate-json|2|{"module":{"remote":{"source":"https://example.invalid/a.zip"}},"module":null}|main.tf.json|Rejected target-owned Trivy Terraform module declaration:
clean-tofu|0|resource "fixture" "safe" {}|main.tofu
clean-json|0|{"resource":{"fixture":{"safe":{}}}}|main.tf.json
clean-tofu-json|0|{"resource":{"fixture":{"safe":{}}}}|main.tofu.json
broken-hcl|2|module "remote" {|main.tf|Unable to parse Trivy Terraform input:
broken-json|2|{"module":|main.tf.json|Unable to inspect Trivy Terraform input:
array-json|2|[]|main.tofu.json|Unable to inspect Trivy Terraform input:
multiple-json|2|{} {}|main.tf.json|Unable to inspect Trivy Terraform input:
CASES

# A failed parser must not become a clean scan.
printf '%s\n' 'resource "fixture" "safe" {}' > "$root/_target/- input file.tf"
git -C "$root/_target" add -- '- input file.tf'
cat > "$root/bin/hcl2json" <<'STUB'
#!/usr/bin/env bash
exit 42
STUB
chmod +x "$root/bin/hcl2json"
set +e
"$trusted/skills/repository-security-audit/scripts/validate-trivy-directives.sh" "$root/_target" > "$root/error.log" 2>&1
status=$?
set -e
[[ "$status" == 2 ]]
grep -F 'Unable to parse Trivy Terraform input:' "$root/error.log" > /dev/null
rm -- "$root/bin/hcl2json"

# The standalone dispatcher deliberately removes tracked ignore policies.
mkdir -p "$root/_target/nested"
for policy in .gitignore .semgrepignore nested/.gitignore nested/.semgrepignore; do
  printf '%s\n' '*.ignored-fixture' > "$root/_target/$policy"
  git -C "$root/_target" add -- "$policy"
  rm -- "$root/_target/$policy"
done
printf '%s\n' 'resource "fixture" "safe" {}' > "$root/_target/- input file.tf"
"$trusted/skills/repository-security-audit/scripts/validate-trivy-directives.sh" "$root/_target"

# Enumeration and read failures must not become clean scans.
real_git=$(command -v git)
export REAL_GIT="$real_git"
cat > "$root/bin/git" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
if [[ ${3:-} == ls-files ]]; then exit 42; fi
exec "$REAL_GIT" "$@"
STUB
chmod +x "$root/bin/git"
set +e
"$trusted/skills/repository-security-audit/scripts/validate-trivy-directives.sh" "$root/_target" > "$root/error.log" 2>&1
status=$?
set -e
[[ "$status" == 2 ]]
grep -F 'Unable to enumerate' "$root/error.log" > /dev/null
rm -- "$root/bin/git" "$root/_target/- input file.tf"
set +e
"$trusted/skills/repository-security-audit/scripts/validate-trivy-directives.sh" "$root/_target" > "$root/error.log" 2>&1
status=$?
set -e
[[ "$status" == 2 ]]
grep -F 'Unable to inspect' "$root/error.log" > /dev/null
printf 'Trivy suppression boundary tests passed\n'
