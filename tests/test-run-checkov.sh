#!/usr/bin/env bash

set -euo pipefail

readonly runner=${1:-scripts/run-checkov.sh}
root=$(mktemp -d)
readonly root
trap 'rm -rf "$root"' EXIT

command -v checkov > /dev/null
command -v hcl2json > /dev/null

sentinel_bin="$root/sentinel-bin"
mkdir -p "$sentinel_bin"
cat > "$sentinel_bin/checkov" <<STUB
#!/usr/bin/env bash
touch "$root/checkov-invoked.marker"
exit 0
STUB
chmod +x "$sentinel_bin/checkov"

# Unsafe Terraform/Serverless sources must be rejected before Checkov runs.
assert_blocked_before_checkov() {
  local fixture=$1 name=$2
  rm -f -- "$root/checkov-invoked.marker"
  local results="$root/$name"
  if PATH="$sentinel_bin:$PATH" "$runner" "$fixture" "$results" > "$root/$name.log" 2>&1; then
    echo "run-checkov.sh accepted a hostile fixture: $fixture" >&2
    cat "$root/$name.log" >&2
    exit 1
  fi
  [[ "$(cat "$results/checkov-status.txt")" == 2 ]]
  [[ ! -e "$root/checkov-invoked.marker" ]]
}

# Checkov's Terraform LocalPathLoader accepts any module source starting
# with "./", "../", or "/" and is never skipped by download-external-modules:
# false (that only gates loaders marked external). Both an absolute and an
# escaping relative local module source must be rejected before Checkov runs.
assert_blocked_before_checkov tests/fixtures/iac-terraform-escape-module terraform-escape-module
assert_blocked_before_checkov tests/fixtures/iac-terraform-absolute-module terraform-absolute-module

# A line-based brace counter would be fooled by braces inside an HCL comment
# or heredoc, letting a hostile module source escape module-scope detection.
# Parsing real HCL (hcl2json) must not be fooled by either.
assert_blocked_before_checkov tests/fixtures/iac-terraform-comment-bypass-module terraform-comment-bypass-module
assert_blocked_before_checkov tests/fixtures/iac-terraform-heredoc-bypass-module terraform-heredoc-bypass-module

# Checkov's Terraform parser loads module blocks from ".hcl" files, not only
# ".tf" files, so the same containment check must cover both extensions.
assert_blocked_before_checkov tests/fixtures/iac-terraform-hcl-escape-module terraform-hcl-escape-module

# Checkov's Serverless collector hard-codes an unconditional node_modules
# exclusion independent of CKV_IGNORED_DIRECTORIES, so a tracked
# serverless.yml under node_modules would otherwise be silently invisible
# with no error at all.
assert_blocked_before_checkov tests/fixtures/iac-serverless-node-modules serverless-node-modules

# The CKV_IGNORED_DIRECTORIES sentinel run-checkov.sh sets is public (it
# lives in this repository), so a target path deliberately named after it
# would otherwise silently prune evidence: an exact directory-name match
# prunes every framework, and a substring match prunes the secrets
# framework specifically. Both must be rejected before Checkov ever runs.
assert_blocked_before_checkov tests/fixtures/iac-ignored-directories-sentinel-exact ignored-directories-sentinel-exact
assert_blocked_before_checkov tests/fixtures/iac-ignored-directories-sentinel-substring ignored-directories-sentinel-substring

results="$root/valid-fixtures"
"$runner" tests/fixtures/iac "$results" > "$root/valid-fixtures.log" 2>&1 || true
[[ "$(cat "$results/checkov-status.txt")" == 1 ]]

# CKV_IGNORED_DIRECTORIES left empty splits to [""], which the secrets
# framework's exclusion filter treats as matching every path -- that would
# silently scan zero files. Confirm the dummy key fixture is still detected.
jq -e '[if type == "array" then .[] else . end
  | select(.check_type == "secrets") | .summary.failed] | add // 0 | . > 0' \
  "$results/checkov-native.json" > /dev/null

# Kubernetes-related frameworks remain excluded even when fixtures contain manifests.
jq -e '[if type == "array" then .[] else . end
  | select(.check_type == "argo_workflows" or .check_type == "helm" or
           .check_type == "kubernetes" or .check_type == "kustomize")] | length == 0' \
  "$results/checkov-native.json" > /dev/null

# A tracked GitHub Actions workflow must be scanned too (Checkov's
# github_actions runner is unaffected by CKV_IGNORE_HIDDEN_DIRECTORIES; this
# only confirms the framework itself ran and produced check results).
jq -e '[if type == "array" then .[] else . end
  | select(.check_type == "github_actions")
  | (.summary.failed // 0) + (.summary.passed // 0)] | add // 0 | . > 0' \
  "$results/checkov-native.json" > /dev/null

# A tracked resource under a dot-prefixed directory must still be scanned:
# Checkov 3.3.9 ignores hidden directories by default, and run-checkov.sh
# must override that default rather than silently dropping the evidence.
results="$root/hidden-fixture"
"$runner" tests/fixtures/iac-hidden "$results" > "$root/hidden-fixture.log" 2>&1 || true
[[ "$(cat "$results/checkov-status.txt")" == 1 ]]
jq -e '[if type == "array" then .[] else . end
  | select(.check_type == "terraform")
  | .results.failed_checks[]?
  | select(.resource == "aws_security_group.hidden")] | length > 0' \
  "$results/checkov-native.json" > /dev/null

# A tracked resource under node_modules must still be scanned: Checkov 3.3.9
# unconditionally ignores directory basenames listed in CKV_IGNORED_DIRECTORIES
# (default node_modules,.terraform,.serverless), independent of
# CKV_IGNORE_HIDDEN_DIRECTORIES, and run-checkov.sh must override that
# default too rather than silently dropping the evidence.
results="$root/ignored-directories-fixture"
"$runner" tests/fixtures/iac-ignored-directories "$results" > "$root/ignored-directories-fixture.log" 2>&1 || true
[[ "$(cat "$results/checkov-status.txt")" == 1 ]]
jq -e '[if type == "array" then .[] else . end
  | select(.check_type == "terraform")
  | .results.failed_checks[]?
  | select(.resource == "aws_security_group.ignored_dir")] | length > 0' \
  "$results/checkov-native.json" > /dev/null

# A contained local Terraform module (source resolves inside the scan root)
# must still be scanned normally.
results="$root/terraform-local-module"
"$runner" tests/fixtures/iac-terraform-local-module "$results" > "$root/terraform-local-module.log" 2>&1 || true
[[ "$(cat "$results/checkov-status.txt")" == 1 ]]
jq -e '[if type == "array" then .[] else . end
  | select(.check_type == "terraform")
  | .results.failed_checks[]?
  | select(.resource == "module.nested.aws_security_group.example")] | length > 0' \
  "$results/checkov-native.json" > /dev/null

# A module block in a contained local ".hcl" file (not just ".tf") must also
# still be scanned normally, not merely rejected when hostile.
results="$root/terraform-hcl-local-module"
"$runner" tests/fixtures/iac-terraform-hcl-local-module "$results" > "$root/terraform-hcl-local-module.log" 2>&1 || true
[[ "$(cat "$results/checkov-status.txt")" == 1 ]]
jq -e '[if type == "array" then .[] else . end
  | select(.check_type == "terraform")
  | .results.failed_checks[]?
  | select(.resource == "module.nested.aws_security_group.hcl_module_example")] | length > 0' \
  "$results/checkov-native.json" > /dev/null

# Checkov's Serverless parser resolves `${file(...)}` by default with no
# containment check on the path. Point it at a FIFO outside the scan root:
# if Checkov actually opens it, the read blocks forever and the run times
# out; with CHECKOV_SERVERLESS_DISABLE_VARS=true the resolution is skipped
# and the run completes normally.
serverless_leak_dir="$root/serverless-leak"
mkdir -p "$serverless_leak_dir"
fifo="$root/serverless-leak.yaml"
mkfifo "$fifo"
cat > "$serverless_leak_dir/serverless.yml" <<EOF
service: leak-test
provider:
  name: aws
custom:
  leaked: \${file($fifo)}
functions:
  hello:
    handler: handler.hello
EOF
results="$root/serverless-leak-results"
if ! timeout 20 "$runner" "$serverless_leak_dir" "$results" > "$root/serverless-leak.log" 2>&1; then
  runner_status=$?
  if ((runner_status == 124)); then
    echo 'run-checkov.sh let Checkov block reading a serverless file() reference outside the scan root' >&2
    cat "$root/serverless-leak.log" >&2
    exit 1
  fi
fi
[[ "$(cat "$results/checkov-status.txt")" == 0 ]]

stub_bin="$root/stub-bin"
mkdir -p "$stub_bin"

cat > "$stub_bin/checkov" <<'STUB'
#!/usr/bin/env bash
exit 0
STUB
chmod +x "$stub_bin/checkov"
results="$root/empty-stdout"
if PATH="$stub_bin:$PATH" "$runner" tests/fixtures/iac "$results" > "$root/empty-stdout.log" 2>&1; then
  echo 'run-checkov.sh accepted exit 0 with empty stdout as a clean scan' >&2
  cat "$root/empty-stdout.log" >&2
  exit 1
fi
[[ "$(cat "$results/checkov-status.txt")" == 2 ]]

cat > "$stub_bin/checkov" <<'STUB'
#!/usr/bin/env bash
printf '[]\n'
exit 0
STUB
chmod +x "$stub_bin/checkov"
results="$root/literal-empty-array"
if PATH="$stub_bin:$PATH" "$runner" tests/fixtures/iac "$results" > "$root/literal-empty-array.log" 2>&1; then
  echo 'run-checkov.sh accepted a literal [] as a clean empty scan' >&2
  cat "$root/literal-empty-array.log" >&2
  exit 1
fi
[[ "$(cat "$results/checkov-status.txt")" == 2 ]]

printf 'run-checkov.sh fail-closed tests passed\n'
