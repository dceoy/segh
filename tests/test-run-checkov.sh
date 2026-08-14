#!/usr/bin/env bash

set -euo pipefail

readonly runner=${1:-scripts/run-checkov.sh}
root=$(mktemp -d)
readonly root
trap 'rm -rf "$root"' EXIT

command -v checkov > /dev/null
command -v helm > /dev/null
command -v kubectl > /dev/null
command -v yq > /dev/null
command -v hcl2json > /dev/null

sentinel_bin="$root/sentinel-bin"
mkdir -p "$sentinel_bin"
cat > "$sentinel_bin/checkov" <<STUB
#!/usr/bin/env bash
touch "$root/checkov-invoked.marker"
exit 0
STUB
chmod +x "$sentinel_bin/checkov"

# Every hostile fixture below must be rejected before Checkov (or any
# Helm/Kustomize renderer it would invoke) ever runs, regardless of which
# reference form Checkov's own blocked-remote-repo detection would or would
# not classify as remote.
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

assert_blocked_before_checkov tests/fixtures/iac-remote-helm remote-helm
assert_blocked_before_checkov tests/fixtures/iac-remote-kustomize remote-kustomize
assert_blocked_before_checkov tests/fixtures/iac-oci-helm oci-helm
assert_blocked_before_checkov tests/fixtures/iac-escape-helm escape-helm
assert_blocked_before_checkov tests/fixtures/iac-scp-kustomize scp-kustomize
assert_blocked_before_checkov tests/fixtures/iac-absolute-kustomize absolute-kustomize
assert_blocked_before_checkov tests/fixtures/iac-scp-kustomize-crds scp-kustomize-crds
assert_blocked_before_checkov tests/fixtures/iac-absolute-kustomize-crds absolute-kustomize-crds

# A local Helm chart that Checkov's own `helm template --dependency-update`
# cannot render cleanly, and a local Kustomization that `kubectl kustomize`
# cannot build, must both be caught before Checkov runs: Checkov itself
# treats these as "no report" (Helm) or ignores the renderer's exit status
# and stderr entirely (Kustomize), silently losing evidence rather than
# reporting a scanner error.
assert_blocked_before_checkov tests/fixtures/iac-invalid-helm invalid-helm
assert_blocked_before_checkov tests/fixtures/iac-invalid-kustomize invalid-kustomize

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

results="$root/valid-fixtures"
"$runner" tests/fixtures/iac "$results" > "$root/valid-fixtures.log" 2>&1 || true
[[ "$(cat "$results/checkov-status.txt")" == 1 ]]

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

# Helm 4.2.3 validates values.schema.json by default and its JSON-schema
# compiler resolves file:/http:/https: $ref loaders with no containment
# check; Checkov invokes `helm template` itself, so this must be fixed for
# both the pre-render check and Checkov's own invocation. Point a chart's
# schema $ref at a FIFO outside the scan root: if either Helm invocation
# actually resolves it, the read blocks forever and the run times out; with
# --skip-schema-validation forced, schema resolution never happens and the
# run completes normally.
helm_schema_leak_dir="$root/helm-schema-leak"
mkdir -p "$helm_schema_leak_dir/templates"
schema_fifo="$root/helm-schema-leak.json"
mkfifo "$schema_fifo"
cat > "$helm_schema_leak_dir/Chart.yaml" <<EOF
apiVersion: v2
name: schema-leak
version: 0.1.0
EOF
cat > "$helm_schema_leak_dir/values.schema.json" <<EOF
{"\$ref": "file://$schema_fifo"}
EOF
cat > "$helm_schema_leak_dir/templates/pod.yaml" <<'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: test
EOF
results="$root/helm-schema-leak-results"
if ! timeout 20 "$runner" "$helm_schema_leak_dir" "$results" > "$root/helm-schema-leak.log" 2>&1; then
  runner_status=$?
  if ((runner_status == 124)); then
    echo 'run-checkov.sh let Helm block resolving a values.schema.json ref outside the scan root' >&2
    cat "$root/helm-schema-leak.log" >&2
    exit 1
  fi
fi
[[ "$(cat "$results/checkov-status.txt")" == 1 ]]

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
