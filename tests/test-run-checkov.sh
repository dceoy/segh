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
