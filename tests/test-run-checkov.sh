#!/usr/bin/env bash

set -euo pipefail

readonly runner=${1:-scripts/run-checkov.sh}
root=$(mktemp -d)
readonly root
trap 'rm -rf "$root"' EXIT

command -v checkov > /dev/null
command -v helm > /dev/null
command -v kubectl > /dev/null

results="$root/remote-helm"
if "$runner" tests/fixtures/iac-remote-helm "$results" > "$root/remote-helm.log" 2>&1; then
  echo 'run-checkov.sh accepted a blocked remote Helm dependency' >&2
  cat "$root/remote-helm.log" >&2
  exit 1
fi
[[ "$(cat "$results/checkov-status.txt")" == 2 ]]
grep -F 'Skipping helm template for' "$results/checkov.log" > /dev/null

results="$root/remote-kustomize"
if "$runner" tests/fixtures/iac-remote-kustomize "$results" > "$root/remote-kustomize.log" 2>&1; then
  echo 'run-checkov.sh accepted a blocked remote Kustomize reference' >&2
  cat "$root/remote-kustomize.log" >&2
  exit 1
fi
[[ "$(cat "$results/checkov-status.txt")" == 2 ]]
grep -F 'Skipping kustomize build for' "$results/checkov.log" > /dev/null

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
