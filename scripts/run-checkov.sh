#!/usr/bin/env bash

set -euo pipefail

readonly target=${1:?target directory is required}
readonly results=${2:?results directory is required}
trusted=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
scan_root=$(mktemp -d)
scan_home=$(mktemp -d)
readonly trusted scan_root scan_home
trap 'rm -rf -- "$scan_root" "$scan_home"' EXIT

cp -a -- "$target/." "$scan_root/"
rm -rf -- "$scan_root/.git"
rm -f -- "$scan_root/.checkov.yml" "$scan_root/.checkov.yaml"
mkdir -p -- "$results"

set +e
(
  cd -- "$trusted"
  env -i \
    PATH="$PATH" \
    HOME="$scan_home" \
    CKV_PARSE_ERROR_FAIL=true \
    CHECKOV_HELM_ALLOWED_REMOTE_REPOS=none \
    CHECKOV_KUSTOMIZE_ALLOWED_REMOTE_PREFIXES=none \
    CHECKOV_ALLOW_KUSTOMIZE_FILE_EDITS=false \
    checkov --directory "$scan_root" --config-file .github/checkov.yml \
      --skip-download --skip-results-upload --output json
) > "$results/checkov-native.json" 2> "$results/checkov.log"
status=$?
set -e

# Checkov silently skips rendering a blocked remote Helm/Kustomize reference
# (exit 0, no per-report evidence); treat that as a scanner error rather than
# a clean scan.
if grep -qF -- 'Skipping helm template for' "$results/checkov.log" \
  || grep -qF -- 'Skipping kustomize build for' "$results/checkov.log"; then
  status=2
fi

# A real Checkov run always emits either the bare no-IaC summary object or a
# non-empty report list/object; empty or literal-[] stdout indicates lost
# evidence, not a clean empty scan.
if ((status == 0)) && ! jq -e '(type == "object") or (type == "array" and length > 0)' \
  "$results/checkov-native.json" > /dev/null 2>&1; then
  status=2
fi

if jq -e 'type == "object" and (.failed | type == "number") and (.parsing_errors | type == "number")' \
  "$results/checkov-native.json" > /dev/null 2>&1; then
  jq '{summary: .}' "$results/checkov-native.json" > "$results/checkov.json"
elif jq -e '.' "$results/checkov-native.json" > /dev/null 2>&1; then
  cp -- "$results/checkov-native.json" "$results/checkov.json"
else
  printf 'null\n' > "$results/checkov.json"
fi

printf '%s\n' "$status" > "$results/checkov-status.txt"
exit "$status"
