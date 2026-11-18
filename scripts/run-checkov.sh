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

# Validate Terraform module containment and Serverless collection safety.
set +e
"$trusted/scripts/validate-iac-references.sh" "$scan_root" > "$results/checkov.log" 2>&1
validation_status=$?
set -e

if ((validation_status != 0)); then
  status=2
  : > "$results/checkov-native.json"
else
  set +e
  (
      cd -- "$trusted"
      # CKV_IGNORED_DIRECTORIES is set to a sentinel rather than left empty:
      # an empty value splits to [""], and the secrets framework's exclusion
      # filter does "p in full_path", which an empty string always matches --
      # that would silently drop every file from the secrets framework.
      # validate-iac-references.sh (already run above) rejects any target
      # path colliding with this exact sentinel, since it is otherwise a
      # target-controlled evidence-suppression path of its own (an exact
      # directory-name match prunes every framework; a substring match
      # prunes the secrets framework). Keep this value identical to the one
      # there.
      env -i \
        PATH="$PATH" \
        HOME="$scan_home" \
        CKV_PARSE_ERROR_FAIL=true \
        CKV_IGNORE_HIDDEN_DIRECTORIES=false \
        CKV_IGNORED_DIRECTORIES=__segh_no_ignored_directory__ \
        CHECKOV_SERVERLESS_DISABLE_VARS=true \
        checkov --directory "$scan_root" --config-file .github/checkov.yml \
          --skip-download --skip-results-upload --output json
    ) > "$results/checkov-native.json" 2>> "$results/checkov.log"
  status=$?
  set -e

  # A successful scan must retain nonempty, parseable native evidence.
  if ((status == 0)) && ! jq -e '(type == "object") or (type == "array" and length > 0)' \
    "$results/checkov-native.json" > /dev/null 2>&1; then
    status=2
  fi
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
