#!/usr/bin/env bash

set -euo pipefail
umask 077
# shellcheck source=skills/repository-security-audit/scripts/scanners/common.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/common.sh"

zizmor_files=()
run_index_selection zizmor_files \
  '.github/workflows/*.yml' '.github/workflows/*.yaml' ':(glob)**/action.yml' ':(glob)**/action.yaml'
if ((${#zizmor_files[@]} == 0)); then
  printf '%s\n' '[]' > "$output/zizmor.json"
  : > "$output/zizmor.log"
  printf '%s\n' 0 > "$output/zizmor-status.txt"
else
  set +e
  mise -C "$repo_root" exec -- zizmor --offline --no-config --no-ignores --no-exit-codes --strict-collection \
    --persona regular --min-severity medium --min-confidence high --format json "${zizmor_files[@]}" \
    > "$output/zizmor.json" 2> "$output/zizmor.log"
  zizmor_status=$?
  set -e
  printf '%s\n' "$zizmor_status" > "$output/zizmor-status.txt"
fi

