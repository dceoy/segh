#!/usr/bin/env bash

set -euo pipefail
umask 077
# shellcheck source=skills/github-repository-security-audit/scripts/scanners/common.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/common.sh"

actionlint_files=()
run_index_selection actionlint_files '.github/workflows/*.yml' '.github/workflows/*.yaml'
if ((${#actionlint_files[@]} == 0)); then
  : > "$output/actionlint.jsonl"
  : > "$output/actionlint.log"
  printf '%s\n' 0 > "$output/actionlint-status.txt"
else
  set +e
  env -u SHELLCHECK_OPTS mise -C "$skill_root" exec --locked -- actionlint --no-color --config-file /dev/null \
    --shellcheck "$skill_root/scripts/scanners/shellcheck.sh" --format '{{json .}}' "${actionlint_files[@]}" \
    > "$output/actionlint.jsonl" 2> "$output/actionlint.log"
  actionlint_status=$?
  set -e
  printf '%s\n' "$actionlint_status" > "$output/actionlint-status.txt"
fi

