#!/usr/bin/env bash

set -euo pipefail
umask 077
# shellcheck source=skills/github-repository-security-audit/scripts/scanners/common.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/common.sh"

run_trivy() {
  local file_kind=$1 scanner_kind=$2
  local output_file="$output/trivy-$file_kind.json"
  local -a trivy_env=()
  local variable
  for variable in "${!TRIVY_@}"; do
    trivy_env+=(-u "$variable")
  done
  set +e
  env "${trivy_env[@]}" mise -C "$skill_root" exec --locked -- trivy filesystem --config /dev/null --ignorefile /dev/null \
    --scanners "$scanner_kind" --exit-code 1 --format json --output "$output_file" \
    --skip-dirs "$checkout/.git" --skip-version-check "$checkout" \
    > "$output/trivy-$file_kind.log" 2>&1
  local status=$?
  set -e
  printf '%s\n' "$status" > "$output/trivy-$file_kind-status.txt"
}

run_trivy vulnerability vuln
run_trivy secret secret

