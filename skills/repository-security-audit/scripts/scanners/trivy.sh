#!/usr/bin/env bash

set -euo pipefail
umask 077
# shellcheck source=skills/repository-security-audit/scripts/scanners/common.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/common.sh"

trivy_env=()
for variable in "${!TRIVY_@}"; do
  trivy_env+=(-u "$variable")
done

set +e
env "${trivy_env[@]}" mise -C "$repo_root" exec -- trivy filesystem --config /dev/null --ignorefile /dev/null \
  --scanners vuln,secret,misconfig --exit-code 1 --format json --output "$output/trivy.json" \
  --skip-dirs "$checkout/.git" --skip-version-check --disable-telemetry "$checkout" \
  > "$output/trivy.log" 2>&1
status=$?
set -e
printf '%s\n' "$status" > "$output/trivy-status.txt"
