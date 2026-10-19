#!/usr/bin/env bash

set -euo pipefail
umask 077

readonly repo=${1:?repository is required}
readonly commit_sha=${2:?commit SHA is required}
checkout=$(cd -- "${3:?checkout is required}" && pwd)
output=$(cd -- "${4:?evidence directory required}" && pwd)
skill_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
readonly checkout output skill_root
export MISE_CEILING_PATHS="$(dirname -- "$skill_root")"

# The checkout passed preflight. Target-owned ignore rules must not
# suppress the native scanners. Only this disposable checkout is modified.
while IFS= read -r -d '' file; do
  rm -f -- "$checkout/$file"
done < <(git -C "$checkout" ls-files -z -- \
  '.gitignore' ':(glob)**/.gitignore' '.semgrepignore' ':(glob)**/.semgrepignore')


runner_status=0
for scanner in scorecard zizmor actionlint shellcheck checkov trivy osv-scanner semgrep trufflehog; do
  args=("$checkout" "$output" "$repo" "$commit_sha")
  if [[ "$scanner" == shellcheck ]]; then
    args=(--audit-scan "${args[@]}")
  fi
  set +e
  mise -C "$skill_root" exec -- \
    bash "$skill_root/scripts/scanners/$scanner.sh" "${args[@]}" \
    > "$output/$scanner-run.log" 2>&1
  status=$?
  set -e
  if [[ "$scanner" == checkov ]]; then
    # Checkov exits nonzero for findings. Its native status is interpreted
    # by audit.sh, not by the orchestration loop.
    printf '%s\n' "$status" > "$output/checkov-invocation-status.txt"
  elif ((status != 0)); then
    printf 'Scanner %s runner failed (%s)\n' "$scanner" "$status" >&2
    runner_status=1
  fi
done
exit "$runner_status"
