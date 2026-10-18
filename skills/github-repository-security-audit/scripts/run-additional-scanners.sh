#!/usr/bin/env bash

set -euo pipefail
umask 077

target=$(cd -- "$1" && pwd)
output=$(cd -- "$2" && pwd)
trusted=$(cd -- "$(dirname -- "$0")/.." && pwd)
scratch=$(mktemp -d)
trap 'rm -rf -- "$scratch"' EXIT
readonly target output trusted scratch

# The disposable checkout has passed preflight. Ignore files in the target
# must not change the policy of the trusted source scanners.
while IFS= read -r -d '' file; do
  rm -f -- "$target/$file"
done < <(git -C "$target" ls-files -z -- \
  '.gitignore' ':(glob)**/.gitignore' '.semgrepignore' ':(glob)**/.semgrepignore')

set +e
mise -C "$trusted" exec --locked -- osv-scanner scan source \
  --recursive --include-git-root --config /dev/null \
  --format json "$target" \
  > "$output/osv-scanner.json" 2> "$output/osv-scanner.log"
osv_status=$?
set -e
printf '%s\n' "$osv_status" > "$output/osv-scanner-status.txt"

set +e
env -u SEMGREP_APP_TOKEN -u SEMGREP_API_TOKEN \
  SEMGREP_SEND_METRICS=off \
  mise -C "$trusted" exec --locked -- \
  uvx --from semgrep==1.180.0 semgrep scan --config p/default \
  --metrics off --disable-nosem --no-git-ignore --error --json \
  --exclude .git -- "$target" \
  > "$output/semgrep.json" 2> "$output/semgrep.log"
semgrep_status=$?
set -e
printf '%s\n' "$semgrep_status" > "$output/semgrep-status.txt"

# TruffleHog has network verification disabled. It still runs natively, so
# the absence of Docker is not a replacement for OS-level network isolation.
# Raw detector results may contain credentials: allowlist fields before writing.
set +e
mise -C "$trusted" exec --locked -- \
  trufflehog git "file://$target" --no-update --no-verification \
  --results=verified,unknown,unverified --json \
  > "$scratch/trufflehog-raw.jsonl" 2> "$scratch/trufflehog-stderr"
trufflehog_status=$?
set -e
if [[ "$trufflehog_status" -eq 0 ]]; then
  if ! jq -s '
    if all(.[]; type == "object" and (.DetectorName | type == "string")) then
      [.[] | {
        detector: .DetectorName,
        verified: (.Verified == true),
        file: (.SourceMetadata.Data.Git.file // ""),
        line: (.SourceMetadata.Data.Git.line // 0),
        commit: (.SourceMetadata.Data.Git.commit // "")
      }]
    else halt_error(1) end
  ' "$scratch/trufflehog-raw.jsonl" > "$output/trufflehog.json"; then
    trufflehog_status=2
    rm -f -- "$output/trufflehog.json"
  fi
fi
printf 'TruffleHog exit status: %s. Raw secret data was discarded.\n' \
  "$trufflehog_status" > "$output/trufflehog.log"
printf '%s\n' "$trufflehog_status" > "$output/trufflehog-status.txt"
