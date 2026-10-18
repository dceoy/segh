#!/usr/bin/env bash

set -euo pipefail
umask 077

target=$(cd -- "$1" && pwd)
output=$(cd -- "$2" && pwd)
scratch=$(mktemp -d)
trap 'rm -rf -- "$scratch"' EXIT
readonly target output scratch

# This disposable checkout has already passed preflight. Do not let target
# ignore files suppress analysis (the Git index and history remain intact).
while IFS= read -r -d '' file; do
  rm -f -- "$target/$file"
done < <(git -C "$target" ls-files -z -- \
  '.gitignore' ':(glob)**/.gitignore' '.semgrepignore' ':(glob)**/.semgrepignore')

osv_status=127
if command -v docker > /dev/null; then
  set +e
  docker run --rm --mount "type=bind,source=$target,target=/repo,readonly" \
    "ghcr.io/google/osv-scanner:v2.7.0@sha256:4f3b7e2c64b9d38a5febc5a7e4a3dfef1d1362f726dea7a2ef4762b46469fcd0" \
    scan source --recursive --include-git-root --config /dev/null \
    --format json /repo > "$output/osv-scanner.json" 2> "$output/osv-scanner.log"
  osv_status=$?
  set -e
else
  printf 'Docker is required for OSV-Scanner\n' > "$output/osv-scanner.log"
fi
printf '%s\n' "$osv_status" > "$output/osv-scanner-status.txt"

semgrep_status=127
if command -v uvx > /dev/null; then
  set +e
  env -u SEMGREP_APP_TOKEN -u SEMGREP_API_TOKEN \
    SEMGREP_SEND_METRICS=off UV_EXCLUDE_NEWER='7 days' \
    uvx --from semgrep==1.180.0 semgrep scan --config p/default \
    --metrics off --disable-nosem --no-git-ignore --error --json \
    --exclude .git -- "$target" \
    > "$output/semgrep.json" 2> "$output/semgrep.log"
  semgrep_status=$?
  set -e
else
  printf 'uvx is required for Semgrep OSS\n' > "$output/semgrep.log"
fi
printf '%s\n' "$semgrep_status" > "$output/semgrep-status.txt"

trufflehog_status=127
if command -v docker > /dev/null; then
  set +e
  docker run --rm --network none \
    --mount "type=bind,source=$target,target=/repo,readonly" \
    --env GIT_CONFIG_COUNT=1 --env GIT_CONFIG_KEY_0=safe.directory \
    --env 'GIT_CONFIG_VALUE_0=*' \
    "trufflesecurity/trufflehog:3.99.2@sha256:47a84bc18a0d04a165498bbbd3bacfd84176661cbc91f8e0f85467f6a771e99a" \
    git file:///repo --no-update --no-verification \
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
  printf 'TruffleHog exited with status %s; raw credentials are not retained.\n' \
    "$trufflehog_status" > "$output/trufflehog.log"
else
  printf 'Docker is required for TruffleHog\n' > "$output/trufflehog.log"
fi
printf '%s\n' "$trufflehog_status" > "$output/trufflehog-status.txt"
