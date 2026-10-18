#!/usr/bin/env bash

set -euo pipefail
umask 077
source "$(dirname -- "${BASH_SOURCE[0]}")/common.sh"

tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT
# TruffleHog has network verification disabled. It still runs natively, so
# the absence of Docker is not a replacement for OS-level network isolation.
# Raw detector results may contain credentials: allowlist fields before writing.
set +e
mise -C "$skill_root" exec --locked -- \
  trufflehog git "file://$checkout" --no-update --no-verification \
  --results=verified,unknown,unverified --json \
  > "$tmp/trufflehog-raw.jsonl" 2> "$tmp/trufflehog-stderr"
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
  ' "$tmp/trufflehog-raw.jsonl" > "$output/trufflehog.json"; then
    trufflehog_status=2
    rm -f -- "$output/trufflehog.json"
  fi
fi
printf 'TruffleHog exit status: %s. Raw secret data was discarded.\n' \
  "$trufflehog_status" > "$output/trufflehog.log"
printf '%s\n' "$trufflehog_status" > "$output/trufflehog-status.txt"
