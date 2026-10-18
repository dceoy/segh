#!/usr/bin/env bash

set -euo pipefail
umask 077
source "$(dirname -- "${BASH_SOURCE[0]}")/common.sh"

set +e
mise -C "$skill_root" exec --locked -- osv-scanner scan source \
  --recursive --include-git-root --config /dev/null \
  --format json "$checkout" \
  > "$output/osv-scanner.json" 2> "$output/osv-scanner.log"
osv_status=$?
set -e
printf '%s\n' "$osv_status" > "$output/osv-scanner-status.txt"

