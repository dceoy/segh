#!/usr/bin/env bash

set -euo pipefail
umask 077
# shellcheck source=skills/repository-security-audit/scripts/scanners/common.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/common.sh"

set +e
mise -C "$skill_root" exec -- osv-scanner scan source \
  --recursive --no-ignore --config /dev/null \
  --format json "$checkout" \
  > "$output/osv-scanner.json" 2> "$output/osv-scanner.log"
osv_status=$?
set -e
printf '%s\n' "$osv_status" > "$output/osv-scanner-status.txt"

