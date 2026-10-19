#!/usr/bin/env bash

set -euo pipefail
umask 077
# shellcheck source=skills/repository-security-audit/scripts/scanners/common.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/common.sh"

set +e
env -u SEMGREP_APP_TOKEN -u SEMGREP_API_TOKEN \
  SEMGREP_SEND_METRICS=off \
  mise -C "$skill_root" exec -- \
  uvx --from semgrep==1.180.0 semgrep scan --config p/default \
  --metrics off --disable-nosem --no-git-ignore --error --json \
  --exclude .git -- "$checkout" \
  > "$output/semgrep.json" 2> "$output/semgrep.log"
semgrep_status=$?
set -e
printf '%s\n' "$semgrep_status" > "$output/semgrep-status.txt"

