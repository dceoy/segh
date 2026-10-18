#!/usr/bin/env bash

set -euo pipefail
umask 077
source "$(dirname -- "${BASH_SOURCE[0]}")/common.sh"

readonly repo=${3:?repository is required}
readonly commit_sha=${4:?commit SHA required}
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT
scorecard_token=''
scorecard_auth_status=0
for token_variable in GITHUB_AUTH_TOKEN GITHUB_TOKEN GH_AUTH_TOKEN GH_TOKEN; do
  if [[ -n "${!token_variable:-}" ]]; then
    scorecard_token=${!token_variable}
    break
  fi
done

if [[ -z "$scorecard_token" ]]; then
  scorecard_auth_stderr="$tmp/scorecard-auth.stderr"
  set +e
  scorecard_token=$(gh auth token 2> "$scorecard_auth_stderr")
  scorecard_auth_status=$?
  set -e
  if ((scorecard_auth_status == 0)) && [[ -z "$scorecard_token" ]]; then
    scorecard_auth_status=1
  fi
fi

if ((scorecard_auth_status == 0)); then
  : > "$output/scorecard-auth.log"
  set +e
  GITHUB_AUTH_TOKEN="$scorecard_token" \
    mise -C "$skill_root" exec --locked -- scorecard --repo="$repo" --commit="$commit_sha" \
      --show-details --format=json > "$output/scorecard.json" 2> "$output/scorecard.log"
  scorecard_status=$?
  set -e
else
  printf '%s\n' 'gh auth token did not provide a usable credential' > "$output/scorecard-auth.log"
  printf '%s\n' '{"checks":[]}' > "$output/scorecard.json"
  printf '%s\n' 'scorecard was not run because GitHub authentication was unavailable' > "$output/scorecard.log"
  scorecard_status=2
fi
unset scorecard_token
printf '%s\n' "$scorecard_status" > "$output/scorecard-status.txt"

