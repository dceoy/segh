#!/usr/bin/env bash

set -euo pipefail
umask 077

readonly repo=${1:?repository is required}
readonly commit_sha=${2:?revision is required}
checkout=$(cd -- "${3:?checkout is required}" && pwd)
output=$(cd -- "${4:?evidence directory is required}" && pwd)
skill_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
tmp=$(mktemp -d)
readonly checkout output skill_root tmp
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

run_index_selection() {
  local -n destination=$1
  shift
  destination=()
  local entry mode path
  while IFS= read -r -d '' entry; do
    mode=${entry%% *}
    case "$mode" in
      100644|100755)
        path=${entry#*$'\t'}
        destination+=("$checkout/$path")
        ;;
    esac
  done < <(git -C "$checkout" ls-files --stage -z -- "$@")
}

zizmor_files=()
run_index_selection zizmor_files \
  '.github/workflows/*.yml' '.github/workflows/*.yaml' ':(glob)**/action.yml' ':(glob)**/action.yaml'
if ((${#zizmor_files[@]} == 0)); then
  printf '%s\n' '[]' > "$output/zizmor.json"
  : > "$output/zizmor.log"
  printf '%s\n' 0 > "$output/zizmor-status.txt"
else
  set +e
  mise -C "$skill_root" exec --locked -- zizmor --offline --no-config --no-ignores --no-exit-codes --strict-collection \
    --persona regular --min-severity medium --min-confidence high --format json "${zizmor_files[@]}" \
    > "$output/zizmor.json" 2> "$output/zizmor.log"
  zizmor_status=$?
  set -e
  printf '%s\n' "$zizmor_status" > "$output/zizmor-status.txt"
fi

actionlint_files=()
run_index_selection actionlint_files '.github/workflows/*.yml' '.github/workflows/*.yaml'
if ((${#actionlint_files[@]} == 0)); then
  : > "$output/actionlint.jsonl"
  : > "$output/actionlint.log"
  printf '%s\n' 0 > "$output/actionlint-status.txt"
else
  set +e
  env -u SHELLCHECK_OPTS mise -C "$skill_root" exec --locked -- actionlint --no-color --config-file /dev/null \
    --shellcheck "$skill_root/scripts/run-shellcheck.sh" --format '{{json .}}' "${actionlint_files[@]}" \
    > "$output/actionlint.jsonl" 2> "$output/actionlint.log"
  actionlint_status=$?
  set -e
  printf '%s\n' "$actionlint_status" > "$output/actionlint-status.txt"
fi

has_supported_shell_shebang() {
  local line=$1 command rest interpreter
  [[ "$line" == '#!'* ]] || return 1
  line=${line#\#!}
  line=${line#"${line%%[![:space:]]*}"}
  read -r command rest <<< "$line"
  interpreter=${command##*/}
  case "$interpreter" in
    sh|bash|dash|ksh) return 0 ;;
    env)
      read -r command rest <<< "$rest"
      if [[ "$command" == -S ]]; then
        read -r command rest <<< "$rest"
      fi
      interpreter=${command##*/}
      case "$interpreter" in
        sh|bash|dash|ksh) return 0 ;;
      esac
      ;;
  esac
  return 1
}

shell_files=()
declare -A shell_seen=()
while IFS= read -r -d '' entry; do
  mode=${entry%% *}
  [[ "$mode" == 100644 || "$mode" == 100755 ]] || continue
  path=${entry#*$'\t'}
  include=false
  case "$path" in
    *.sh|*.bash|*.bats) include=true ;;
  esac
  if [[ "$include" == false ]]; then
    first_line=''
    IFS= LC_ALL=C read -r -n 256 first_line < "$checkout/$path" || true
    if has_supported_shell_shebang "$first_line"; then
      include=true
    fi
  fi
  if [[ "$include" == true && -z "${shell_seen[$path]:-}" ]]; then
    shell_files+=("$checkout/$path")
    shell_seen[$path]=1
  fi
done < <(git -C "$checkout" ls-files --stage -z)

if ((${#shell_files[@]} == 0)); then
  printf '%s\n' '[]' > "$output/shellcheck.json"
  : > "$output/shellcheck.log"
  printf '%s\n' 0 > "$output/shellcheck-status.txt"
else
  set +e
  env -u SHELLCHECK_OPTS mise -C "$skill_root" exec --locked -- "$skill_root/scripts/run-shellcheck.sh" \
    --color=never --format=json1 --rcfile /dev/null \
    --severity=style -- "${shell_files[@]}" > "$output/shellcheck.json" 2> "$output/shellcheck.log"
  shellcheck_status=$?
  set -e
  printf '%s\n' "$shellcheck_status" > "$output/shellcheck-status.txt"
fi

set +e
mise -C "$skill_root" exec --locked -- "$skill_root/scripts/run-checkov.sh" "$checkout" "$output" \
  > "$output/checkov-run.log" 2>&1
checkov_invocation_status=$?
set -e
printf '%s\n' "$checkov_invocation_status" > "$output/checkov-invocation-status.txt"

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

# The disposable checkout has passed preflight. Ignore files in the target
# must not change the policy of the trusted source scanners.
while IFS= read -r -d '' file; do
  rm -f -- "$checkout/$file"
done < <(git -C "$checkout" ls-files -z -- \
  '.gitignore' ':(glob)**/.gitignore' '.semgrepignore' ':(glob)**/.semgrepignore')

set +e
mise -C "$skill_root" exec --locked -- osv-scanner scan source \
  --recursive --include-git-root --config /dev/null \
  --format json "$checkout" \
  > "$output/osv-scanner.json" 2> "$output/osv-scanner.log"
osv_status=$?
set -e
printf '%s\n' "$osv_status" > "$output/osv-scanner-status.txt"

set +e
env -u SEMGREP_APP_TOKEN -u SEMGREP_API_TOKEN \
  SEMGREP_SEND_METRICS=off \
  mise -C "$skill_root" exec --locked -- \
  uvx --from semgrep==1.180.0 semgrep scan --config p/default \
  --metrics off --disable-nosem --no-git-ignore --error --json \
  --exclude .git -- "$checkout" \
  > "$output/semgrep.json" 2> "$output/semgrep.log"
semgrep_status=$?
set -e
printf '%s\n' "$semgrep_status" > "$output/semgrep-status.txt"

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
