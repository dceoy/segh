#!/usr/bin/env bash

set -euo pipefail
umask 077

skill_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
readonly skill_root
unset SHELLCHECK_OPTS

shellcheck_args=()
input_files=()
stdin_requested=false
for argument in "$@"; do
  case "$argument" in
    -x|--external-sources|--external-sources=*)
      ;;
    -)
      stdin_requested=true
      shellcheck_args+=("$argument")
      ;;
    *)
      shellcheck_args+=("$argument")
      if [[ -f "$argument" ]]; then
        input_files+=("$argument")
      fi
      ;;
  esac
done

reject_directives() {
  local file=$1
  local grep_status
  set +e
  LC_ALL=C grep -nE '^[[:space:]]*#[[:space:]]*shellcheck([[:space:]]|$)' "$file" > /dev/null
  grep_status=$?
  set -e
  if ((grep_status == 0)); then
    printf 'github-repository-security-audit: target-owned ShellCheck directive rejected: %s\n' "$file" >&2
    return 1
  fi
  if ((grep_status > 1)); then
    printf 'github-repository-security-audit: unable to inspect ShellCheck input: %s\n' "$file" >&2
    return 1
  fi
}

stdin_file=''
if [[ "$stdin_requested" == true ]]; then
  stdin_file=$(mktemp)
  trap 'rm -f -- "$stdin_file"' EXIT
  cat > "$stdin_file"
  reject_directives "$stdin_file"
fi
for input_file in "${input_files[@]}"; do
  reject_directives "$input_file"
done

if [[ "$stdin_requested" == true ]]; then
  exec env -u SHELLCHECK_OPTS mise -C "$skill_root" exec --locked -- shellcheck "${shellcheck_args[@]}" < "$stdin_file"
fi
exec env -u SHELLCHECK_OPTS mise -C "$skill_root" exec --locked -- shellcheck "${shellcheck_args[@]}"
