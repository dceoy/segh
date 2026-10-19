#!/usr/bin/env bash

set -euo pipefail
umask 077

if [[ "${1:-}" == --audit-scan ]]; then
  shift
  # shellcheck source=skills/repository-security-audit/scripts/scanners/common.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/common.sh"
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
  env -u SHELLCHECK_OPTS mise -C "$repo_root" exec -- "$skill_root/scripts/scanners/shellcheck.sh" \
    --color=never --format=json1 --rcfile /dev/null \
    --severity=style -- "${shell_files[@]}" > "$output/shellcheck.json" 2> "$output/shellcheck.log"
  shellcheck_status=$?
  set -e
  printf '%s\n' "$shellcheck_status" > "$output/shellcheck-status.txt"
fi

  exit 0
fi

skill_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
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
    printf 'repository-security-audit: target-owned ShellCheck directive rejected: %s\n' "$file" >&2
    return 1
  fi
  if ((grep_status > 1)); then
    printf 'repository-security-audit: unable to inspect ShellCheck input: %s\n' "$file" >&2
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
  exec env -u SHELLCHECK_OPTS mise -C "$repo_root" exec -- shellcheck "${shellcheck_args[@]}" < "$stdin_file"
fi
exec env -u SHELLCHECK_OPTS mise -C "$repo_root" exec -- shellcheck "${shellcheck_args[@]}"
