#!/usr/bin/env bash
# Shared trusted file selection for scanner entry points.

set -euo pipefail
umask 077
checkout=$(cd -- "${1:?checkout is required}" && pwd)
output=$(cd -- "${2:?output is required}" && pwd)
skill_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
readonly checkout output skill_root

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

