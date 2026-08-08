#!/usr/bin/env bash

set -euo pipefail

readonly target=${1:?target checkout is required}
index=$(mktemp)
readonly index
trap 'rm -f "$index"' EXIT

git -C "$target" rev-parse --is-inside-work-tree > /dev/null
git -C "$target" ls-files --stage -z > "$index"

regular=0
rejected=0
while IFS= read -r -d '' path; do
  printf 'Rejected untracked path: %s\n' "$path" >&2
  rejected=1
done < <(git -C "$target" ls-files --others -z)

while IFS= read -r -d '' entry; do
  mode=${entry%% *}
  path=${entry#*$'\t'}
  case "$mode" in
    120000)
      printf 'Removed tracked symlink: %s\n' "$path"
      rm -f -- "$target/$path"
      ;;
    160000)
      printf 'Rejected unmaterialized submodule: %s\n' "$path" >&2
      rejected=1
      ;;
    100644|100755)
      ((regular += 1))
      prefix=$(head -c 200 -- "$target/$path") || {
        printf 'Unable to read tracked file: %s\n' "$path" >&2
        rejected=1
        continue
      }
      if [[ "$prefix" == 'version https://git-lfs.github.com/spec/v1'* ]]; then
        printf 'Rejected unmaterialized Git LFS pointer: %s\n' "$path" >&2
        rejected=1
      fi
      ;;
  esac
done < "$index"

if ((regular == 0)); then
  printf 'Rejected checkout with no tracked regular files.\n' >&2
  rejected=1
fi
if ((rejected != 0)); then
  exit 1
fi

printf 'Validated %d tracked regular files with no untracked paths.\n' "$regular"
