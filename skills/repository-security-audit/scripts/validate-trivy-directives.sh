#!/usr/bin/env bash

set -euo pipefail

readonly target=${1:?target checkout is required}
index=$(mktemp)
readonly index
trap 'rm -f -- "$index"' EXIT

# Trivy parses raw source tokens, including legacy tfsec annotations and
# reordered sections. Conservatively reject directive-shaped content rather
# than trying to reproduce each language parser or rewriting target files.
if ! git -C "$target" ls-files --stage -z > "$index"; then
  printf 'Unable to enumerate Trivy inputs.\n' >&2
  exit 2
fi
while IFS= read -r -d '' entry; do
  mode=${entry%% *}
  [[ "$mode" == 100644 || "$mode" == 100755 ]] || continue
  path=${entry#*$'\t'}
  set +e
  LC_ALL=C grep -aEq '(trivy|tfsec):([^[:space:]]*:)*ignore:' -- "$target/$path"
  status=$?
  set -e
  if ((status == 0)); then
    printf 'Rejected target-owned Trivy suppression directive: %s\n' "$path" >&2
    exit 2
  elif ((status != 1)); then
    printf 'Unable to inspect Trivy input: %s\n' "$path" >&2
    exit 2
  fi
done < "$index"
