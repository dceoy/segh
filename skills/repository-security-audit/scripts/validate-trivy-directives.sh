#!/usr/bin/env bash

set -euo pipefail

readonly target=${1:?target checkout is required}
skill_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
readonly skill_root
export MISE_CEILING_PATHS="$(dirname -- "$skill_root")"
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
  # The standalone dispatcher deliberately removes these ignore policies
  # after preflight. They are not scanner inputs once removed.
  case "$path" in
    .gitignore|*/.gitignore|.semgrepignore|*/.semgrepignore)
      [[ -e "$target/$path" ]] || continue
      ;;
  esac
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
  # Trivy downloads Terraform/OpenTofu modules by default, with no CLI
  # switch to disable downloads. Reject every module declaration, including
  # local ones, instead of reproducing source evaluation and cache traversal.
  # Parse syntax rather than matching source text (JSON keys may be escaped).
  case "$path" in
    *.tf|*.tofu)
      if ! parsed=$(mise -C "$skill_root" exec -- hcl2json < "$target/$path"); then
        printf 'Unable to parse Trivy Terraform input: %s\n' "$path" >&2
        exit 2
      fi
      ;;
    *.tf.json|*.tofu.json)
      if ! parsed=$(cat -- "$target/$path"); then
        printf 'Unable to read Trivy Terraform input: %s\n' "$path" >&2
        exit 2
      fi
      ;;
    *) continue ;;
  esac
  # Key presence also rejects null/attribute forms that could overwrite block
  # data during conversion. Slurp requires exactly one JSON object.
  if ! module_present=$(printf '%s' "$parsed" | jq -ser '
    if length == 1 and (.[0] | type) == "object"
    then (.[0] | has("module") | tostring)
    else error("expected one Terraform object") end'); then
    printf 'Unable to inspect Trivy Terraform input: %s\n' "$path" >&2
    exit 2
  fi
  if [[ "$module_present" == true ]]; then
    printf 'Rejected target-owned Trivy Terraform module declaration: %s\n' "$path" >&2
    exit 2
  fi
done < "$index"
