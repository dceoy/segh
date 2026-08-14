#!/usr/bin/env bash

set -euo pipefail

readonly scan_root=${1:?scan root directory is required}
canonical_root=$(realpath -e -- "$scan_root")
readonly canonical_root

reject() {
  printf 'validate-iac-references: %s\n' "$1" >&2
  exit 1
}

is_contained() {
  local candidate=$1
  [[ "$candidate" == "$canonical_root" || "$candidate" == "$canonical_root"/* ]]
}

# Every Helm/Kustomize reference to local content is required to resolve, via
# realpath, to a location inside the copied scan root. This is a positive
# allowlist: it accepts only references that demonstrably stay inside the
# sandbox, rather than trying to enumerate every remote scheme Checkov's own
# blocked-remote-repo detection might miss (oci://, scp-style git refs,
# absolute file:// paths, go-getter shorthand, and so on).
validate_local_reference() {
  local raw=$1 base_dir=$2 description=$3
  local target resolved

  if [[ "$raw" == /* ]]; then
    target=$raw
  else
    target="$base_dir/$raw"
  fi

  if ! resolved=$(realpath -e -- "$target" 2>/dev/null); then
    reject "unresolved local reference ($description): $raw"
  fi
  is_contained "$resolved" || reject "reference escapes scan root ($description): $raw -> $resolved"
}

while IFS= read -r -d '' chart; do
  chart_dir=$(dirname -- "$chart")
  dependency_count=$(yq -r '.dependencies // [] | length' "$chart")
  for ((i = 0; i < dependency_count; i++)); do
    repository=$(yq -r ".dependencies[$i].repository // \"\"" "$chart")
    [[ -z "$repository" ]] && continue
    case "$repository" in
      file://*)
        validate_local_reference "${repository#file://}" "$chart_dir" "Helm dependency in $chart"
        ;;
      *)
        reject "disallowed Helm dependency repository in $chart: $repository"
        ;;
    esac
  done
done < <(find "$scan_root" -type f -name Chart.yaml -print0)

while IFS= read -r -d '' kustomization; do
  kustomization_dir=$(dirname -- "$kustomization")
  for field in resources bases components crds; do
    entry_count=$(yq -r ".${field} // [] | length" "$kustomization")
    for ((i = 0; i < entry_count; i++)); do
      entry=$(yq -r ".${field}[${i}] // \"\"" "$kustomization")
      [[ -z "$entry" ]] && continue
      validate_local_reference "$entry" "$kustomization_dir" "Kustomize $field in $kustomization"
    done
  done
done < <(find "$scan_root" -type f \
  \( -iname 'kustomization.yaml' -o -iname 'kustomization.yml' -o -iname 'Kustomization' \) -print0)

# Checkov's Terraform LocalPathLoader (is_external = False) accepts any
# module source starting with "./", "../", or "/" and is never skipped by
# download-external-modules: false, which only gates loaders marked
# external (git/registry/etc.). Apply the same local-reference containment
# check to every such module source before Checkov ever loads it. Module
# scope is determined by parsing real HCL with hcl2json rather than a raw
# brace counter, which comments, strings, and heredocs could fool.
# Checkov's tf_parser loads both ".tf" and ".hcl" files into its module
# graph, so ".hcl" module blocks must be covered by the same check.
while IFS= read -r -d '' tf_file; do
  tf_dir=$(dirname -- "$tf_file")
  parsed=$(hcl2json "$tf_file" 2>&1) \
    || reject "failed to parse Terraform file: $tf_file"
  while IFS= read -r source_value; do
    [[ -z "$source_value" ]] && continue
    case "$source_value" in
      ./* | ../* | /*)
        validate_local_reference "$source_value" "$tf_dir" "Terraform module source in $tf_file"
        ;;
    esac
  done < <(printf '%s' "$parsed" \
    | jq -r '.module // {} | to_entries[] | .value[]? | .source? // empty')
done < <(find "$scan_root" -type f \( -name '*.tf' -o -name '*.hcl' \) -print0)

# Checkov's Serverless collector (get_scannable_file_paths in
# checkov/serverless/utils.py) hard-codes an unconditional node_modules
# exclusion via os.walk(), independent of CKV_IGNORED_DIRECTORIES. A tracked
# serverless.yml/yaml under node_modules would be silently invisible to
# Checkov with no error at all; fail closed rather than let that evidence
# gap pass unnoticed.
while IFS= read -r -d '' sls_file; do
  case "$sls_file" in
    */node_modules/*)
      reject "serverless config under node_modules is invisible to Checkov: $sls_file"
      ;;
  esac
done < <(find "$scan_root" -type f \( -name 'serverless.yml' -o -name 'serverless.yaml' \) -print0)

exit 0
