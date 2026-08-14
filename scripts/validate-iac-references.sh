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
