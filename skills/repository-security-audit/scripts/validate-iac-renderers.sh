#!/usr/bin/env bash

set -euo pipefail

readonly scan_root=${1:?scan root directory is required}
readonly scan_home=${2:?isolated HOME directory is required}

reject() {
  printf 'validate-iac-renderers: %s\n' "$1" >&2
  exit 1
}

# Checkov silently drops evidence for local Helm/Kustomize input it cannot
# render, without treating that as a scanner error. A Helm chart whose
# `helm template --dependency-update` run writes anything to stderr is
# treated by Checkov as producing no report at all (info-level log only,
# exit 0). A Kustomize build's exit status and stderr are ignored entirely,
# so a broken or cyclic local Kustomization renders to nothing with no log
# line whatsoever. Pre-render every contained local Helm chart and
# Kustomization with the same pinned renderers Checkov invokes, in the same
# isolated environment, and fail closed before Checkov -- and its own
# renderer invocations -- ever run.
while IFS= read -r -d '' chart; do
  chart_dir=$(dirname -- "$chart")
  set +e
  render_stderr=$(env -i PATH="$PATH" HOME="$scan_home" \
    helm template --dependency-update "$chart_dir" 2>&1 > /dev/null)
  render_status=$?
  set -e
  if ((render_status != 0)) || [[ -n "$render_stderr" ]]; then
    reject "Helm chart failed to render cleanly: $chart_dir"
  fi
done < <(find "$scan_root" -type f -name Chart.yaml -print0)

while IFS= read -r -d '' kustomization; do
  kustomization_dir=$(dirname -- "$kustomization")
  if ! env -i PATH="$PATH" HOME="$scan_home" \
    kubectl kustomize "$kustomization_dir" > /dev/null 2> /dev/null; then
    reject "Kustomization failed to render cleanly: $kustomization_dir"
  fi
done < <(find "$scan_root" -type f \
  \( -iname 'kustomization.yaml' -o -iname 'kustomization.yml' -o -iname 'Kustomization' \) -print0)
