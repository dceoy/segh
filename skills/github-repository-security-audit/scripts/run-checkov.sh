#!/usr/bin/env bash

set -euo pipefail

readonly target=${1:?target directory is required}
readonly results=${2:?results directory is required}
trusted=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
scan_root=$(mktemp -d)
scan_home=$(mktemp -d)
helm_shim_dir=$(mktemp -d)
readonly trusted scan_root scan_home helm_shim_dir
trap 'rm -rf -- "$scan_root" "$scan_home" "$helm_shim_dir"' EXIT

cp -a -- "$target/." "$scan_root/"
rm -rf -- "$scan_root/.git"
rm -f -- "$scan_root/.checkov.yml" "$scan_root/.checkov.yaml"
mkdir -p -- "$results"

# Helm 4.2.3 validates values.schema.json by default, and its JSON-schema
# compiler resolves file:/http:/https: $ref loaders with no containment
# check, so a chart-controlled schema can force target-controlled network
# access or read arbitrary files. Checkov invokes `helm template` itself, so
# disabling schema validation on our own pre-render check is not enough;
# shim `helm` in front of both invocations to force --skip-schema-validation
# on every `template` call while passing every other subcommand through
# unchanged.
real_helm=$(command -v helm)
readonly real_helm
cat > "$helm_shim_dir/helm" <<SHIM
#!/usr/bin/env bash
set -euo pipefail
if [[ "\${1:-}" == "template" ]]; then
  shift
  exec "$real_helm" template --skip-schema-validation "\$@"
fi
exec "$real_helm" "\$@"
SHIM
chmod +x -- "$helm_shim_dir/helm"
readonly shimmed_path="$helm_shim_dir:$PATH"

# Checkov's own blocked-remote-repo detection only classifies references it
# recognizes as remote (notably http(s):// for Helm); it misses other forms
# such as oci://, absolute file:// paths, scp-style Git refs, and escaping
# relative paths for Kustomize. Validate every local Helm/Kustomize reference
# against a positive allowlist (must resolve inside the copied scan root)
# before Checkov -- and any Helm/Kustomize renderer it invokes -- ever runs.
set +e
"$trusted/scripts/validate-iac-references.sh" "$scan_root" > "$results/checkov.log" 2>&1
validation_status=$?
set -e

if ((validation_status != 0)); then
  status=2
  : > "$results/checkov-native.json"
else
  set +e
  PATH="$shimmed_path" "$trusted/scripts/validate-iac-renderers.sh" "$scan_root" "$scan_home" \
    >> "$results/checkov.log" 2>&1
  renderer_status=$?
  set -e

  if ((renderer_status != 0)); then
    status=2
    : > "$results/checkov-native.json"
  else
    set +e
    (
      cd -- "$trusted"
      # CKV_IGNORED_DIRECTORIES is set to a sentinel rather than left empty:
      # an empty value splits to [""], and the secrets framework's exclusion
      # filter does "p in full_path", which an empty string always matches --
      # that would silently drop every file from the secrets framework.
      # validate-iac-references.sh (already run above) rejects any target
      # path colliding with this exact sentinel, since it is otherwise a
      # target-controlled evidence-suppression path of its own (an exact
      # directory-name match prunes every framework; a substring match
      # prunes the secrets framework). Keep this value identical to the one
      # there.
      env -i \
        PATH="$shimmed_path" \
        HOME="$scan_home" \
        CKV_PARSE_ERROR_FAIL=true \
        CKV_IGNORE_HIDDEN_DIRECTORIES=false \
        CKV_IGNORED_DIRECTORIES=__segh_no_ignored_directory__ \
        CHECKOV_SERVERLESS_DISABLE_VARS=true \
        CHECKOV_HELM_ALLOWED_REMOTE_REPOS=none \
        CHECKOV_KUSTOMIZE_ALLOWED_REMOTE_PREFIXES=none \
        CHECKOV_ALLOW_KUSTOMIZE_FILE_EDITS=false \
        checkov --directory "$scan_root" --config-file config/checkov.yml \
          --skip-download --skip-results-upload --output json
    ) > "$results/checkov-native.json" 2>> "$results/checkov.log"
    status=$?
    set -e

    # Checkov silently skips rendering a blocked remote Helm/Kustomize
    # reference, or a Helm chart/dependency it fails to process (exit 0, no
    # per-report evidence in every case); treat all of these as a scanner
    # error rather than a clean scan. The last two patterns are defense in
    # depth: validate-iac-renderers.sh already fails closed on any stderr
    # from `helm template --dependency-update` for every contained chart,
    # which is strictly stronger than what triggers them, so no fixture
    # reaches this path today.
    if grep -qF -- 'Skipping helm template for' "$results/checkov.log" \
      || grep -qF -- 'Skipping kustomize build for' "$results/checkov.log" \
      || grep -qF -- 'Failed processing helm chart' "$results/checkov.log" \
      || grep -qF -- 'Error processing helm dependencies for' "$results/checkov.log"; then
      status=2
    fi

    # A real Checkov run always emits either the bare no-IaC summary object
    # or a non-empty report list/object; empty or literal-[] stdout
    # indicates lost evidence, not a clean empty scan.
    if ((status == 0)) && ! jq -e '(type == "object") or (type == "array" and length > 0)' \
      "$results/checkov-native.json" > /dev/null 2>&1; then
      status=2
    fi
  fi
fi

if jq -e 'type == "object" and (.failed | type == "number") and (.parsing_errors | type == "number")' \
  "$results/checkov-native.json" > /dev/null 2>&1; then
  jq '{summary: .}' "$results/checkov-native.json" > "$results/checkov.json"
elif jq -e '.' "$results/checkov-native.json" > /dev/null 2>&1; then
  cp -- "$results/checkov-native.json" "$results/checkov.json"
else
  printf 'null\n' > "$results/checkov.json"
fi

printf '%s\n' "$status" > "$results/checkov-status.txt"
exit "$status"
