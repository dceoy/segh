#!/usr/bin/env bash

set -euo pipefail

readonly audit=${1:-skills/github-repository-security-audit/scripts/audit.sh}
root=$(mktemp -d)
readonly root
trap 'rm -rf -- "$root"' EXIT

source_repo="$root/source"
fake_bin="$root/bin"
mkdir -p "$fake_bin"
git init -q "$source_repo"
git -C "$source_repo" config user.name segh-validation
git -C "$source_repo" config user.email segh-validation@example.invalid

mkdir -p "$source_repo/.github/workflows"
printf '%s\n' 'safe' > "$source_repo/README.md"
cat > "$source_repo/.github/workflows/ci.yml" <<'EOF_WORKFLOW'
name: Fixture
on:
  push:
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-24.04
    steps:
      - run: true
EOF_WORKFLOW
cat > "$source_repo/install.sh" <<'EOF_SCRIPT'
#!/usr/bin/env bash
touch "$SOURCE_MARKER"
EOF_SCRIPT
chmod +x "$source_repo/install.sh"
printf '%s\n' 'linked' > "$source_repo/linked.txt"
ln -s linked.txt "$source_repo/link.txt"
git -C "$source_repo" add .
git -C "$source_repo" commit -qm fixture
target_sha=$(git -C "$source_repo" rev-parse HEAD)
readonly target_sha

cat > "$fake_bin/mise" <<'EOF_MISE'
#!/usr/bin/env bash
set -euo pipefail
while [[ ${1:-} == -y || ${1:-} == --yes ]]; do shift; done
while [[ ${1:-} == -C ]]; do shift 2; done
case "${1:-}" in
  install) exit 0 ;;
  exec)
    shift
    while [[ ${1:-} != -- ]]; do shift; done
    shift
    exec "$@"
    ;;
  *) exit 2 ;;
esac
EOF_MISE

cat > "$fake_bin/gh" <<'EOF_GH'
#!/usr/bin/env bash
set -euo pipefail
if [[ ${1:-} == repo && ${2:-} == view ]]; then
  printf '%s\n' fixture-owner/fixture-repo
  exit 0
fi
if [[ ${1:-} == repo && ${2:-} == clone ]]; then
  destination=${4:?clone destination missing}
  git clone -q --no-checkout --no-tags --no-recurse-submodules "$SOURCE_REPO" "$destination"
  exit 0
fi
if [[ ${1:-} != api ]]; then
  exit 2
fi
printf '%s\n' "$*" >> "$GH_LOG"
[[ "$*" == *'--method GET'* ]] || exit 91
endpoint=${!#}

emit() {
  local status=$1 body=$2
  printf 'HTTP/2 %s Test\r\ncontent-type: application/json\r\n\r\n%s\n' "$status" "$body"
  [[ "$status" == 2* ]] || exit 1
}

case "$endpoint" in
  repos/fixture-owner/fixture-repo)
    emit 200 '{"id":7,"full_name":"fixture-owner/fixture-repo","name":"fixture-repo","owner":{"login":"fixture-owner"},"visibility":"public","fork":false,"archived":false,"default_branch":"main","security_and_analysis":{"secret_scanning":{"status":"enabled"},"secret_scanning_push_protection":{"status":"enabled"}}}'
    ;;
  repos/fixture-owner/fixture-repo/commits/main)
    emit 200 "{\"sha\":\"$TARGET_SHA\"}"
    ;;
  repos/fixture-owner/fixture-repo/rules/branches/main)
    if [[ ${FAKE_GH_RULES:-} == forbidden ]]; then emit 403 '{}'; fi
    emit 200 '[]'
    ;;
  repos/fixture-owner/fixture-repo/actions/permissions)
    emit 200 '{"enabled":true,"allowed_actions":"all","sha_pinning_required":false}'
    ;;
  repos/fixture-owner/fixture-repo/actions/permissions/workflow)
    emit 200 '{"default_workflow_permissions":"write","can_approve_pull_request_reviews":true}'
    ;;
  repos/fixture-owner/fixture-repo/code-security-configuration)
    if [[ ${FAKE_GH_CODE_SECURITY:-} == malformed ]]; then emit 200 '{'; exit 0; fi
    emit 200 '{"id":12,"name":"default"}'
    ;;
  repos/fixture-owner/fixture-repo/vulnerability-alerts)
    emit 204 ''
    ;;
  repos/fixture-owner/fixture-repo/automated-security-fixes)
    emit 404 '{}'
    ;;
  repos/fixture-owner/fixture-repo/private-vulnerability-reporting)
    emit 404 '{}'
    ;;
  *) emit 404 '{}' ;;
esac
EOF_GH

cat > "$fake_bin/fake-scanner" <<'EOF_SCANNER'
#!/usr/bin/env bash
set -euo pipefail
tool=$(basename "$0")
printf '%s %s\n' "$tool" "$*" >> "${SCANNER_LOG:-/dev/null}"
case "$tool" in
  scorecard)
    if [[ ${1:-} == version ]]; then printf '%s\n' 'scorecard 5.5.0'; else printf '%s\n' '{"checks":[{"name":"Fixture","score":1}]}' ; fi
    ;;
  zizmor)
    if [[ ${1:-} == --version ]]; then printf '%s\n' 'zizmor 1.28.0'; else printf '%s\n' '[]'; fi
    ;;
  actionlint)
    if [[ ${1:-} == -version ]]; then printf '%s\n' '1.7.12'; fi
    ;;
  shellcheck)
    if [[ ${1:-} == --version ]]; then printf '%s\n' 'ShellCheck - shell script analysis tool' 'version: 0.11.0'; else printf '%s\n' '[]'; fi
    ;;
  checkov)
    if [[ ${1:-} == --version ]]; then printf '%s\n' '3.3.9'; else printf '%s\n' '[{"check_type":"terraform","summary":{"failed":0,"skipped":0,"parsing_errors":0}}]'; fi
    ;;
  helm)
    if [[ ${1:-} == version ]]; then printf '%s\n' 'v4.2.3'; fi
    ;;
  kubectl)
    if [[ ${1:-} == version ]]; then printf '%s\n' 'Client Version: v1.36.3'; fi
    ;;
  trivy)
    if [[ ${1:-} == --version ]]; then
      printf '%s\n' 'Version: 0.72.0'
    else
      for ((i = 1; i <= $#; i++)); do
        if [[ ${!i:-} == --output ]]; then
          next=$((i + 1))
          printf '%s\n' '{"SchemaVersion":2,"Trivy":{},"Results":[]}' > "${!next}"
        fi
      done
    fi
    ;;
esac
EOF_SCANNER
chmod +x "$fake_bin/mise" "$fake_bin/gh" "$fake_bin/fake-scanner"
for tool in scorecard zizmor actionlint shellcheck checkov helm kubectl trivy; do
  ln -s fake-scanner "$fake_bin/$tool"
done

run_audit() {
  local label=$1
  local destination="$root/$label"
  mkdir -p "$destination"
  set +e
  PATH="$fake_bin:$PATH" \
    SOURCE_REPO="$source_repo" \
    TARGET_SHA="$target_sha" \
    SOURCE_MARKER="$root/executed.marker" \
    GH_LOG="$root/gh.log" \
    SCANNER_LOG="$root/scanner.log" \
    FAKE_GH_RULES="${FAKE_GH_RULES:-}" \
    FAKE_GH_CODE_SECURITY="${FAKE_GH_CODE_SECURITY:-}" \
    "$audit" --repo fixture-owner/fixture-repo --output "$destination" \
    > "$root/$label.log" 2>&1
  status=$?
  set -e
  printf '%s\n' "$status" > "$root/$label.status"
}

run_audit first
[[ "$(cat "$root/first.status")" == 1 ]]
[[ ! -e "$root/executed.marker" ]]
grep -F 'Removed tracked symlink: link.txt' "$root/first/preflight.txt" > /dev/null
[[ "$(jq -r '.repository_id' "$root/first/target.json")" == 7 ]]
[[ "$(jq -r '.commit_sha' "$root/first/target.json")" == "$target_sha" ]]
jq -e '
  (.controls | length >= 10) and
  all(.controls[]; (.id | type == "string") and (.state | IN("pass", "finding", "unknown", "error")) and
    (.reason | type == "string") and (.required_permission | type == "string") and
    (.evidence.file | type == "string"))
' "$root/first/github-controls.json" > /dev/null
[[ "$(jq -r '.overall_status' "$root/first/summary.json")" == findings ]]
[[ "$(jq -r '.scanners | length' "$root/first/summary.json")" == 7 ]]
[[ "$(jq -r '.controls[] | select(.id == "actions_permissions") | .state' "$root/first/github-controls.json")" == finding ]]
[[ "$(jq -r '.controls[] | select(.id == "dependabot_security_updates") | .state' "$root/first/github-controls.json")" == finding ]]
[[ "$(jq -r '.controls[] | select(.id == "private_vulnerability_reporting") | .state' "$root/first/github-controls.json")" == finding ]]
if grep -v -- '--method GET' "$root/gh.log"; then exit 1; fi
if grep -F -- 'misconfig' "$root/scanner.log"; then exit 1; fi
[[ ! -e "$root/first/trivy-misconfiguration.json" ]]

FAKE_GH_RULES=forbidden
run_audit forbidden
[[ "$(cat "$root/forbidden.status")" == 1 ]]
[[ "$(jq -r '.controls[] | select(.id == "effective_branch_rules") | .state' "$root/forbidden/github-controls.json")" == unknown ]]
[[ "$(jq -r '.controls[] | select(.id == "effective_branch_rules") | .reason' "$root/forbidden/github-controls.json")" == insufficient-permission ]]

FAKE_GH_RULES=''
FAKE_GH_CODE_SECURITY=malformed
run_audit malformed
[[ "$(cat "$root/malformed.status")" == 1 ]]
[[ "$(jq -r '.controls[] | select(.id == "code_security_configuration") | .state' "$root/malformed/github-controls.json")" == error ]]
[[ "$(jq -r '.overall_status' "$root/malformed/summary.json")" == error ]]

printf 'repository security audit boundary tests passed\n'
