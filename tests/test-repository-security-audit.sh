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

lfs_source="$root/lfs-source"
git clone -q "$source_repo" "$lfs_source"
git -C "$lfs_source" config user.name segh-validation
git -C "$lfs_source" config user.email segh-validation@example.invalid
printf '%s\n' 'version https://git-lfs.github.com/spec/v1' > "$lfs_source/fixture-lfs.bin"
git -C "$lfs_source" add fixture-lfs.bin
git -C "$lfs_source" commit -qm 'add LFS pointer fixture'
lfs_target_sha=$(git -C "$lfs_source" rev-parse HEAD)
readonly lfs_target_sha

cat > "$fake_bin/mise" <<'EOF_MISE'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "${MISE_LOG:-/dev/null}"
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

cat > "$fake_bin/git" <<'EOF_GIT'
#!/usr/bin/env bash
set -euo pipefail
for argument in "$@"; do
  if [[ "$argument" == checkout ]]; then
    printf '%s\n' "${GIT_LFS_SKIP_SMUDGE:-unset}" > "${GIT_CHECKOUT_ENV_LOG:-/dev/null}"
    break
  fi
done
exec /usr/bin/git "$@"
EOF_GIT

cat > "$fake_bin/uname" <<'EOF_UNAME'
#!/usr/bin/env bash
set -euo pipefail
case "${1:-}" in
  -s) printf '%s\n' "${FAKE_PLATFORM:-$(/usr/bin/uname -s)}" ;;
  -m) printf '%s\n' "${FAKE_MACHINE:-$(/usr/bin/uname -m)}" ;;
  *) exec /usr/bin/uname "$@" ;;
esac
EOF_UNAME

cat > "$fake_bin/arch" <<'EOF_ARCH'
#!/usr/bin/env bash
set -euo pipefail
if [[ ${FAKE_ROSETTA:-} == unavailable ]]; then exit 1; fi
exit 0
EOF_ARCH

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
  if [[ ${FAKE_BAD_PREFLIGHT:-} == 1 ]]; then
    printf '%s\n' generated > "$destination/untracked.txt"
  fi
  exit 0
fi
if [[ ${1:-} == auth && ${2:-} == token ]]; then
  printf '%s\n' auth-token >> "${GH_AUTH_LOG:-/dev/null}"
  printf '%s\n' "${FAKE_GH_TOKEN:-gh-login-token}"
  exit 0
fi
if [[ ${1:-} != api ]]; then
  exit 2
fi
printf '%s\n' "$*" >> "$GH_LOG"
[[ "$*" == *'--method GET'* ]] || exit 91
endpoint=${!#}
endpoint=${endpoint,,}

emit() {
  local status=$1 body=$2
  printf 'HTTP/2 %s Test\r\ncontent-type: application/json\r\n\r\n%s\n' "$status" "$body"
  [[ "$status" == 2* ]] || exit 1
}

case "$endpoint" in
  repos/fixture-owner/fixture-repo)
    if [[ ${FAKE_GH_MIXED_CASE:-} == 1 ]]; then
      emit 200 '{"id":7,"full_name":"Fixture-Owner/Fixture-Repo","name":"Fixture-Repo","owner":{"login":"Fixture-Owner"},"visibility":"public","fork":false,"archived":false,"default_branch":"main","security_and_analysis":{"secret_scanning":{"status":"enabled"},"secret_scanning_push_protection":{"status":"enabled"}}}'
    else
      emit 200 '{"id":7,"full_name":"fixture-owner/fixture-repo","name":"fixture-repo","owner":{"login":"fixture-owner"},"visibility":"public","fork":false,"archived":false,"default_branch":"main","security_and_analysis":{"secret_scanning":{"status":"enabled"},"secret_scanning_push_protection":{"status":"enabled"}}}'
    fi
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
    if [[ ${FAKE_GH_FEATURES:-} == 404 ]]; then emit 404 '{}'; fi
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
    if [[ ${1:-} == version ]]; then
      printf '%s\n' 'scorecard 5.5.0'
    else
      printf '%s\n' "${GITHUB_AUTH_TOKEN:-}" > "${SCORECARD_TOKEN_LOG:-/dev/null}"
      printf '%s\n' '{"checks":[{"name":"Fixture","score":1}]}'
    fi
    ;;
  zizmor)
    if [[ ${1:-} == --version ]]; then printf '%s\n' 'zizmor 1.28.0'; else printf '%s\n' '[]'; fi
    ;;
  actionlint)
    if [[ ${1:-} == -version ]]; then printf '%s\n' '1.7.12'; fi
    ;;
  shellcheck)
    if [[ ${FAKE_VERSION_FAIL:-} == shellcheck && ${1:-} == --version ]]; then exit 42; fi
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
chmod +x "$fake_bin/mise" "$fake_bin/git" "$fake_bin/gh" "$fake_bin/uname" "$fake_bin/arch" "$fake_bin/fake-scanner"
for tool in scorecard zizmor actionlint shellcheck checkov helm kubectl trivy; do
  ln -s fake-scanner "$fake_bin/$tool"
done

run_audit() {
  local label=$1
  local destination="$root/$label"
  local requested_repo=fixture-owner/fixture-repo
  local source_for_audit=$source_repo
  local target_for_audit=$target_sha
  local scorecard_env=()
  if [[ "$label" == mixed-case ]]; then
    requested_repo=fixture-owner/FIXTURE-REPO
  fi
  if [[ "$label" == lfs ]]; then
    source_for_audit=$lfs_source
    target_for_audit=$lfs_target_sha
  fi
  if [[ "$label" == env-token ]]; then
    scorecard_env=(GITHUB_TOKEN=environment-token)
  fi
  mkdir -p "$destination"
  set +e
  env -u GITHUB_AUTH_TOKEN -u GITHUB_TOKEN -u GH_AUTH_TOKEN -u GH_TOKEN -u GIT_LFS_SKIP_SMUDGE \
    "${scorecard_env[@]}" \
    PATH="$fake_bin:$PATH" \
    SOURCE_REPO="$source_for_audit" \
    TARGET_SHA="$target_for_audit" \
    SOURCE_MARKER="$root/executed.marker" \
    GH_LOG="$root/gh.log" \
    GH_AUTH_LOG="$root/$label.auth.log" \
    SCANNER_LOG="$root/scanner.log" \
    SCORECARD_TOKEN_LOG="$root/$label.scorecard-token" \
    GIT_CHECKOUT_ENV_LOG="$root/$label.checkout-env" \
    MISE_LOG="$root/$label.mise.log" \
    FAKE_GH_RULES="${FAKE_GH_RULES:-}" \
    FAKE_GH_CODE_SECURITY="${FAKE_GH_CODE_SECURITY:-}" \
    FAKE_GH_FEATURES="${FAKE_GH_FEATURES:-}" \
    FAKE_GH_MIXED_CASE="${FAKE_GH_MIXED_CASE:-}" \
    FAKE_BAD_PREFLIGHT="${FAKE_BAD_PREFLIGHT:-}" \
    FAKE_VERSION_FAIL="${FAKE_VERSION_FAIL:-}" \
    FAKE_PLATFORM="${FAKE_PLATFORM:-}" \
    FAKE_MACHINE="${FAKE_MACHINE:-}" \
    FAKE_ROSETTA="${FAKE_ROSETTA:-}" \
    "$audit" --repo "$requested_repo" --output "$destination" \
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
[[ "$(jq -r '.controls[] | select(.id == "vulnerability_alerts") | .state' "$root/first/github-controls.json")" == pass ]]
[[ "$(jq -r '.controls[] | select(.id == "dependabot_security_updates") | .state' "$root/first/github-controls.json")" == unknown ]]
[[ "$(jq -r '.controls[] | select(.id == "private_vulnerability_reporting") | .state' "$root/first/github-controls.json")" == unknown ]]
[[ "$(cat "$root/first.scorecard-token")" == gh-login-token ]]
if grep -R -F -- 'gh-login-token' "$root/first"; then exit 1; fi
if grep -v -- '--method GET' "$root/gh.log"; then exit 1; fi
if grep -F -- 'misconfig' "$root/scanner.log"; then exit 1; fi
[[ ! -e "$root/first/trivy-misconfiguration.json" ]]

FAKE_GH_FEATURES=404
run_audit feature-404
[[ "$(jq -r '.controls[] | select(.id == "vulnerability_alerts") | .state' "$root/feature-404/github-controls.json")" == unknown ]]
[[ "$(jq -r '.controls[] | select(.id == "dependabot_security_updates") | .state' "$root/feature-404/github-controls.json")" == unknown ]]
[[ "$(jq -r '.controls[] | select(.id == "private_vulnerability_reporting") | .state' "$root/feature-404/github-controls.json")" == unknown ]]
[[ "$(jq '[.controls[] | select(.id == "vulnerability_alerts" or .id == "dependabot_security_updates" or .id == "private_vulnerability_reporting") | select(.state == "finding")] | length' "$root/feature-404/github-controls.json")" == 0 ]]
FAKE_GH_FEATURES=''

run_audit lfs
[[ "$(cat "$root/lfs.status")" == 1 ]]
[[ "$(cat "$root/lfs.checkout-env")" == 1 ]]
grep -F 'Rejected unmaterialized Git LFS pointer: fixture-lfs.bin' "$root/lfs/preflight.txt" > /dev/null

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
FAKE_GH_CODE_SECURITY=''

FAKE_BAD_PREFLIGHT=1
run_audit preflight-failure
[[ "$(cat "$root/preflight-failure.status")" == 1 ]]
[[ "$(cat "$root/preflight-failure/preflight-status.txt")" == 1 ]]
grep -F 'Rejected untracked path: untracked.txt' "$root/preflight-failure/preflight.txt" > /dev/null
[[ "$(jq -r '.stage_status.preflight' "$root/preflight-failure/summary.json")" == 1 ]]
FAKE_BAD_PREFLIGHT=''

FAKE_VERSION_FAIL=shellcheck
run_audit version-failure
[[ "$(cat "$root/version-failure.status")" == 1 ]]
[[ "$(cat "$root/version-failure/preflight-status.txt")" == 0 ]]
grep -F 'Removed tracked symlink: link.txt' "$root/version-failure/preflight.txt" > /dev/null
[[ "$(cat "$root/version-failure/versions-status.txt")" == 1 ]]
FAKE_VERSION_FAIL=''

run_audit env-token
[[ "$(cat "$root/env-token.scorecard-token")" == environment-token ]]
[[ ! -e "$root/env-token.auth.log" ]]

FAKE_GH_MIXED_CASE=1
run_audit mixed-case
[[ "$(cat "$root/mixed-case.status")" == 1 ]]
[[ "$(jq -r '.repository' "$root/mixed-case/target.json")" == Fixture-Owner/Fixture-Repo ]]
[[ "$(jq -r '.owner' "$root/mixed-case/target.json")" == Fixture-Owner ]]
[[ "$(jq -r '.name' "$root/mixed-case/target.json")" == Fixture-Repo ]]
[[ "$(jq -r '.repository.full_name' "$root/mixed-case/summary.json")" == Fixture-Owner/Fixture-Repo ]]

FAKE_PLATFORM=Darwin
FAKE_MACHINE=arm64
FAKE_ROSETTA=unavailable
run_audit rosetta-missing
[[ "$(cat "$root/rosetta-missing.status")" == 1 ]]
[[ "$(cat "$root/rosetta-missing/toolchain-status.txt")" == 1 ]]
[[ ! -e "$root/rosetta-missing.mise.log" ]]
grep -F 'Rosetta 2' "$root/rosetta-missing/toolchain.log" > /dev/null
FAKE_PLATFORM=''
FAKE_MACHINE=''
FAKE_ROSETTA=''

printf 'repository security audit boundary tests passed\n'
