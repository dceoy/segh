#!/usr/bin/env bash

set -euo pipefail
umask 077
export GH_TELEMETRY=false

skill_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
readonly skill_root
MISE_CEILING_PATHS=$(dirname -- "$skill_root")
export MISE_CEILING_PATHS
readonly repo_pattern='^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$'

repo=''
output=''

usage() {
  cat <<'EOF'
Usage: audit.sh [--repo OWNER/REPO] --output DIRECTORY

Resolve the default-branch commit for a GitHub repository, audit that
immutable revision, and retain private machine-readable evidence in DIRECTORY.
If --repo is omitted, the current repository is resolved with gh repo view.
EOF
}

fail() {
  local message=$1
  printf 'repository-security-audit: %s\n' "$message" >&2
  if [[ -n "${output:-}" && -d "${output:-}" ]]; then
    printf '%s\n' "$message" > "$output/audit-error.txt"
  fi
  exit 1
}

while (($# > 0)); do
  case "$1" in
    --repo)
      (($# >= 2)) || fail '--repo requires OWNER/REPO'
      repo=$2
      shift 2
      ;;
    --output)
      (($# >= 2)) || fail '--output requires a directory'
      output=$2
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      fail "unknown argument: $1"
      ;;
  esac
done

[[ -n "$output" ]] || fail '--output is required'
mkdir -p -- "$output" || fail "cannot create output directory: $output"
output=$(cd -- "$output" && pwd)
readonly output
shopt -s nullglob dotglob
output_entries=("$output"/*)
shopt -u nullglob dotglob
if ((${#output_entries[@]} > 0)); then
  printf 'repository-security-audit: output directory must be empty: %s\n' "$output" >&2
  exit 1
fi
unset output_entries
mkdir -p -- "$output/github-controls"

tmp=$(mktemp -d)
readonly tmp
trap 'rm -rf -- "$tmp"' EXIT

if [[ -z "$repo" ]]; then
  set +e
  repo=$(gh repo view --json nameWithOwner --jq .nameWithOwner 2> "$tmp/repo-view.log")
  repo_status=$?
  set -e
  if ((repo_status != 0)); then
    cat -- "$tmp/repo-view.log" >&2
    fail 'unable to resolve the current repository with gh repo view'
  fi
fi

[[ "$repo" =~ $repo_pattern ]] || fail "invalid repository: $repo"
requested_repo=$repo
readonly requested_repo

api_call() {
  local endpoint=$1
  local key=$2
  REQUEST_RAW="$tmp/$key.raw"
  REQUEST_BODY="$tmp/$key.body"
  REQUEST_ERROR="$tmp/$key.stderr"
  set +e
  gh api --method GET --include \
    --header 'Accept: application/vnd.github+json' \
    --header 'X-GitHub-Api-Version: 2022-11-28' \
    "$endpoint" > "$REQUEST_RAW" 2> "$REQUEST_ERROR"
  REQUEST_EXIT=$?
  set -e
  REQUEST_HTTP_STATUS=$(awk '/^HTTP\/[0-9.]+[[:space:]]+[0-9]+/ {code=$2} END {print code}' "$REQUEST_RAW")
  if [[ -n "$REQUEST_HTTP_STATUS" ]]; then
    awk '
      /^HTTP\/[0-9.]+[[:space:]]+[0-9]+/ {seen=1; body=0; next}
      seen && /^[[:space:]]*\r?$/ {body=1; next}
      seen && body {sub(/\r$/, ""); print}
    ' "$REQUEST_RAW" > "$REQUEST_BODY"
  else
    cp -- "$REQUEST_RAW" "$REQUEST_BODY"
  fi
}

request_succeeded() {
  [[ "$REQUEST_EXIT" -eq 0 ]] || return 1
  [[ -z "$REQUEST_HTTP_STATUS" || "$REQUEST_HTTP_STATUS" =~ ^2[0-9][0-9]$ ]]
}

save_control_evidence() {
  local id=$1 endpoint=$2
  local evidence="$output/github-controls/$id.json"
  local metadata="$output/github-controls/$id.meta.json"
  local http_status=${REQUEST_HTTP_STATUS:-}
  jq -n \
    --arg endpoint "$endpoint" \
    --arg http_status "$http_status" \
    --argjson exit_status "$REQUEST_EXIT" \
    --rawfile body "$REQUEST_BODY" \
    --rawfile stderr "$REQUEST_ERROR" \
    '{endpoint: $endpoint, http_status: (if $http_status == "" then null else ($http_status | tonumber) end),
      exit_status: $exit_status, body_raw: $body, stderr: $stderr}' > "$evidence"
  jq -n \
    --arg endpoint "$endpoint" \
    --arg http_status "$http_status" \
    --argjson exit_status "$REQUEST_EXIT" \
    '{endpoint: $endpoint, http_status: (if $http_status == "" then null else ($http_status | tonumber) end),
      exit_status: $exit_status}' > "$metadata"
  CONTROL_EVIDENCE=${evidence#"$output/"}
}

record_control() {
  local id=$1 state=$2 reason=$3 permission=$4 evidence=$5 endpoint=$6
  jq -cn \
    --arg id "$id" --arg state "$state" --arg reason "$reason" \
    --arg permission "$permission" --arg evidence "$evidence" --arg endpoint "$endpoint" \
    '{id: $id, state: $state, reason: $reason, required_permission: $permission,
      evidence: {file: $evidence, endpoint: $endpoint}}' >> "$tmp/controls.ndjson"
}

control_failure() {
  local id=$1 permission=$2 endpoint=$3
  if [[ "$REQUEST_HTTP_STATUS" == 403 ]]; then
    record_control "$id" unknown insufficient-permission "$permission" "$CONTROL_EVIDENCE" "$endpoint"
  elif [[ "$REQUEST_HTTP_STATUS" == 404 ]]; then
    record_control "$id" unknown not-observable "$permission" "$CONTROL_EVIDENCE" "$endpoint"
  else
    record_control "$id" error request-failed "$permission" "$CONTROL_EVIDENCE" "$endpoint"
  fi
}

metadata_endpoint="repos/$requested_repo"
api_call "$metadata_endpoint" repository-metadata
save_control_evidence repository-metadata "$metadata_endpoint"
cp -- "$REQUEST_BODY" "$output/repository-metadata.json"
request_succeeded || fail 'repository metadata request failed'

if ! jq -e --arg repo "$requested_repo" '
  type == "object" and
  (.id | type == "number" and . > 0 and . == floor) and
  (.full_name | type == "string" and length > 0) and
  (.full_name | ascii_downcase) == ($repo | ascii_downcase) and
  (.owner | type == "object" and (.login | type == "string" and length > 0)) and
  (.name | type == "string" and length > 0) and
  (.visibility | IN("public", "private", "internal")) and
  (.fork | type == "boolean") and
  (.archived | type == "boolean") and
  (.default_branch | type == "string" and length > 0)
' "$REQUEST_BODY" > /dev/null; then
  fail 'repository metadata response was malformed'
fi

repo=$(jq -er '.full_name' "$REQUEST_BODY")
owner=$(jq -er '.owner.login' "$REQUEST_BODY")
name=$(jq -er '.name' "$REQUEST_BODY")
readonly repo owner name
gh_endpoint="repos/$repo"
repository_id=$(jq -er '.id | tostring' "$REQUEST_BODY")
visibility=$(jq -er '.visibility' "$REQUEST_BODY")
default_branch=$(jq -er '.default_branch' "$REQUEST_BODY")
readonly repository_id visibility default_branch

encoded_branch=$(jq -nr --arg branch "$default_branch" '$branch | @uri')
commit_endpoint="repos/$repo/commits/$encoded_branch"
api_call "$commit_endpoint" default-branch-commit
save_control_evidence default-branch-commit "$commit_endpoint"
cp -- "$REQUEST_BODY" "$output/default-branch-commit.json"
request_succeeded || fail 'default branch commit request failed'
commit_sha=$(jq -er '.sha | select(type == "string" and test("^[0-9a-f]{40}$"))' "$REQUEST_BODY") ||
  fail 'default branch commit response did not contain a lowercase 40-character SHA'
readonly commit_sha

jq -n \
  --slurpfile metadata "$output/repository-metadata.json" \
  --arg repository_id "$repository_id" \
  --arg repository "$repo" \
  --arg owner "$owner" \
  --arg name "$name" \
  --arg visibility "$visibility" \
  --arg default_branch "$default_branch" \
  --arg commit_sha "$commit_sha" \
  '($metadata[0]) as $m |
   {repository_id: ($repository_id | tonumber), repository: $repository,
    owner: $owner, name: $name, visibility: $visibility, fork: $m.fork,
    archived: $m.archived, default_branch: $default_branch, commit_sha: $commit_sha}' \
  > "$output/target.json"

jq -n '{granted: ["metadata:read", "contents:read", "checks:read", "issues:read", "pull_requests:read"],
  not_granted: ["actions", "administration"],
  limitations: ["Classic branch-protection administrator-only settings are not measured.",
    "The experimental Webhooks check is not supported."]}' > "$output/scorecard-permissions.json"

: > "$tmp/controls.ndjson"
record_control repository_metadata pass observable metadata:read repository-metadata.json "$gh_endpoint"
record_control immutable_default_branch pass immutable-commit contents:read default-branch-commit.json "$commit_endpoint"

rules_endpoint="repos/$repo/rules/branches/$encoded_branch"
api_call "$rules_endpoint" effective-branch-rules
save_control_evidence effective-branch-rules "$rules_endpoint"
if request_succeeded; then
  if jq -e 'type == "array" and all(.[]; type == "object")' "$REQUEST_BODY" > /dev/null; then
    record_control effective_branch_rules pass effective-rules-observed administration:read "$CONTROL_EVIDENCE" "$rules_endpoint"
  else
    record_control effective_branch_rules error malformed-response administration:read "$CONTROL_EVIDENCE" "$rules_endpoint"
  fi
else
  control_failure effective_branch_rules administration:read "$rules_endpoint"
fi

actions_endpoint="repos/$repo/actions/permissions"
api_call "$actions_endpoint" actions-permissions
save_control_evidence actions_permissions "$actions_endpoint"
if request_succeeded; then
  if ! jq -e '
    type == "object" and
    (.sha_pinning_required == null or (.sha_pinning_required | type == "boolean")) and
    (.enabled == null or (.enabled | type == "boolean")) and
    (.allowed_actions == null or (.allowed_actions | type == "string"))
  ' "$REQUEST_BODY" > /dev/null; then
    record_control actions_permissions error malformed-response administration:read "$CONTROL_EVIDENCE" "$actions_endpoint"
  elif [[ "$(jq -r 'if has("sha_pinning_required") then (.sha_pinning_required | tostring) else "" end' "$REQUEST_BODY")" == false ]]; then
    record_control actions_permissions finding sha-pinning-not-required administration:read "$CONTROL_EVIDENCE" "$actions_endpoint"
  elif [[ "$(jq -r 'if has("sha_pinning_required") then (.sha_pinning_required | tostring) else "" end' "$REQUEST_BODY")" == true ]]; then
    record_control actions_permissions pass sha-pinning-required administration:read "$CONTROL_EVIDENCE" "$actions_endpoint"
  else
    record_control actions_permissions unknown not-observable administration:read "$CONTROL_EVIDENCE" "$actions_endpoint"
  fi
else
  control_failure actions_permissions administration:read "$actions_endpoint"
fi

workflow_permissions_endpoint="repos/$repo/actions/permissions/workflow"
api_call "$workflow_permissions_endpoint" workflow-permissions
save_control_evidence workflow_permissions "$workflow_permissions_endpoint"
if request_succeeded; then
  if ! jq -e '
    type == "object" and
    (.default_workflow_permissions == null or (.default_workflow_permissions | IN("read", "write"))) and
    (.can_approve_pull_request_reviews == null or (.can_approve_pull_request_reviews | type == "boolean"))
  ' "$REQUEST_BODY" > /dev/null; then
    record_control workflow_permissions error malformed-response administration:read "$CONTROL_EVIDENCE" "$workflow_permissions_endpoint"
  else
    workflow_default=$(jq -r '.default_workflow_permissions // ""' "$REQUEST_BODY")
    workflow_approve=$(jq -r 'if has("can_approve_pull_request_reviews") then (.can_approve_pull_request_reviews | tostring) else "" end' "$REQUEST_BODY")
    workflow_reason='workflow-permissions-safe'
    if [[ "$workflow_default" == write ]]; then
      workflow_reason='default-workflow-permissions-write'
    elif [[ "$workflow_approve" == true ]]; then
      workflow_reason='workflow-can-approve-pull-request-reviews'
    fi
    if [[ "$workflow_default" == write || "$workflow_approve" == true ]]; then
      record_control workflow_permissions finding "$workflow_reason" administration:read "$CONTROL_EVIDENCE" "$workflow_permissions_endpoint"
    elif [[ -n "$workflow_default" && -n "$workflow_approve" ]]; then
      record_control workflow_permissions pass "$workflow_reason" administration:read "$CONTROL_EVIDENCE" "$workflow_permissions_endpoint"
    else
      record_control workflow_permissions unknown not-observable administration:read "$CONTROL_EVIDENCE" "$workflow_permissions_endpoint"
    fi
  fi
else
  control_failure workflow_permissions administration:read "$workflow_permissions_endpoint"
fi

security_config_endpoint="repos/$repo/code-security-configuration"
api_call "$security_config_endpoint" code-security-configuration
save_control_evidence code_security_configuration "$security_config_endpoint"
if request_succeeded; then
  if [[ "$REQUEST_HTTP_STATUS" == 204 ]]; then
    record_control code_security_configuration pass no-association administration:read "$CONTROL_EVIDENCE" "$security_config_endpoint"
  elif [[ "$REQUEST_HTTP_STATUS" == 200 ]] && jq -e '
    type == "object" and .status == "attached" and (.configuration | type == "object")
  ' "$REQUEST_BODY" > /dev/null; then
    record_control code_security_configuration pass association-observed administration:read "$CONTROL_EVIDENCE" "$security_config_endpoint"
  else
    record_control code_security_configuration error malformed-response administration:read "$CONTROL_EVIDENCE" "$security_config_endpoint"
  fi
else
  control_failure code_security_configuration administration:read "$security_config_endpoint"
fi

security_analysis_present=false
if jq -e '.security_and_analysis != null' "$output/repository-metadata.json" > /dev/null 2>&1; then
  security_analysis_present=true
fi

record_security_control() {
  local id=$1 field=$2
  if [[ "$security_analysis_present" == false ]]; then
    record_control "$id" unknown insufficient-permission administration:read repository-metadata.json "$gh_endpoint"
    return
  fi
  if ! jq -e '.security_and_analysis | type == "object"' "$output/repository-metadata.json" > /dev/null; then
    record_control "$id" error malformed-response administration:read repository-metadata.json "$gh_endpoint"
    return
  fi
  if [[ "$(jq -r --arg field "$field" 'if (.security_and_analysis | has($field)) and .security_and_analysis[$field] != null then "present" else "missing" end' "$output/repository-metadata.json")" == missing ]]; then
    record_control "$id" unknown not-observable administration:read repository-metadata.json "$gh_endpoint"
    return
  fi
  if ! jq -e --arg field "$field" '(.security_and_analysis[$field] | type == "object" and (.status | type == "string"))' "$output/repository-metadata.json" > /dev/null; then
    record_control "$id" error malformed-response administration:read repository-metadata.json "$gh_endpoint"
    return
  fi
  local status
  status=$(jq -r --arg field "$field" '.security_and_analysis[$field].status // ""' "$output/repository-metadata.json")
  case "$status" in
    enabled) record_control "$id" pass enabled administration:read repository-metadata.json "$gh_endpoint" ;;
    disabled) record_control "$id" finding disabled administration:read repository-metadata.json "$gh_endpoint" ;;
    '') record_control "$id" error malformed-response administration:read repository-metadata.json "$gh_endpoint" ;;
    *) record_control "$id" error malformed-response administration:read repository-metadata.json "$gh_endpoint" ;;
  esac
}

record_security_control secret_scanning secret_scanning
record_security_control secret_scanning_push_protection secret_scanning_push_protection

feature_control() {
  local id=$1 endpoint=$2 key=$3 permission=$4
  api_call "$endpoint" "$key"
  save_control_evidence "$key" "$endpoint"
  if request_succeeded; then
    record_control "$id" pass enabled "$permission" "$CONTROL_EVIDENCE" "$endpoint"
  else
    control_failure "$id" "$permission" "$endpoint"
  fi
}

feature_control vulnerability_alerts "repos/$repo/vulnerability-alerts" vulnerability-alerts administration:read
feature_control dependabot_security_updates "repos/$repo/automated-security-fixes" automated-security-fixes administration:read
if [[ "$visibility" == public ]]; then
  private_vulnerability_endpoint="repos/$repo/private-vulnerability-reporting"
  api_call "$private_vulnerability_endpoint" private-vulnerability-reporting
  save_control_evidence private_vulnerability_reporting "$private_vulnerability_endpoint"
  if request_succeeded; then
    if ! jq -e 'type == "object" and (.enabled | type == "boolean")' "$REQUEST_BODY" > /dev/null; then
      record_control private_vulnerability_reporting error malformed-response metadata:read "$CONTROL_EVIDENCE" "$private_vulnerability_endpoint"
    elif [[ "$(jq -r '.enabled' "$REQUEST_BODY")" == true ]]; then
      record_control private_vulnerability_reporting pass enabled metadata:read "$CONTROL_EVIDENCE" "$private_vulnerability_endpoint"
    else
      record_control private_vulnerability_reporting finding disabled metadata:read "$CONTROL_EVIDENCE" "$private_vulnerability_endpoint"
    fi
  else
    control_failure private_vulnerability_reporting metadata:read "$private_vulnerability_endpoint"
  fi
else
  record_control private_vulnerability_reporting unknown unsupported metadata:read repository-metadata.json "$gh_endpoint"
fi

jq -s --arg repository "$repo" --arg commit_sha "$commit_sha" \
  '{schema_version: 1, repository: $repository, commit_sha: $commit_sha, controls: .}' \
  "$tmp/controls.ndjson" > "$output/github-controls.json"

: > "$tmp/scanners.ndjson"

record_scanner() {
  local scanner_name=$1 status=$2 findings=$3 category=${4:-}
  jq -cn \
    --arg name "$scanner_name" --arg status "$status" --argjson findings "$findings" --arg category "$category" \
    '{name: $name, status: $status, findings: $findings} +
      (if $category == "" or $status != "findings" then {} else {category: $category} end)' \
    >> "$tmp/scanners.ndjson"
}

record_all_scanners_error() {
  record_scanner scorecard error 0
  record_scanner zizmor error 0 actions
  record_scanner actionlint error 0 actions
  record_scanner shellcheck error 0 shell
  record_scanner checkov error 0 misconfiguration
  record_scanner trivy-vulnerability error 0 vulnerability
  record_scanner trivy-secret error 0 secret
  record_scanner trivy-misconfiguration error 0 misconfiguration
  record_scanner osv-scanner error 0 vulnerability
  record_scanner semgrep error 0 sast
  record_scanner trufflehog error 0 secret
}

write_empty_scanner_evidence() {
  if [[ ! -e "$output/scanner-versions.txt" ]]; then
    printf '%s\n' 'not run' > "$output/scanner-versions.txt"
  fi
  if [[ ! -e "$output/scanner-versions.log" ]]; then
    printf '%s\n' 'scanner stage was not reached' > "$output/scanner-versions.log"
  fi
  printf '%s\n' '{"checks":[]}' > "$output/scorecard.json"
  printf '%s\n' 2 > "$output/scorecard-status.txt"
  printf '%s\n' '[]' > "$output/zizmor.json"
  printf '%s\n' 2 > "$output/zizmor-status.txt"
  : > "$output/actionlint.jsonl"
  printf '%s\n' 2 > "$output/actionlint-status.txt"
  printf '%s\n' '[]' > "$output/shellcheck.json"
  printf '%s\n' 2 > "$output/shellcheck-status.txt"
  printf '%s\n' 'null' > "$output/checkov.json"
  printf '%s\n' 2 > "$output/checkov-status.txt"
  printf '%s\n' '{"SchemaVersion":2,"Trivy":{},"Results":[]}' > "$output/trivy.json"
  printf '%s\n' 2 > "$output/trivy-status.txt"
  for scanner_kind in osv-scanner semgrep trufflehog; do
    printf '%s\n' 2 > "$output/$scanner_kind-status.txt"
  done
  printf '%s\n' '{"results":[]}' > "$output/osv-scanner.json"
  printf '%s\n' '{"results":[],"errors":[]}' > "$output/semgrep.json"
  printf '%s\n' '[]' > "$output/trufflehog.json"
}

status_value() {
  local file=$1
  if [[ -f "$file" ]]; then
    cat -- "$file"
  else
    printf '%s\n' not-run
  fi
}

build_summary() {
  local overall=$1
  local toolchain_stage checkout_stage versions_stage preflight_stage
  toolchain_stage=$(status_value "$output/toolchain-status.txt")
  checkout_stage=$(status_value "$output/checkout-status.txt")
  versions_stage=$(status_value "$output/versions-status.txt")
  preflight_stage=$(status_value "$output/preflight-status.txt")
  jq -n \
    --slurpfile target "$output/target.json" \
    --slurpfile controls "$output/github-controls.json" \
    --slurpfile scanners "$tmp/scanners.ndjson" \
    --arg overall "$overall" \
    --arg toolchain_stage "$toolchain_stage" --arg checkout_stage "$checkout_stage" \
    --arg versions_stage "$versions_stage" --arg preflight_stage "$preflight_stage" \
    '{schema_version: 1,
      repository: {id: $target[0].repository_id, full_name: $target[0].repository, visibility: $target[0].visibility,
        commit_sha: $target[0].commit_sha},
      overall_status: $overall,
      stage_status: {toolchain: $toolchain_stage, checkout: $checkout_stage,
        versions: $versions_stage, preflight: $preflight_stage},
      scanners: $scanners,
      github_controls: $controls[0].controls,
      evidence_artifact: "repository-security-audit"}' \
    > "$output/summary.json"
  jq '{schema_version: 1,
      gaps: [.github_controls[] | select(.state == "unknown") | {id, reason, required_permission}],
      scanner_gaps: [.scanners[] | select(.status == "error" or .status == "skipped") |
        {id: .name, reason: "scanner-evidence-unavailable", status: .status}],
      stage_gaps: ([.stage_status | to_entries[] | select(.value != "0") |
        {id: .key, reason: "stage-failed-or-not-run", status: .value}]),
      evidence_errors: [.github_controls[] | select(.state == "error") | {id, reason, required_permission}]}' \
    "$output/summary.json" > "$output/coverage-gaps.json"
}

toolchain_status=0
host_os=$(uname -s)
host_arch=$(uname -m)
if [[ "$host_os" == Darwin && "$host_arch" == arm64 ]]; then
  if ! arch -x86_64 /usr/bin/true > "$output/toolchain.log" 2>&1; then
    toolchain_status=1
    printf '%s\n' 'Apple Silicon macOS requires Rosetta 2 for the Darwin x86_64 Checkov binary' >> "$output/toolchain.log"
  fi
fi
if ((toolchain_status == 0)); then
  if ! command -v mise > /dev/null 2>&1; then
    toolchain_status=127
    printf '%s\n' 'mise is required to install and run the skill-local audit toolchain' > "$output/toolchain.log"
  else
    set +e
    mise -y -C "$skill_root" install > "$output/toolchain.log" 2>&1
    toolchain_status=$?
    set -e
  fi
fi
printf '%s\n' "$toolchain_status" > "$output/toolchain-status.txt"

checkout="$tmp/checkout"
readonly checkout
checkout_status=0
if ((toolchain_status == 0)); then
  set +e
  GH_PROMPT_DISABLED=1 GIT_TERMINAL_PROMPT=0 GIT_LFS_SKIP_SMUDGE=1 \
    gh repo clone "$repo" "$checkout" --no-upstream -- \
    --no-checkout --no-tags --no-recurse-submodules \
    > "$output/checkout.log" 2>&1
  checkout_status=$?
  set -e
else
  printf '%s\n' 'toolchain installation failed; checkout was not attempted' > "$output/checkout.log"
  checkout_status=2
fi
printf '%s\n' "$checkout_status" > "$output/checkout-status.txt"

if ((checkout_status == 0)); then
  export GIT_CONFIG_NOSYSTEM=1
  export GIT_CONFIG_GLOBAL=/dev/null
  export GIT_CONFIG_COUNT=0
  unset GIT_CONFIG_PARAMETERS
  set +e
  git -C "$checkout" config --local core.hooksPath /dev/null
  git -C "$checkout" config --local submodule.recurse false
  git -C "$checkout" config --local protocol.file.allow never
  if ! GIT_LFS_SKIP_SMUDGE=1 git -C "$checkout" checkout --detach --force "$commit_sha"; then
    checkout_status=1
  fi
  while IFS= read -r remote; do
    git -C "$checkout" remote remove "$remote" || checkout_status=1
  done < <(git -C "$checkout" remote)
  detached_sha=$(git -C "$checkout" rev-parse HEAD 2> /dev/null || true)
  if [[ "$detached_sha" != "$commit_sha" ]]; then
    checkout_status=1
    printf '%s\n' 'detached checkout did not resolve the planned commit' >> "$output/checkout.log"
  fi
  set -e
fi
printf '%s\n' "$checkout_status" > "$output/checkout-status.txt"

preflight_status=2
if ((checkout_status == 0 && toolchain_status == 0)); then
  set +e
  "$skill_root/scripts/preflight.sh" "$checkout" > "$output/preflight.txt" 2>&1
  preflight_status=$?
  set -e
else
  printf '%s\n' 'checkout or toolchain stage failed; preflight was not attempted' > "$output/preflight.txt"
fi
printf '%s\n' "$preflight_status" > "$output/preflight-status.txt"

if ((toolchain_status != 0 || checkout_status != 0 || preflight_status != 0)); then
  write_empty_scanner_evidence
  record_all_scanners_error
  if ((toolchain_status != 0 || checkout_status != 0)); then
    overall=error
  else
    overall=incomplete
  fi
  build_summary "$overall"
  exit 1
fi

versions_status=0
{
  printf 'scorecard: '
  mise -C "$skill_root" exec -- scorecard version || versions_status=1
  printf 'zizmor: '
  mise -C "$skill_root" exec -- zizmor --version || versions_status=1
  printf 'actionlint: '
  env -u SHELLCHECK_OPTS mise -C "$skill_root" exec -- actionlint -version || versions_status=1
  printf 'shellcheck: '
  env -u SHELLCHECK_OPTS mise -C "$skill_root" exec -- shellcheck --version | head -n 2 | tail -n 1 || versions_status=1
  printf 'checkov: '
  mise -C "$skill_root" exec -- checkov --version || versions_status=1
  printf 'helm: '
  mise -C "$skill_root" exec -- helm version --short || versions_status=1
  printf 'kubectl: '
  mise -C "$skill_root" exec -- kubectl version --client || versions_status=1
  printf 'trivy: '
  mise -C "$skill_root" exec -- trivy --version | head -n 1 || versions_status=1
  printf 'osv-scanner: '
  mise -C "$skill_root" exec -- osv-scanner --version || versions_status=1
  printf 'trufflehog: '
  mise -C "$skill_root" exec -- trufflehog --version || versions_status=1
  printf 'uvx: '
  mise -C "$skill_root" exec -- uvx --version || versions_status=1
} > "$output/scanner-versions.txt" 2> "$output/scanner-versions.log"
printf '%s\n' "$versions_status" > "$output/versions-status.txt"

if ((versions_status != 0)); then
  write_empty_scanner_evidence
  record_all_scanners_error
  build_summary error
  exit 1
fi

# Keep native scanner execution separate from GitHub controls and evidence parsing.
set +e
bash "$skill_root/scripts/run-scanners.sh" "$repo" "$commit_sha" "$checkout" "$output" \
  > "$output/scanners-run.log" 2>&1
scanners_run_status=$?
set -e
printf '%s\n' "$scanners_run_status" > "$output/scanners-run-status.txt"
if ((scanners_run_status != 0)); then
  record_all_scanners_error
  build_summary error
  exit 1
fi

record_array_scanner() {
  local scanner_name=$1 file=$2 status_file=$3 category=$4
  local status count
  status=$(cat -- "$status_file")
  if ! count=$(jq -er 'if type == "array" then length else halt_error(1) end' "$file" 2> /dev/null); then
    record_scanner "$scanner_name" error 0 "$category"
  elif ((count > 0)) && [[ "$status" == 0 || "$status" == 1 ]]; then
    record_scanner "$scanner_name" findings "$count" "$category"
  elif ((count == 0)) && [[ "$status" == 0 ]]; then
    record_scanner "$scanner_name" pass 0
  else
    record_scanner "$scanner_name" error "$count" "$category"
  fi
}

if [[ -s "$output/actionlint.jsonl" ]]; then
  if ! jq -s 'if length == 1 and (.[0] | type == "array") then .[0] else . end' \
    "$output/actionlint.jsonl" > "$output/actionlint.json" 2> "$output/actionlint-parse.log"; then
    printf '%s\n' 'null' > "$output/actionlint.json"
  fi
else
  printf '%s\n' '[]' > "$output/actionlint.json"
fi
record_array_scanner zizmor "$output/zizmor.json" "$output/zizmor-status.txt" actions
record_array_scanner actionlint "$output/actionlint.json" "$output/actionlint-status.txt" actions

shell_status=$(cat -- "$output/shellcheck-status.txt")
if ! shell_count=$(jq -er 'if type == "array" then length elif (.comments | type == "array") then (.comments | length) else halt_error(1) end' \
  "$output/shellcheck.json" 2> /dev/null); then
  record_scanner shellcheck error 0 shell
elif ((shell_count > 0)) && [[ "$shell_status" == 1 ]]; then
  record_scanner shellcheck findings "$shell_count" shell
elif ((shell_count == 0)) && [[ "$shell_status" == 0 ]]; then
  record_scanner shellcheck pass 0
else
  record_scanner shellcheck error "$shell_count" shell
fi

scorecard_status=$(cat -- "$output/scorecard-status.txt")
if [[ "$scorecard_status" == 0 ]] && jq -e '.checks | type == "array" and length > 0 and all(.[]; type == "object")' \
  "$output/scorecard.json" > /dev/null 2>&1; then
  record_scanner scorecard pass 0
else
  record_scanner scorecard error 0
fi

checkov_status=$(cat -- "$output/checkov-status.txt" 2> /dev/null || printf '2')
if checkov_values=$(jq -er '
  (if type == "array" then . else [.] end) as $reports |
  if ($reports | length) == 0 or
     any($reports[]; (.summary | type != "object")) or
     any($reports[]; (.summary.failed | type != "number" or . != floor or . < 0)) or
     any($reports[]; (.summary.skipped | type != "number" or . != floor or . < 0)) or
     any($reports[]; (.summary.parsing_errors | type != "number" or . != floor or . < 0)) then
    halt_error(1)
  else
    [($reports | map(.summary.failed) | add),
     ($reports | map(.summary.skipped) | add),
     ($reports | map(.summary.parsing_errors) | add)] | @tsv
  end
' "$output/checkov.json" 2> /dev/null); then
  IFS=$'\t' read -r checkov_findings checkov_skipped checkov_parsing <<< "$checkov_values"
  if ((checkov_skipped > 0 || checkov_parsing > 0)); then
    record_scanner checkov error 0 misconfiguration
  elif ((checkov_findings > 0)) && [[ "$checkov_status" == 1 ]]; then
    record_scanner checkov findings "$checkov_findings" misconfiguration
  elif ((checkov_findings == 0)) && [[ "$checkov_status" == 0 ]]; then
    record_scanner checkov pass 0
  else
    record_scanner checkov error "$checkov_findings" misconfiguration
  fi
else
  record_scanner checkov error 0 misconfiguration
fi

trivy_status=$(cat -- "$output/trivy-status.txt" 2> /dev/null || printf '2')
if trivy_counts=$(jq -er '
  if type != "object" then halt_error(1) end |
  (if (.Results | type) == "array" then .Results
   elif (.Results == null) and .SchemaVersion == 2 and (.Trivy | type) == "object"
   then []
   else halt_error(1) end) as $rows |
  if any($rows[]; type != "object" or
    ((.Vulnerabilities? != null) and (.Vulnerabilities | type) != "array") or
    ((.Secrets? != null) and (.Secrets | type) != "array") or
    ((.Misconfigurations? != null) and (.Misconfigurations | type) != "array"))
  then halt_error(1)
  else [
    ([$rows[] | .Vulnerabilities[]?] | length),
    ([$rows[] | .Secrets[]?] | length),
    ([$rows[] | .Misconfigurations[]?] | length)
  ] | @tsv end
' "$output/trivy.json" 2> /dev/null); then
  IFS=$'\t' read -r trivy_vuln trivy_secret trivy_misconfig <<< "$trivy_counts"
  trivy_total=$((trivy_vuln + trivy_secret + trivy_misconfig))
  if { [[ "$trivy_status" == 0 ]] && ((trivy_total == 0)); } ||
     { [[ "$trivy_status" == 1 ]] && ((trivy_total > 0)); }; then
    for entry in "vulnerability:$trivy_vuln" "secret:$trivy_secret" "misconfiguration:$trivy_misconfig"; do
      kind=${entry%%:*}
      count=${entry#*:}
      if ((count > 0)); then
        record_scanner "trivy-$kind" findings "$count" "$kind"
      else
        record_scanner "trivy-$kind" pass 0
      fi
    done
  else
    record_scanner trivy-vulnerability error 0 vulnerability
    record_scanner trivy-secret error 0 secret
    record_scanner trivy-misconfiguration error 0 misconfiguration
  fi
else
  record_scanner trivy-vulnerability error 0 vulnerability
  record_scanner trivy-secret error 0 secret
  record_scanner trivy-misconfiguration error 0 misconfiguration
fi

osv_status=$(cat -- "$output/osv-scanner-status.txt")
if [[ "$osv_status" == 128 ]]; then
  record_scanner osv-scanner skipped 0
elif osv_count=$(jq -er '
  if type == "object" and (.results | type == "array") and
     all(.results[]; (.packages | type == "array") and
       all(.packages[]; (.groups | type == "array"))) then
    [.results[].packages[].groups[]] | length
  else halt_error(1) end
' "$output/osv-scanner.json" 2> /dev/null); then
  if ((osv_count > 0)) && [[ "$osv_status" == 1 ]]; then
    record_scanner osv-scanner findings "$osv_count" vulnerability
  elif ((osv_count == 0)) && [[ "$osv_status" == 0 ]]; then
    record_scanner osv-scanner pass 0
  else
    record_scanner osv-scanner error 0 vulnerability
  fi
else
  record_scanner osv-scanner error 0 vulnerability
fi

semgrep_status=$(cat -- "$output/semgrep-status.txt")
if semgrep_count=$(jq -er '
  if type == "object" and (.results | type == "array") and
     (.errors | type == "array") and (.errors | length) == 0 then
    .results | length
  else halt_error(1) end
' "$output/semgrep.json" 2> /dev/null); then
  if ((semgrep_count > 0)) && [[ "$semgrep_status" == 1 ]]; then
    record_scanner semgrep findings "$semgrep_count" sast
  elif ((semgrep_count == 0)) && [[ "$semgrep_status" == 0 ]]; then
    record_scanner semgrep pass 0
  else
    record_scanner semgrep error 0 sast
  fi
else
  record_scanner semgrep error 0 sast
fi

trufflehog_status=$(cat -- "$output/trufflehog-status.txt")
if trufflehog_count=$(jq -er '
  if type == "array" and all(.[];
    (.detector | type == "string") and
    (.verified | type == "boolean") and (.file | type == "string") and
    (.commit | type == "string") and (.line | type == "number")) then
    length
  else halt_error(1) end
' "$output/trufflehog.json" 2> /dev/null) &&
    [[ "$trufflehog_status" == 0 ]]; then
  if ((trufflehog_count > 0)); then
    record_scanner trufflehog findings "$trufflehog_count" secret
  else
    record_scanner trufflehog pass 0
  fi
else
  record_scanner trufflehog error 0 secret
fi

control_error=false
control_finding=false
control_unknown=false
if jq -e '.controls[] | select(.state == "error")' "$output/github-controls.json" > /dev/null; then control_error=true; fi
if jq -e '.controls[] | select(.state == "finding")' "$output/github-controls.json" > /dev/null; then control_finding=true; fi
if jq -e '.controls[] | select(.state == "unknown")' "$output/github-controls.json" > /dev/null; then control_unknown=true; fi
scanner_error=$(jq -s 'any(.[]; .status == "error")' "$tmp/scanners.ndjson")
scanner_finding=$(jq -s 'any(.[]; .status == "findings")' "$tmp/scanners.ndjson")

if [[ "$control_error" == true || "$scanner_error" == true ]]; then
  overall=error
elif [[ "$control_finding" == true || "$scanner_finding" == true ]]; then
  overall=findings
elif [[ "$control_unknown" == true ]]; then
  overall=unknown
else
  overall=pass
fi
build_summary "$overall"

printf 'Audit complete: %s (%s)\n' "$repo" "$overall"
if [[ "$overall" == pass ]]; then
  exit 0
fi
exit 1
