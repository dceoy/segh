#!/usr/bin/env bash

set -euo pipefail

readonly root=${1:-.}
readonly workflow=.github/workflows/organization-scan.yml
readonly source_scan="$root/$workflow"
readonly checkov_runner="$root/scripts/run-checkov.sh"

fail() {
  printf '::error file=%s::%s\n' "$workflow" "$1" >&2
  exit 1
}

scan=$(mktemp)
trap 'rm -f "$scan"' EXIT
yq --yaml-fix-merge-anchor-to-spec=true 'explode(.)' "$source_scan" > "$scan" || fail 'invalid YAML'
readonly scan

assert_value() {
  local expression=$1
  local expected=$2
  local message=$3
  local actual
  actual=$(yq -r "$expression" "$scan") || fail "$message"
  [[ "$actual" == "$expected" ]] || fail "$message"
}

assert_json() {
  local expression=$1
  local expected=$2
  local message=$3
  local actual
  actual=$(yq -o=json -I=0 "$expression | sort_keys(.)" "$scan") || fail "$message"
  [[ "$actual" == "$expected" ]] || fail "$message"
}

assert_absent() {
  local text=$1
  local pattern=$2
  local message=$3
  [[ "$text" != *"$pattern"* ]] || fail "$message"
}

assert_present() {
  local text=$1
  local pattern=$2
  local message=$3
  [[ "$text" == *"$pattern"* ]] || fail "$message"
}

assert_json '.permissions' '{}' 'top-level permissions must be empty'
assert_json '.jobs.plan.permissions' '{}' 'plan job must not receive GITHUB_TOKEN permissions'
assert_json '.jobs.scan.permissions' \
  '{"checks":"read","contents":"read","issues":"read","pull-requests":"read"}' \
  'scan job permissions must stay read-only'

assert_value '[.jobs.plan.steps[] | select(.id == "app-token")] | length' '1' \
  'plan must mint the organization installation token'
assert_value '[.jobs.plan.steps[] | select(.id == "app-token")][0].with."app-id"' \
  "\${{ secrets.SEGH_ORG_SCAN_APP_ID }}" 'plan must use the organization scan App ID'
assert_value '[.jobs.plan.steps[] | select(.id == "app-token")][0].with."private-key"' \
  "\${{ secrets.SEGH_ORG_SCAN_APP_PRIVATE_KEY }}" 'plan must use the organization scan App private key'
assert_json \
  '[.jobs.plan.steps[] | select(.id == "app-token")][0].with | with_entries(select(.key | test("^permission-")))' \
  '{"permission-contents":"read","permission-metadata":"read"}' \
  'plan token must request only metadata and contents read'

assert_value '[.jobs.scan.steps[] | select(.id == "target-token")] | length' '1' \
  'scan must mint a repository-scoped token'
assert_value '[.jobs.scan.steps[] | select(.id == "target-token")][0].with.owner' \
  "\${{ matrix.owner }}" 'target token owner must come from the matrix'
assert_value '[.jobs.scan.steps[] | select(.id == "target-token")][0].with.repositories' \
  "\${{ matrix.name }}" 'target token must be scoped to one repository'
assert_json \
  '[.jobs.scan.steps[] | select(.id == "target-token")][0].with | with_entries(select(.key | test("^permission-")))' \
  '{"permission-checks":"read","permission-contents":"read","permission-issues":"read","permission-metadata":"read","permission-pull-requests":"read"}' \
  'target token permissions must match the measured Scorecard read-only set'

assert_value '[.jobs.scan.steps[] | select(.id == "checkout")] | length' '1' 'target checkout is required'
assert_value '[.jobs.scan.steps[] | select(.id == "checkout")][0].with.ref' \
  "\${{ matrix.commit_sha }}" 'target checkout must bind to the immutable planned SHA'
assert_value '[.jobs.scan.steps[] | select(.id == "checkout")][0].with."persist-credentials"' 'false' \
  'target checkout must not persist credentials'
assert_value '[.jobs.scan.steps[] | select(.id == "checkout")][0].with.lfs' 'false' \
  'target checkout must not expand LFS or submodules'
assert_value '[.jobs.scan.steps[] | select(.id == "checkout")][0].with.submodules' 'false' \
  'target checkout must not expand LFS or submodules'
assert_value '[.jobs.scan.steps[] | select(.id == "checkout")][0].with.token' \
  "\${{ inputs.validation_mode && github.token || steps.target-token.outputs.token }}" \
  'target checkout must use only the current target token'

assert_value '[.jobs.scan.steps[] | select(.id == "scorecard")] | length' '1' 'Scorecard step is required'
assert_value '[.jobs.scan.steps[] | select(.id == "scorecard")][0].env.SEGH_TARGET_SCORECARD_TOKEN' \
  "\${{ inputs.validation_mode && github.token || steps.target-token.outputs.token }}" \
  'Scorecard must use only the target token'
assert_value '.jobs.scan.env.SEGH_TARGET_SCORECARD_TOKEN // ""' '' \
  'target token must not be promoted to job environment'

assert_value '[.jobs.scan.steps[] | select(.id == "checkov")] | length' '1' 'Checkov step is required'
checkov=$(yq -o=json '.jobs.scan.steps[] | select(.id == "checkov")' "$scan")
assert_absent "$checkov" '"uses"' 'Checkov must run directly instead of through a wrapper action'
assert_value '[.jobs.scan.steps[] | select(.id == "checkov")][0].run' \
  '_trusted/scripts/run-checkov.sh _target results' 'Checkov must use the trusted scanner runner'
[[ -f "$checkov_runner" ]] || fail 'trusted Checkov runner is missing'
checkov_runner_text=$(cat "$checkov_runner")
assert_present "$checkov_runner_text" 'env -i' 'Checkov must discard inherited configuration environment variables'
assert_present "$checkov_runner_text" 'rm -f -- "$scan_root/.checkov.yml" "$scan_root/.checkov.yaml"' \
  'Checkov must remove target-owned default config files from its static scan view'
assert_present "$checkov_runner_text" 'HOME="$scan_home"' 'Checkov must use an isolated HOME'
assert_present "$checkov_runner_text" '--config-file .github/checkov.yml' 'Checkov must use only trusted configuration'
assert_present "$checkov_runner_text" '--skip-download' 'Checkov must disable remote policy/config downloads'
assert_present "$checkov_runner_text" '--skip-results-upload' 'Checkov must not upload results'
assert_present "$checkov_runner_text" 'CKV_PARSE_ERROR_FAIL=true' 'Checkov parsing errors must fail closed'
assert_present "$checkov_runner_text" 'CHECKOV_HELM_ALLOWED_REMOTE_REPOS=none' \
  'Checkov Helm scanning must block remote dependency repositories'
assert_present "$checkov_runner_text" 'CHECKOV_KUSTOMIZE_ALLOWED_REMOTE_PREFIXES=none' \
  'Checkov Kustomize scanning must block remote resources'
assert_present "$checkov_runner_text" 'checkov.json' 'Checkov native JSON evidence must be retained'
assert_present "$checkov_runner_text" 'checkov-status.txt' 'Checkov execution status must be retained'
assert_absent "$checkov_runner_text" 'external-checks' 'external Checkov checks must not be loaded'
assert_value '[.jobs.scan.steps[] | select(.id == "trivy-misconfiguration")] | length' '0' \
  'Trivy misconfiguration scanning must not remain in the production scanner'
trivy_steps=$(yq -o=json '[.jobs.scan.steps[] | select(.id == "trivy-vulnerability" or .id == "trivy-secret")]' "$scan")
assert_absent "$trivy_steps" '--scanners misconfig' 'Trivy must remain limited to vulnerability and secret scanning'

references=$(
  yq -r '.. | select(tag == "!!str") | select(contains("steps.target-token.outputs.token")) | path | join("/")' "$scan" |
    LC_ALL=C sort
)
allowed_references=$(
  {
    yq -r '.jobs.scan.steps[] | select(.id == "checkout") | .with.token | path | join("/")' "$scan"
    yq -r '.jobs.scan.steps[] | select(.id == "scorecard") | .env.SEGH_TARGET_SCORECARD_TOKEN | path | join("/")' "$scan"
  } | LC_ALL=C sort
)
[[ "$references" == "$allowed_references" ]] || fail 'target credentials escaped the approved checkout and Scorecard nodes'

assert_json '.jobs["publish-dashboard"].permissions' \
  '{"actions":"read","contents":"read","issues":"write"}' \
  'publisher permissions exceed the current-run dashboard contract'
publisher=$(yq -o=json '.jobs["publish-dashboard"]' "$scan")
assert_absent "$publisher" 'secrets.' 'publisher must not receive configured secrets'
assert_absent "$publisher" 'SEGH_ORG_SCAN_APP_' 'publisher must not receive organization scan credentials'
assert_absent "$publisher" 'target-token' 'publisher must not receive target credentials'
assert_present "$publisher" 'github.event.repository.private' 'publisher must enforce a private control repository'
assert_present "$publisher" 'organization-scan-plan' 'publisher must consume the current run plan'
assert_present "$publisher" 'repository-summary-*' 'publisher must consume current run summaries'
assert_present "$publisher" '_trusted/scripts/publish-dashboard.js' 'publisher must use the trusted implementation'

issue_writers=$(yq -o=json '.jobs | to_entries[] | select(.value.permissions.issues == "write") | .value' "$scan")
assert_absent "$issue_writers" 'SEGH_ORG_SCAN_APP_ID' 'a job combines issue-write and scan credentials'
assert_absent "$issue_writers" 'SEGH_ORG_SCAN_APP_PRIVATE_KEY' 'a job combines issue-write and scan credentials'

printf 'workflow boundary is valid\n'
