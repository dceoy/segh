#!/usr/bin/env bash

set -euo pipefail

readonly root=${1:-.}
readonly workflow=.github/workflows/organization-scan.yml
readonly scan="$root/$workflow"
json=$(mktemp)
readonly json
trap 'rm -f "$json"' EXIT

yq -o=json '.' "$scan" > "$json"

fail() {
  printf '::error file=%s::%s\n' "$workflow" "$1" >&2
  exit 1
}

assert_jq() {
  local expression=$1
  local message=$2
  jq -e "$expression" "$json" > /dev/null || fail "$message"
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

assert_jq '.permissions == {}' 'top-level permissions must be empty'
assert_jq '.jobs.plan.permissions == {}' 'plan job must not receive GITHUB_TOKEN permissions'
assert_jq '.jobs.scan.permissions == {"contents":"read","checks":"read","issues":"read","pull-requests":"read"}' \
  'scan job permissions must stay read-only'

assert_jq '[.jobs.plan.steps[] | select(.id == "app-token")] | length == 1' \
  'plan must mint the organization installation token'
assert_jq '[.jobs.plan.steps[] | select(.id == "app-token")][0].with."app-id" == "\u0024{{ secrets.SEGH_ORG_SCAN_APP_ID }}"' \
  'plan must use the organization scan App ID'
assert_jq '[.jobs.plan.steps[] | select(.id == "app-token")][0].with."private-key" == "\u0024{{ secrets.SEGH_ORG_SCAN_APP_PRIVATE_KEY }}"' \
  'plan must use the organization scan App private key'
assert_jq '([.jobs.plan.steps[] | select(.id == "app-token")][0].with | with_entries(select(.key | startswith("permission-")))) == {"permission-contents":"read","permission-metadata":"read"}' \
  'plan token must request only metadata and contents read'

assert_jq '[.jobs.scan.steps[] | select(.id == "target-token")] | length == 1' \
  'scan must mint a repository-scoped token'
assert_jq '[.jobs.scan.steps[] | select(.id == "target-token")][0].with.owner == "\u0024{{ matrix.owner }}"' \
  'target token owner must come from the matrix'
assert_jq '[.jobs.scan.steps[] | select(.id == "target-token")][0].with.repositories == "\u0024{{ matrix.name }}"' \
  'target token must be scoped to one repository'
assert_jq '([.jobs.scan.steps[] | select(.id == "target-token")][0].with | with_entries(select(.key | startswith("permission-")))) == {"permission-checks":"read","permission-contents":"read","permission-issues":"read","permission-metadata":"read","permission-pull-requests":"read"}' \
  'target token permissions must match the measured Scorecard read-only set'

assert_jq '[.jobs.scan.steps[] | select(.id == "checkout")] | length == 1' 'target checkout is required'
assert_jq '[.jobs.scan.steps[] | select(.id == "checkout")][0].with.ref == "\u0024{{ matrix.commit_sha }}"' \
  'target checkout must bind to the immutable planned SHA'
assert_jq '[.jobs.scan.steps[] | select(.id == "checkout")][0].with."persist-credentials" == false' \
  'target checkout must not persist credentials'
assert_jq '[.jobs.scan.steps[] | select(.id == "checkout")][0].with.lfs == false and [.jobs.scan.steps[] | select(.id == "checkout")][0].with.submodules == false' \
  'target checkout must not expand LFS or submodules'
assert_jq '[.jobs.scan.steps[] | select(.id == "checkout")][0].with.token == "\u0024{{ inputs.validation_mode && github.token || steps.target-token.outputs.token }}"' \
  'target checkout must use only the current target token'

assert_jq '[.jobs.scan.steps[] | select(.id == "scorecard")] | length == 1' 'Scorecard step is required'
assert_jq '[.jobs.scan.steps[] | select(.id == "scorecard")][0].env.SEGH_TARGET_SCORECARD_TOKEN == "\u0024{{ inputs.validation_mode && github.token || steps.target-token.outputs.token }}"' \
  'Scorecard must use only the target token'
assert_jq '(.jobs.scan.env // {}) | has("SEGH_TARGET_SCORECARD_TOKEN") | not' \
  'target token must not be promoted to job environment'

references=$(grep -Fc 'steps.target-token.outputs.token' "$scan" || true)
[[ "$references" == 2 ]] || fail 'target credentials escaped the approved checkout and Scorecard nodes'

assert_jq '.jobs["publish-dashboard"].permissions == {"actions":"read","contents":"read","issues":"write"}' \
  'publisher permissions exceed the current-run dashboard contract'
publisher=$(jq -c '.jobs["publish-dashboard"]' "$json")
assert_absent "$publisher" 'secrets.' 'publisher must not receive configured secrets'
assert_absent "$publisher" 'SEGH_ORG_SCAN_APP_' 'publisher must not receive organization scan credentials'
assert_absent "$publisher" 'target-token' 'publisher must not receive target credentials'
assert_present "$publisher" 'github.event.repository.private' 'publisher must enforce a private control repository'
assert_present "$publisher" 'organization-scan-plan' 'publisher must consume the current run plan'
assert_present "$publisher" 'repository-summary-*' 'publisher must consume current run summaries'
assert_present "$publisher" '_trusted/scripts/publish-dashboard.js' 'publisher must use the trusted implementation'

assert_jq '[.jobs | to_entries[] | select(.value.permissions.issues == "write") | select((.value | tostring | contains("SEGH_ORG_SCAN_APP_ID")) or (.value | tostring | contains("SEGH_ORG_SCAN_APP_PRIVATE_KEY")))] | length == 0' \
  'a job combines issue-write and scan credentials'

printf 'workflow boundary is valid\n'
