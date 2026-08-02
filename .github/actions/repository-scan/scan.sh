#!/usr/bin/env bash
set -u -o pipefail

readonly trusted_dir="$GITHUB_WORKSPACE/_segh"
readonly target_dir="$GITHUB_WORKSPACE/_target"
readonly results_dir="$GITHUB_WORKSPACE/security-results"
readonly scanners=(content-validation zizmor actionlint shellcheck checkov trivy-vulnerability trivy-secret)

prepare() {
  mkdir -p "$results_dir"
}

write_result() {
  local scanner=$1
  local status=$2
  local result=${3:-}
  if [[ -z "$result" ]]; then
    case "$status" in
      0) result=pass ;;
      1) result=findings ;;
      *) result=error ;;
    esac
  fi
  printf '%s\n' "$status" > "$results_dir/$scanner.status"
  printf '%s\n' "$result" > "$results_dir/$scanner.result"
}

validate_content() {
  cd "$target_dir" || return
  index_file="$results_dir/tracked-files.index"
  if ! git ls-files -z --stage > "$index_file"; then
    rm -f -- "$index_file"
    printf '::error::Unable to enumerate the target checkout before scanning.\n'
    printf 'Unable to enumerate tracked content.\n' > "$results_dir/content-validation.txt"
    write_result content-validation 2 error
    return 0
  fi
  rejected=()
  incomplete=()
  while IFS= read -r -d '' entry; do
    mode=${entry%% *}
    file=${entry#*$'\t'}
    case "$mode" in
      120000)
        rejected+=("$file")
        if ! rm -f -- "$file"; then
          printf '::error::Unable to remove a tracked symlink before scanning.\n'
          incomplete+=("unable to remove symlink: $file")
        fi
        ;;
      160000)
        incomplete+=("submodule gitlink: $file")
        ;;
      100644 | 100755)
        if [[ -f "$file" ]] && [[ "$(head -n 1 -- "$file" 2> /dev/null || true)" == "version https://git-lfs.github.com/spec/v1" ]]; then
          incomplete+=("Git LFS pointer: $file")
        fi
        ;;
    esac
  done < "$index_file"
  rm -f -- "$index_file"
  if ((${#rejected[@]} > 0)); then
    {
      printf 'Rejected %d target-controlled symlink(s) before scanning:\n' \
        "${#rejected[@]}"
      printf '%s\n' "${rejected[@]}"
    } > "$results_dir/rejected-symlinks.txt"
    printf '::warning::Removed tracked symlinks before scanning; no scanner receives paths outside the target checkout.\n'
  else
    printf 'No tracked symlinks were present.\n' > "$results_dir/rejected-symlinks.txt"
  fi
  if ((${#incomplete[@]} > 0)); then
    {
      printf 'Incomplete repository content (%d item(s)):\n' "${#incomplete[@]}"
      printf '%s\n' "${incomplete[@]}"
    } > "$results_dir/content-validation.txt"
    printf '::error::Repository content is incomplete because tracked Git LFS pointers, submodules, or unremovable symlinks were found.\n'
    write_result content-validation 1 incomplete
  else
    printf 'Passed: repository content is complete static scanner input.\n' > "$results_dir/content-validation.txt"
    write_result content-validation 0 pass
  fi
}

run_zizmor() {
  cd "$target_dir" || return
  set +e
  zizmor \
    --offline \
    --no-config \
    --strict-collection \
    --persona regular \
    --min-severity medium \
    --min-confidence high \
    --format json \
    . > "$results_dir/zizmor.json"
  status=$?
  zizmor \
    --offline \
    --no-config \
    --strict-collection \
    --persona regular \
    --min-severity medium \
    --min-confidence high \
    --no-exit-codes \
    --format plain \
    --color never \
    --render-links never \
    --show-audit-urls always \
    . > "$results_dir/zizmor.txt" 2>&1
  render_status=$?
  if ((render_status != 0)); then
    status=$render_status
    if ((status == 1)); then status=2; fi
  fi
  if [[ ! -s "$results_dir/zizmor.json" ]] || ! jq -e . "$results_dir/zizmor.json" > /dev/null 2>&1; then
    status=2
  fi
  write_result zizmor "$status"
}

run_actionlint() {
  cd "$target_dir" || return
  set +e
  workflow_files=()
  while IFS= read -r -d '' entry; do
    mode=${entry%% *}
    file=${entry#*$'\t'}
    if [[ "$mode" == "100644" || "$mode" == "100755" ]]; then
      workflow_files+=("$file")
    fi
  done < <(git ls-files -z --stage -- '.github/workflows/*.yml' '.github/workflows/*.yaml')
  if ((${#workflow_files[@]} == 0)); then
    printf 'Skipped: no tracked GitHub Actions workflow files.\n' > "$results_dir/actionlint.txt"
    status=0
    result=skipped
  else
    SHELLCHECK_OPTS="--rcfile=$trusted_dir/.github/security/shellcheckrc" \
      actionlint \
      --no-color \
      --config-file "$trusted_dir/.github/security/actionlint.yaml" \
      --shellcheck shellcheck \
      "${workflow_files[@]}" \
      > "$results_dir/actionlint.txt" 2>&1
    status=$?
    result=
    if ((status == 0)) && [[ ! -s "$results_dir/actionlint.txt" ]]; then
      printf 'Passed: actionlint and embedded ShellCheck checked %d workflow files.\n' \
        "${#workflow_files[@]}" > "$results_dir/actionlint.txt"
    fi
  fi
  write_result actionlint "$status" "${result:-}"
}

run_shellcheck() {
  cd "$target_dir" || return
  set +e
  script_files=()
  declare -A seen_scripts=()
  shell_shebang='^#![[:space:]]*(/usr/bin/env([[:space:]]+-S)?[[:space:]]+)?(/[^[:space:]]*/)?(busybox[[:space:]]+)?(sh|ash|dash|bash|ksh93|ksh88|ksh|oksh|bats)([[:space:]]|$)'
  while IFS= read -r -d '' entry; do
    mode=${entry%% *}
    file=${entry#*$'\t'}
    if [[ "$mode" != "100644" && "$mode" != "100755" ]]; then
      continue
    fi
    if [[ "$file" == *.sh || "$file" == *.bash || "$file" == *.bats ]]; then
      script_files+=("$file")
      seen_scripts["$file"]=1
      continue
    fi
    if [[ -n "${seen_scripts[$file]:-}" ]]; then
      continue
    fi
    IFS= read -r -n 256 first_line < "$file" || true
    if [[ "$first_line" =~ $shell_shebang ]]; then
      script_files+=("$file")
      seen_scripts["$file"]=1
    fi
  done < <(git ls-files -z --stage)
  if ((${#script_files[@]} == 0)); then
    printf 'Skipped: no tracked standalone shell scripts.\n' > "$results_dir/shellcheck.txt"
    status=0
    result=skipped
  else
    shellcheck \
      --color=never \
      --format=gcc \
      --rcfile "$trusted_dir/.github/security/shellcheckrc" \
      --severity=style \
      -- \
      "${script_files[@]}" \
      > "$results_dir/shellcheck.txt" 2>&1
    status=$?
    result=
    if ((status == 0)) && [[ ! -s "$results_dir/shellcheck.txt" ]]; then
      printf 'Passed: ShellCheck checked %d standalone shell scripts.\n' \
        "${#script_files[@]}" > "$results_dir/shellcheck.txt"
    fi
  fi
  write_result shellcheck "$status" "${result:-}"
}

run_checkov() {
  cd "$target_dir" || return
  set +e
  checkov \
    --directory . \
    --config-file "$trusted_dir/.github/security/checkov.yaml" \
    --skip-download \
    --output json \
    --output cli \
    --output-file-path "$results_dir/checkov.json,$results_dir/checkov.txt" \
    > "$results_dir/checkov.log" 2>&1
  status=$?
  if ((status == 0)) && [[ ! -s "$results_dir/checkov.txt" ]]; then
    printf 'Skipped: no supported infrastructure-as-code resources were found.\n' \
      > "$results_dir/checkov.txt"
  fi
  if ((status == 0)) && [[ ! -s "$results_dir/checkov.json" ]]; then
    printf '{"results":{"failed_checks":[]}}\n' > "$results_dir/checkov.json"
  fi
  if [[ ! -s "$results_dir/checkov.json" ]] || ! jq -e . "$results_dir/checkov.json" > /dev/null 2>&1; then
    status=2
  fi
  result=
  if ((status == 0)) && grep -q '^Skipped:' "$results_dir/checkov.txt"; then
    result=skipped
  fi
  write_result checkov "$status" "$result"
}

run_trivy_vulnerability() {
  cd "$target_dir" || return
  set +e
  trivy fs \
    --config /dev/null \
    --ignorefile /dev/null \
    --scanners vuln \
    --severity HIGH,CRITICAL \
    --exit-code 1 \
    --format json \
    --output "$results_dir/trivy-vulnerability.json" \
    --skip-dirs .git \
    --skip-version-check \
    . 2> "$results_dir/trivy-vulnerability.log"
  status=$?
  trivy convert \
    --config /dev/null \
    --scanners vuln \
    --format table \
    --output "$results_dir/trivy-vulnerability.txt" \
    "$results_dir/trivy-vulnerability.json"
  convert_status=$?
  if ((convert_status != 0)); then
    status=$convert_status
    if ((status == 1)); then status=2; fi
  fi
  if [[ ! -s "$results_dir/trivy-vulnerability.json" ]] || ! jq -e . "$results_dir/trivy-vulnerability.json" > /dev/null 2>&1; then
    status=2
  fi
  write_result trivy-vulnerability "$status"
}

run_trivy_secret() {
  cd "$target_dir" || return
  set +e
  trivy fs \
    --config /dev/null \
    --ignorefile /dev/null \
    --secret-config "$trusted_dir/.github/security/trivy-secret.yaml" \
    --scanners secret \
    --severity UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL \
    --exit-code 1 \
    --format json \
    --output "$results_dir/trivy-secret.json" \
    --skip-dirs .git \
    --skip-version-check \
    . 2> "$results_dir/trivy-secret.log"
  status=$?
  trivy convert \
    --config /dev/null \
    --scanners secret \
    --format table \
    --output "$results_dir/trivy-secret.txt" \
    "$results_dir/trivy-secret.json"
  convert_status=$?
  if ((convert_status != 0)); then
    status=$convert_status
    if ((status == 1)); then status=2; fi
  fi
  if [[ ! -s "$results_dir/trivy-secret.json" ]] || ! jq -e . "$results_dir/trivy-secret.json" > /dev/null 2>&1; then
    status=2
  fi
  write_result trivy-secret "$status"
}

tool_version() {
  case "$1" in
    content-validation) git --version 2> /dev/null | head -n 1 ;;
    zizmor) zizmor --version 2> /dev/null | head -n 1 ;;
    actionlint) actionlint -version 2> /dev/null | head -n 1 ;;
    shellcheck) shellcheck --version 2> /dev/null | sed -n '2p' ;;
    checkov) checkov --version 2> /dev/null | head -n 1 ;;
    trivy-vulnerability | trivy-secret) trivy --version 2> /dev/null | head -n 1 ;;
  esac
}

finding_count() {
  local scanner=$1
  local result=$2
  if [[ "$result" != "findings" ]]; then
    printf '0\n'
    return
  fi
  case "$scanner" in
    zizmor)
      jq -r 'if type == "array" then length else ([.. | objects | select(has("rule"))] | length) end' "$results_dir/zizmor.json" 2> /dev/null || printf '0\n'
      ;;
    actionlint | shellcheck)
      grep -cve '^[[:space:]]*$' "$results_dir/$scanner.txt" || true
      ;;
    checkov)
      jq -r '[.. | objects | .failed_checks? // empty | arrays | length] | add // 0' "$results_dir/checkov.json" 2> /dev/null || printf '0\n'
      ;;
    trivy-vulnerability)
      jq -r '[.Results[]?.Vulnerabilities[]?] | length' "$results_dir/trivy-vulnerability.json" 2> /dev/null || printf '0\n'
      ;;
    trivy-secret)
      jq -r '[.Results[]?.Secrets[]?] | length' "$results_dir/trivy-secret.json" 2> /dev/null || printf '0\n'
      ;;
    *) printf '0\n' ;;
  esac
}

record_status() {
  if [[ ! "${SEGH_SCAN_REPOSITORY_ID:-}" =~ ^[1-9][0-9]*$ ]] \
    || [[ ! "${SEGH_SCAN_COMMIT_SHA:-}" =~ ^[0-9a-f]{40}$ ]] \
    || [[ "${SEGH_SCAN_REPOSITORY:-}" != */* ]] \
    || [[ -z "${SEGH_SCAN_VISIBILITY:-}" ]] \
    || [[ -z "${SEGH_SCAN_DEFAULT_BRANCH:-}" ]]; then
    printf '::error::Repository scan identity inputs are invalid.\n'
    return 1
  fi
  overall=pass
  jq -n \
    --argjson repository_id "$SEGH_SCAN_REPOSITORY_ID" \
    --arg repository "$SEGH_SCAN_REPOSITORY" \
    --arg visibility "$SEGH_SCAN_VISIBILITY" \
    --arg default_branch "$SEGH_SCAN_DEFAULT_BRANCH" \
    --arg commit_sha "$SEGH_SCAN_COMMIT_SHA" \
    '{schema_version:1,repository_id:$repository_id,repository:$repository,visibility:$visibility,default_branch:$default_branch,commit_sha:$commit_sha,result:"pass",scanners:[]}' \
    > "$results_dir/status.json" || return 1
  for scanner in "${scanners[@]}"; do
    if [[ ! -f "$results_dir/$scanner.status" || ! -f "$results_dir/$scanner.result" ]]; then
      status=2
      result=error
    else
      status=$(< "$results_dir/$scanner.status")
      result=$(< "$results_dir/$scanner.result")
      if [[ ! "$status" =~ ^[0-9]+$ ]] \
        || [[ ! "$result" =~ ^(pass|skipped|findings|incomplete|error)$ ]]; then
        status=2
        result=error
      fi
    fi
    case "$result" in
      error) overall=error ;;
      incomplete)
        if [[ "$overall" != error ]]; then overall=incomplete; fi
        ;;
      findings)
        if [[ "$overall" == pass ]]; then overall=findings; fi
        ;;
    esac
    version=$(tool_version "$scanner")
    if [[ -z "$version" ]]; then
      version=unavailable
      status=2
      result=error
      overall=error
    fi
    count=$(finding_count "$scanner" "$result")
    if [[ ! "$count" =~ ^[0-9]+$ ]]; then count=0; fi
    if [[ "$result" == findings ]] && ((count == 0)); then
      status=2
      result=error
      overall=error
    fi
    temporary="$results_dir/.status.json.tmp"
    jq \
      --arg name "$scanner" --arg version "$version" --argjson exit_status "$status" \
      --arg result "$result" --argjson finding_count "$count" \
      '.scanners += [{name:$name,version:$version,exit_status:$exit_status,result:$result,finding_count:$finding_count}]' \
      "$results_dir/status.json" > "$temporary" || return 1
    mv -- "$temporary" "$results_dir/status.json"
  done
  temporary="$results_dir/.status.json.tmp"
  jq --arg result "$overall" '.result = $result' "$results_dir/status.json" > "$temporary" || return 1
  mv -- "$temporary" "$results_dir/status.json"
}

publish_summary() {
  for scanner in "${scanners[@]}"; do
    {
      printf '## %s\n\n' "$scanner"
      if [[ -f "$results_dir/$scanner.txt" ]]; then
        printf '```\n'
        sed -n '1,200p' "$results_dir/$scanner.txt"
        printf '```\n\n'
      else
        printf 'No human-readable report was produced. See the retained logs.\n\n'
      fi
    } >> "$GITHUB_STEP_SUMMARY"
  done
}

enforce() {
  failed=0
  for scanner in "${scanners[@]}"; do
    status_file="$results_dir/$scanner.status"
    result_file="$results_dir/$scanner.result"
    if [[ ! -f "$status_file" || ! -f "$result_file" ]]; then
      echo "::error::$scanner did not produce valid status evidence"
      failed=1
      continue
    fi
    status=$(< "$status_file")
    result=$(< "$result_file")
    if [[ ! "$status" =~ ^[0-9]+$ ]] \
      || [[ ! "$result" =~ ^(pass|skipped)$ ]] || ((status != 0)); then
      echo "::error::$scanner gate failed with status $status and result $result"
      failed=1
    fi
  done
  exit "$failed"
}

case "${1:-}" in
  prepare) prepare ;;
  validate-content) validate_content ;;
  zizmor) run_zizmor ;;
  actionlint) run_actionlint ;;
  shellcheck) run_shellcheck ;;
  checkov) run_checkov ;;
  trivy-vulnerability) run_trivy_vulnerability ;;
  trivy-secret) run_trivy_secret ;;
  status) record_status ;;
  summary) publish_summary ;;
  enforce) enforce ;;
  *)
    printf 'usage: %s {prepare|validate-content|zizmor|actionlint|shellcheck|checkov|trivy-vulnerability|trivy-secret|status|summary|enforce}\n' "$0" >&2
    exit 2
    ;;
esac
