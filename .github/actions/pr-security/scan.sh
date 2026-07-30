#!/usr/bin/env bash
set -u -o pipefail

readonly trusted_dir="$GITHUB_WORKSPACE/_segh"
readonly target_dir="$GITHUB_WORKSPACE/_target"
readonly results_dir="$GITHUB_WORKSPACE/security-results"
readonly scanners=(zizmor actionlint shellcheck checkov trivy-vulnerability trivy-secret)

prepare() {
  mkdir -p "$results_dir"
}

reject_symlinks() {
  cd "$target_dir" || return
  index_file="$results_dir/tracked-files.index"
  if ! git ls-files -z --stage > "$index_file"; then
    rm -f -- "$index_file"
    printf '::error::Unable to enumerate the target checkout before scanning.\n'
    return 1
  fi
  rejected=()
  while IFS= read -r -d '' entry; do
    mode=${entry%% *}
    file=${entry#*$'\t'}
    if [[ "$mode" == "120000" ]]; then
      rejected+=("$file")
      if ! rm -f -- "$file"; then
        printf '::error::Unable to remove a tracked symlink before scanning.\n'
        return 1
      fi
    fi
  done < "$index_file"
  rm -f -- "$index_file"
  if ((${#rejected[@]} > 0)); then
    {
      printf 'Rejected %d pull-request-controlled symlink(s) before scanning:\n' \
        "${#rejected[@]}"
      printf '%s\n' "${rejected[@]}"
    } > "$results_dir/rejected-symlinks.txt"
    printf '::warning::Rejected tracked symlinks before scanning; no scanner receives paths outside the pull request checkout.\n'
  else
    printf 'No tracked symlinks were present.\n' > "$results_dir/rejected-symlinks.txt"
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
  fi
  printf '%s\n' "$status" > "$results_dir/zizmor.status"
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
  else
    SHELLCHECK_OPTS="--rcfile=$trusted_dir/.github/security/shellcheckrc" \
      actionlint \
      --no-color \
      --config-file "$trusted_dir/.github/security/actionlint.yaml" \
      --shellcheck shellcheck \
      "${workflow_files[@]}" \
      > "$results_dir/actionlint.txt" 2>&1
    status=$?
    if ((status == 0)) && [[ ! -s "$results_dir/actionlint.txt" ]]; then
      printf 'Passed: actionlint and embedded ShellCheck checked %d workflow files.\n' \
        "${#workflow_files[@]}" > "$results_dir/actionlint.txt"
    fi
  fi
  printf '%s\n' "$status" > "$results_dir/actionlint.status"
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
    if ((status == 0)) && [[ ! -s "$results_dir/shellcheck.txt" ]]; then
      printf 'Passed: ShellCheck checked %d standalone shell scripts.\n' \
        "${#script_files[@]}" > "$results_dir/shellcheck.txt"
    fi
  fi
  printf '%s\n' "$status" > "$results_dir/shellcheck.status"
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
  printf '%s\n' "$status" > "$results_dir/checkov.status"
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
  if ((status == 0 && convert_status != 0)); then
    status=$convert_status
  fi
  printf '%s\n' "$status" > "$results_dir/trivy-vulnerability.status"
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
  if ((status == 0 && convert_status != 0)); then
    status=$convert_status
  fi
  printf '%s\n' "$status" > "$results_dir/trivy-secret.status"
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
    if [[ ! -f "$status_file" ]]; then
      echo "::error::$scanner did not produce a status"
      failed=1
      continue
    fi
    status=$(< "$status_file")
    if [[ ! "$status" =~ ^[0-9]+$ ]] || ((status != 0)); then
      echo "::error::$scanner gate failed with status $status"
      failed=1
    fi
  done
  exit "$failed"
}

case "${1:-}" in
  prepare) prepare ;;
  reject-symlinks) reject_symlinks ;;
  zizmor) run_zizmor ;;
  actionlint) run_actionlint ;;
  shellcheck) run_shellcheck ;;
  checkov) run_checkov ;;
  trivy-vulnerability) run_trivy_vulnerability ;;
  trivy-secret) run_trivy_secret ;;
  summary) publish_summary ;;
  enforce) enforce ;;
  *)
    printf 'usage: %s {prepare|reject-symlinks|zizmor|actionlint|shellcheck|checkov|trivy-vulnerability|trivy-secret|summary|enforce}\n' "$0" >&2
    exit 2
    ;;
esac
