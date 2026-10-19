#!/usr/bin/env bash

set -euo pipefail

trusted=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
root=$(mktemp -d)
readonly trusted root
trap 'rm -rf -- "$root"' EXIT
mkdir -p "$root/bin" "$root/_target" "$root/results"
ln -s "$trusted" "$root/_trusted"
git -C "$root/_target" init -q
printf 'safe\n' > "$root/_target/- input file.tf"
git -C "$root/_target" add -- '- input file.tf'
yq -r '.jobs.scan.steps[] | select(.id == "trivy") | .run' \
  "$trusted/.github/workflows/organization-scan.yml" > "$root/workflow.sh"
cat > "$root/bin/trivy" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
touch "$SCANNER_MARKER"
while (($#)); do
  if [[ "$1" == --output ]]; then
    printf '%s\n' '{"SchemaVersion":2,"Trivy":{},"Results":[]}' > "$2"
    break
  fi
  shift
done
STUB
cat > "$root/bin/mise" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
while [[ ${1:-} != -- ]]; do shift; done
shift
exec "$@"
STUB
chmod +x "$root/bin/trivy" "$root/bin/mise"
export PATH="$root/bin:$PATH" SCANNER_MARKER="$root/invoked"

# name | expected status | tracked content; run each case through both paths.
while IFS='|' read -r name expected content; do
  for entry in workflow standalone; do
    printf '%s\n' "$content" > "$root/_target/- input file.tf"
    rm -f -- "$SCANNER_MARKER"
    printf 'stale evidence\n' > "$root/results/trivy.json"
    set +e
    if [[ "$entry" == workflow ]]; then
      (cd -- "$root" && bash workflow.sh)
      status=$?
    else
      bash "$trusted/skills/repository-security-audit/scripts/scanners/trivy.sh" "$root/_target" "$root/results"
      status=$(cat "$root/results/trivy-status.txt")
    fi
    set -e
    [[ "$status" == "$expected" ]] || { printf 'Failed %s/%s: %s\n' "$entry" "$name" "$status" >&2; exit 1; }
    if [[ "$expected" == 2 ]]; then
      [[ ! -e "$SCANNER_MARKER" && ! -s "$root/results/trivy.json" ]]
      grep -F 'Rejected target-owned Trivy suppression directive:' "$root/results/trivy.log" > /dev/null
    else
      [[ -e "$SCANNER_MARKER" ]]
      jq -e '.Results == []' "$root/results/trivy.json" > /dev/null
    fi
    printf 'passed %s/%s\n' "$entry" "$name"
  done
done <<'CASES'
clean|0|resource "fixture" "safe" {}
hash|2|# trivy:ignore:AVD-TEST
compact|2|#trivy:ignore:*
legacy|2|#tfsec:ignore:*
slash|2|//trivy:ignore:*
block|2|/* tfsec:ignore:* */
trailing|2|value = true # trivy:ignore:*
bare|2|trivy:ignore:*
reordered|2|#trivy:exp:2221-01-02:ignore:*
conditional|2|#tfsec:ignore:AVD-TEST[port=443]
CASES

# Enumeration and read failures must not become clean scans.
real_git=$(command -v git)
export REAL_GIT="$real_git"
cat > "$root/bin/git" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
if [[ ${3:-} == ls-files ]]; then exit 42; fi
exec "$REAL_GIT" "$@"
STUB
chmod +x "$root/bin/git"
set +e
"$trusted/skills/repository-security-audit/scripts/validate-trivy-directives.sh" "$root/_target" > "$root/error.log" 2>&1
status=$?
set -e
[[ "$status" == 2 ]]
grep -F 'Unable to enumerate' "$root/error.log" > /dev/null
rm -- "$root/bin/git" "$root/_target/- input file.tf"
set +e
"$trusted/skills/repository-security-audit/scripts/validate-trivy-directives.sh" "$root/_target" > "$root/error.log" 2>&1
status=$?
set -e
[[ "$status" == 2 ]]
grep -F 'Unable to inspect' "$root/error.log" > /dev/null
printf 'Trivy suppression boundary tests passed\n'
