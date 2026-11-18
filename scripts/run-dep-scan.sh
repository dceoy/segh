#!/usr/bin/env bash

set -euo pipefail
umask 077

readonly checkout=${1:?target checkout is required}
readonly output=${2:?evidence directory is required}
readonly image=ghcr.io/owasp-dep-scan/depscan@sha256:085282708983374b216a9d75851898014fe5f6f244a706165b33405bcc3cd7e8
readonly report_dir="$output/dep-scan"
readonly cache_dir="$RUNNER_TEMP/dep-scan-cache"
readonly sbom="$output/dep-scan-input.cdx.json"

mkdir -p -- "$report_dir" "$cache_dir"
# Use only scanner-generated inventory; never mount the target checkout.
trivy filesystem --config /dev/null --ignorefile /dev/null --scanners vuln \
  --format cyclonedx --output "$sbom" --skip-dirs "$checkout/.git" \
  --skip-version-check --disable-telemetry "$checkout" \
  > "$output/dep-scan-sbom.log" 2>&1
jq -e '.bomFormat == "CycloneDX" and (.components | type == "array")' "$sbom" > /dev/null
if jq -e '(.components | length) == 0' "$sbom" > /dev/null; then
  printf 'no-dependencies\n' > "$output/dep-scan-skipped.txt"
  exit 0
fi

# Reject future upstream CLI-major changes rather than silently changing coverage.
docker run --rm --network none --read-only --cap-drop ALL \
  "$image" depscan --src /app --help > /dev/null

docker run --rm \
  --user "$(id -u):$(id -g)" \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --tmpfs /tmp:rw,nosuid,nodev,size=2g \
  --mount "type=bind,source=$(realpath -e -- "$sbom"),target=/input.cdx.json,readonly" \
  --mount "type=bind,source=$(realpath -e -- "$report_dir"),target=/reports" \
  --mount "type=bind,source=$(realpath -e -- "$cache_dir"),target=/cache" \
  --env HOME=/cache \
  --env XDG_CACHE_HOME=/cache/.cache \
  --env VDB_HOME=/cache/vdb \
  --workdir /reports \
  "$image" depscan \
    --bom /input.cdx.json \
    --reports-dir /reports \
    --reachability-analyzer off \
    --no-suggest \
    --csaf \
    --fail-on-error \
  > "$output/dep-scan.log" 2>&1

jq -e '.bomFormat == "CycloneDX" and
  (.vulnerabilities == null or (.vulnerabilities | type == "array"))' \
  "$report_dir/input.vdr.json" > /dev/null
