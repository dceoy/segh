#!/usr/bin/env bash

set -euo pipefail

readonly filter=${1:-skills/repository-security-audit/scripts/billing-exposure.jq}

assert_case() {
  local fixture=$1 code_status=$2 code_exposure=$3 secret_status=$4 secret_exposure=$5
  printf '%s\n' "$fixture" | jq -f "$filter" | jq -e \
    --arg code_status "$code_status" --arg code_exposure "$code_exposure" \
    --arg secret_status "$secret_status" --arg secret_exposure "$secret_exposure" '
      (.features | length == 2) and
      (.features[0].observed_status == $code_status) and
      (.features[0].billing_exposure == $code_exposure) and
      (.features[1].observed_status == $secret_status) and
      (.features[1].billing_exposure == $secret_exposure)
    ' > /dev/null
}

assert_case \
  '{"full_name":"org/public","visibility":"public","security_and_analysis":{"code_security":{"status":"enabled"},"secret_scanning":{"status":"enabled"}}}' \
  enabled no-additional-license-for-public enabled no-additional-license-for-public

assert_case \
  '{"full_name":"org/private","visibility":"private","security_and_analysis":{"code_security":{"status":"enabled"},"secret_scanning":{"status":"enabled"}}}' \
  enabled potential-license-required enabled potential-license-required

assert_case \
  '{"full_name":"org/private","visibility":"private","security_and_analysis":{"advanced_security":{"status":"disabled"},"secret_scanning":{"status":"disabled"},"secret_scanning_push_protection":{"status":"disabled"}}}' \
  unknown unknown disabled not-enabled

assert_case \
  '{"full_name":"org/private","visibility":"private"}' \
  unknown unknown unknown unknown

assert_case \
  '{"full_name":"org/internal","visibility":"internal","security_and_analysis":{"advanced_security":{"status":"enabled"},"code_security":{"status":"disabled"},"secret_scanning":{"status":"disabled"},"secret_scanning_push_protection":{"status":"enabled"}}}' \
  enabled potential-license-required enabled potential-license-required

assert_case \
  '{"full_name":"org/private","visibility":"private","security_and_analysis":{"code_security":{"status":"not_set"},"secret_scanning":{"status":"unexpected"}}}' \
  unknown unknown unknown unknown

assert_case \
  '{"full_name":"org/private","visibility":"private","security_and_analysis":{"secret_scanning_push_protection":{"status":"disabled"}}}' \
  unknown unknown unknown unknown

assert_case \
  '{"full_name":"org/private","visibility":"private","security_and_analysis":{"code_security":{"status":"disabled"},"secret_scanning":{"status":"disabled"}}}' \
  disabled not-enabled disabled not-enabled

assert_case \
  '{"full_name":"org/private","visibility":"private","security_and_analysis":{"advanced_security":{"status":"enabled"}}}' \
  enabled potential-license-required enabled potential-license-required

assert_case \
  '{"full_name":"org/private","visibility":"private","security_and_analysis":{"advanced_security":{"status":"disabled"}}}' \
  unknown unknown unknown unknown

assert_case \
  '{"full_name":"org/private","visibility":"private","security_and_analysis":{"code_security":"enabled","secret_scanning":["enabled"]}}' \
  unknown unknown unknown unknown

assert_case \
  '{"full_name":"org/private","visibility":"private","security_and_analysis":"malformed"}' \
  unknown unknown unknown unknown

printf '%s\n' 'Billing-exposure classification tests passed.'
