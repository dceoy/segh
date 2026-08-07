#!/usr/bin/env ruby

require "json"
require "yaml"

errors = []
fail_if = lambda { |condition, message| errors << message if condition }
stringify = lambda { |value| JSON.generate(value) }
false_value = lambda { |value| value == false || value == "false" }

selection_path = ".github/workflows/organization-selection.yml"
selection_source = File.read(selection_path)
selection = YAML.load_file(selection_path)
selection_job = selection.fetch("jobs").fetch("snapshot")
selection_text = stringify.call(selection_job)

fail_if.call(selection["permissions"] != {}, "selection workflow top-level permissions must be empty")
fail_if.call(selection_job.fetch("permissions") != {}, "selection job permissions must be empty")
fail_if.call(selection_text.include?("issues\":\"write") || selection_text.include?("issues: write"), "selection job must not have issue-write permission")
fail_if.call(selection_text.include?("SEGH_DASHBOARD_REPOSITORY"), "selection job must not receive the dashboard target")

selection_token = Array(selection_job["steps"]).find { |step| step["id"] == "app-token" }
fail_if.call(selection_token.nil?, "selection job must mint the organization read token")
if selection_token
  fail_if.call(selection_token.fetch("uses", "") !~ %r{\Aactions/create-github-app-token@[0-9a-f]{40}\z}, "selection token action must be commit-pinned")
  with = selection_token.fetch("with", {})
  fail_if.call(with["app-id"] != "${{ secrets.SEGH_ORG_SCAN_APP_ID }}", "selection must use the organization scan App ID")
  fail_if.call(with["private-key"] != "${{ secrets.SEGH_ORG_SCAN_APP_PRIVATE_KEY }}", "selection must use the organization scan App private key")
  permissions = with.select { |key, _| key.start_with?("permission-") }
  fail_if.call(permissions != {"permission-contents" => "read", "permission-metadata" => "read"}, "selection token must request only metadata and contents read")
end
fail_if.call(!selection_source.include?("organization-selection-snapshot"), "selection workflow must retain the complete bounded selection snapshot")
fail_if.call(!selection_source.include?("archived") || !selection_source.include?("disabled"), "selection snapshot must preserve archived and disabled repository state")

reconcile_path = ".github/workflows/dashboard-reconcile.yml"
reconcile_source = File.read(reconcile_path)
reconcile = YAML.load_file(reconcile_path)
reconcile_job = reconcile.fetch("jobs").fetch("reconcile")
reconcile_text = stringify.call(reconcile_job)

fail_if.call(reconcile["permissions"] != {}, "reconciliation workflow top-level permissions must be empty")
expected_permissions = {"actions" => "read", "contents" => "read", "issues" => "write"}
fail_if.call(reconcile_job.fetch("permissions") != expected_permissions, "reconciliation job permissions must be actions:read, contents:read, issues:write")
fail_if.call(reconcile_text.include?("secrets."), "reconciliation job must not receive configured secrets")
fail_if.call(reconcile_text.include?("SEGH_ORG_SCAN_APP_"), "reconciliation job must not receive organization scan credentials")
fail_if.call(reconcile_text.include?("SEGH_TARGET_SCORECARD_TOKEN") || reconcile_text.include?("target-token"), "reconciliation job must not receive target scanner credentials")
fail_if.call(!reconcile_text.include?("organization-selection-snapshot"), "reconciliation must consume the complete App selection snapshot")
fail_if.call(!reconcile_text.include?("organization-scan-plan"), "reconciliation must consume the immutable scan plan")
fail_if.call(!reconcile_text.include?("repository-summary-*"), "reconciliation must consume normalized summaries")
fail_if.call(!reconcile_text.include?("reconcile-organization-dashboard.js"), "reconciliation must run the trusted reconciler")
fail_if.call(!reconcile_text.include?("stale_after_hours") && !reconcile_source.include?("stale_after_hours"), "reconciliation must expose a bounded stale threshold")

Array(reconcile_job["steps"]).select { |step| step.fetch("uses", "").start_with?("actions/checkout@") }.each do |checkout|
  fail_if.call(!false_value.call(checkout.fetch("with", {})["persist-credentials"]), "reconciliation checkout must disable credential persistence")
end
Array(reconcile_job["steps"]).select { |step| step.key?("uses") }.each do |step|
  fail_if.call(step["uses"] !~ /@[0-9a-f]{40}\z/, "reconciliation action must be commit-pinned: #{step["uses"]}")
end

if errors.empty?
  puts "reconciliation workflow boundaries are valid"
else
  warn errors.map { |message| "- #{message}" }.join("\n")
  exit 1
end
