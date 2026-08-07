#!/usr/bin/env ruby

require "json"
require "yaml"

errors = []
fail_if = lambda { |condition, message| errors << message if condition }
stringify = lambda { |value| JSON.generate(value) }
false_value = lambda { |value| value == false || value == "false" }

orchestrator_path = ".github/workflows/organization-dashboard.yml"
orchestrator_source = File.read(orchestrator_path)
orchestrator = YAML.load_file(orchestrator_path)
orchestrator_jobs = orchestrator.fetch("jobs")

fail_if.call(orchestrator["permissions"] != {}, "orchestrator top-level permissions must be empty")
fail_if.call(!orchestrator_source.include?("schedule:"), "orchestrator must provide the weekly schedule")
fail_if.call(!orchestrator_source.include?("workflow_dispatch:"), "orchestrator must provide manual dispatch")
fail_if.call(!orchestrator_source.include?("cancel-in-progress: false"), "orchestrator must not cancel an overlapping organization reconciliation")
scan_job = orchestrator_jobs.fetch("scan")
fail_if.call(scan_job["uses"] != "./.github/workflows/organization-scan.yml", "orchestrator scan job must call the trusted source-scan workflow")
fail_if.call(scan_job.dig("with", "dashboard_publication") != "deferred", "orchestrator must defer source-scan issue publication to final reconciliation")
fail_if.call(orchestrator_jobs.fetch("selection")["uses"] != "./.github/workflows/organization-selection.yml", "orchestrator selection job must call the trusted selection workflow")
final_job = orchestrator_jobs.fetch("reconcile")
fail_if.call(final_job["uses"] != "./.github/workflows/dashboard-reconcile.yml", "orchestrator must call the trusted final reconciliation workflow")
fail_if.call(final_job["needs"] != ["scan", "selection"], "final reconciliation must depend on scan and selection")
fail_if.call(!final_job.fetch("if", "").include?("always()"), "final reconciliation must run after failed scan or selection jobs")
fail_if.call(stringify.call(final_job).include?("secrets."), "final orchestrator reconciliation job must not pass configured secrets")
fail_if.call(final_job.dig("with", "scan_result") != "${{ needs.scan.result }}", "orchestrator must pass the source-scan result to stale-state reconciliation")

source_scan_path = ".github/workflows/organization-scan.yml"
source_scan = YAML.load_file(source_scan_path)
source_scan_jobs = source_scan.fetch("jobs")
publisher_job = source_scan_jobs.fetch("publish-dashboard")
fail_if.call(!publisher_job.fetch("if", "").include?("inputs.dashboard_publication != 'deferred'"), "source-scan publisher must honor deferred publication mode")
summary_artifact = Array(source_scan_jobs.fetch("scan")["steps"]).find { |step| step["id"] == "summary-artifact" }
fail_if.call(summary_artifact.nil?, "source scan must retain a normalized summary artifact")
if summary_artifact
  fail_if.call(summary_artifact.dig("with", "retention-days") != 31, "normalized summary artifacts must outlive the maximum stale threshold")
end

selection_path = ".github/workflows/organization-selection.yml"
selection_source = File.read(selection_path)
selection = YAML.load_file(selection_path)
selection_job = selection.fetch("jobs").fetch("snapshot")
selection_text = stringify.call(selection_job)

fail_if.call(selection["permissions"] != {}, "selection workflow top-level permissions must be empty")
fail_if.call(selection_job.fetch("permissions") != {}, "selection job permissions must be empty")
fail_if.call(selection_text.include?(%q{"issues":"write"}), "selection job must not have issue-write permission")
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
