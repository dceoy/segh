#!/usr/bin/env ruby

require "json"
require "yaml"

path = ARGV.fetch(0, ".github/workflows/organization-scan.yml")
source = File.read(path)
workflow = YAML.load_file(path)
jobs = workflow.fetch("jobs")
errors = []

fail_if = lambda do |condition, message|
  errors << message if condition
end

step = lambda do |job, id|
  Array(job["steps"]).find { |candidate| candidate["id"] == id }
end

stringify = lambda { |value| JSON.generate(value) }
false_value = lambda { |value| value == false || value == "false" }

fail_if.call(workflow["permissions"] != {}, "top-level permissions must be an explicit empty map")

jobs.each do |name, job|
  fail_if.call(!job.key?("permissions"), "job #{name} must declare job-level permissions")
  outputs = job["outputs"]
  fail_if.call(outputs && stringify.call(outputs).match?(/token/i), "job #{name} must not expose a token through outputs")
end

plan = jobs.fetch("plan")
scan = jobs.fetch("scan")
publisher = jobs["publish-dashboard"]
plan_text = stringify.call(plan)
scan_text = stringify.call(scan)

fail_if.call(plan["permissions"] != {}, "plan permissions must be an explicit empty map")

scan_permissions = scan.fetch("permissions")
expected_scan_permissions = {
  "contents" => "read",
  "checks" => "read",
  "issues" => "read",
  "pull-requests" => "read"
}
fail_if.call(scan_permissions != expected_scan_permissions, "scan job permissions must be the measured read-only set")
fail_if.call(scan_permissions.values.any? { |value| value == "write" }, "scan job must not have write permission")

plan_token = step.call(plan, "app-token")
fail_if.call(plan_token.nil?, "plan must mint an installation token")
if plan_token
  fail_if.call(plan_token.fetch("uses", "") !~ %r{\Aactions/create-github-app-token@[0-9a-f]{40}\z}, "plan token action must be commit-pinned")
  with = plan_token.fetch("with", {})
  fail_if.call(with["app-id"] != "${{ secrets.SEGH_ORG_SCAN_APP_ID }}", "plan must use the organization scan App ID")
  fail_if.call(with["private-key"] != "${{ secrets.SEGH_ORG_SCAN_APP_PRIVATE_KEY }}", "plan must use the organization scan App private key")
  fail_if.call(with["owner"] != "${{ github.repository_owner }}", "plan token must be installation-scoped to the caller owner")
  fail_if.call(with.key?("repositories"), "plan token must not be repository-scoped")
  expected = {"permission-contents" => "read", "permission-metadata" => "read"}
  actual = with.select { |key, _| key.start_with?("permission-") }
  fail_if.call(actual != expected, "plan token must request only metadata and contents read")
end

resolve_step = step.call(plan, "targets")
if resolve_step
  env = resolve_step.fetch("env", {})
  fail_if.call(env["SEGH_PLAN_TOKEN"] != "${{ steps.app-token.outputs.token }}", "planning token must use SEGH_PLAN_TOKEN")
  fail_if.call(env.key?("GH_TOKEN"), "planning token must not use a configured generic GH_TOKEN environment entry")
end

plan_upload = Array(plan["steps"]).find do |candidate|
  candidate.fetch("uses", "").start_with?("actions/upload-artifact@") &&
    candidate.fetch("with", {})["name"] == "organization-scan-plan"
end
fail_if.call(plan_upload.nil?, "plan must retain the authoritative publication plan")
if plan_upload
  fail_if.call(plan_upload.fetch("uses", "") !~ %r{\Aactions/upload-artifact@[0-9a-f]{40}\z}, "plan artifact action must be commit-pinned")
  fail_if.call(plan_upload.fetch("with", {})["path"] != "matrix.json", "publication plan artifact must contain only matrix.json")
end

target_token = step.call(scan, "target-token")
fail_if.call(target_token.nil?, "scan must mint a repository-scoped token")
if target_token
  fail_if.call(target_token.fetch("uses", "") !~ %r{\Aactions/create-github-app-token@[0-9a-f]{40}\z}, "target token action must be commit-pinned")
  with = target_token.fetch("with", {})
  fail_if.call(with["app-id"] != "${{ secrets.SEGH_ORG_SCAN_APP_ID }}", "scan must use the organization scan App ID")
  fail_if.call(with["private-key"] != "${{ secrets.SEGH_ORG_SCAN_APP_PRIVATE_KEY }}", "scan must use the organization scan App private key")
  fail_if.call(with["owner"] != "${{ matrix.owner }}", "target token owner must come from the current matrix target")
  fail_if.call(with["repositories"] != "${{ matrix.name }}", "target token must be scoped to exactly one matrix repository")
  expected = {
    "permission-checks" => "read",
    "permission-contents" => "read",
    "permission-issues" => "read",
    "permission-metadata" => "read",
    "permission-pull-requests" => "read"
  }
  actual = with.select { |key, _| key.start_with?("permission-") }
  fail_if.call(actual != expected, "target token permissions must match the measured Scorecard read-only set")
end

scorecard = step.call(scan, "scorecard")
if scorecard
  env = scorecard.fetch("env", {})
  fail_if.call(env["SEGH_TARGET_SCORECARD_TOKEN"] != "${{ inputs.validation_mode && github.token || steps.target-token.outputs.token }}", "Scorecard token must use the target-only environment name")
  fail_if.call(env.key?("GITHUB_AUTH_TOKEN"), "Scorecard token must not be stored under a generic job environment key")
end

checkout_steps = Array(scan["steps"]).select { |candidate| candidate.fetch("uses", "").start_with?("actions/checkout@") }
fail_if.call(checkout_steps.empty?, "scan must contain checkout steps")
checkout_steps.each do |checkout|
  with = checkout.fetch("with", {})
  fail_if.call(!false_value.call(with["persist-credentials"]), "every scan checkout must disable credential persistence")
end

target_checkout = checkout_steps.find { |candidate| candidate["id"] == "checkout" }
fail_if.call(target_checkout.nil?, "target checkout step is missing")
if target_checkout
  with = target_checkout.fetch("with", {})
  fail_if.call(!false_value.call(with["lfs"]), "target checkout must disable Git LFS")
  fail_if.call(!false_value.call(with["submodules"]), "target checkout must disable submodules")
  fail_if.call(with["token"] != "${{ inputs.validation_mode && github.token || steps.target-token.outputs.token }}", "target checkout must use only the current target token")
end

summary = step.call(scan, "summary")
fail_if.call(summary.nil?, "scan must build a normalized dashboard summary")
if summary
  fail_if.call(!summary.fetch("run", "").include?("_trusted/scripts/build-dashboard-summary.js"), "summary must be rendered by the trusted implementation")
  fail_if.call(stringify.call(summary).include?("SEGH_ORG_SCAN_APP_"), "summary renderer must not receive organization scan credentials")
end

summary_upload = step.call(scan, "summary-artifact")
fail_if.call(summary_upload.nil?, "scan must upload a bounded dashboard summary")
if summary_upload
  fail_if.call(summary_upload.fetch("uses", "") !~ %r{\Aactions/upload-artifact@[0-9a-f]{40}\z}, "summary artifact action must be commit-pinned")
  fail_if.call(summary_upload.fetch("with", {})["path"] != "results/summary.json", "summary artifact must contain only summary.json")
  fail_if.call(!summary_upload.fetch("with", {})["name"].include?("repository-summary-"), "summary artifact must be keyed by repository ID")
end

upload = step.call(scan, "artifact")
fail_if.call(upload.nil?, "raw evidence artifact upload is missing")
if upload
  artifact_path = upload.fetch("with", {})["path"]
  fail_if.call(artifact_path != "results", "raw artifact upload must be limited to the bounded results directory")
end

fail_if.call(!plan_text.include?("github.event.repository.private"), "plan must inspect caller repository visibility")
fail_if.call(!plan_text.include?("private control repository"), "plan must fail closed outside a private control repository")
fail_if.call(!source.include?("results/scorecard-permissions.json"), "each scan must record Scorecard permission limitations")

fail_if.call(source.include?("SEGH_READ_APP_ID") || source.include?("SEGH_READ_APP_PRIVATE_KEY"), "obsolete generic scan secret names must be removed")
fail_if.call(plan_text.include?("SEGH_PUBLISH_APP_"), "plan must not receive publisher App credentials")
fail_if.call(scan_text.include?("SEGH_PUBLISH_APP_"), "scan must not receive publisher App credentials")

fail_if.call(publisher.nil?, "publish-dashboard job is required")
if publisher
  publisher_text = stringify.call(publisher)
  allowed = {"issues" => "write", "contents" => "read", "actions" => "read"}
  permissions = publisher.fetch("permissions")
  fail_if.call(permissions["issues"] != "write", "publisher must have issues: write")
  permissions.each do |name, access|
    fail_if.call(allowed[name] != access, "publisher permission #{name}: #{access} is outside the credential contract")
  end
  publisher_env = publisher.fetch("env", {})
  fail_if.call(
    publisher_env["SEGH_DASHBOARD_REPOSITORY"] != "${{ github.repository }}",
    "publisher must bind the dashboard target to the caller repository"
  )
  fail_if.call(publisher_text.include?("secrets."), "publisher must not receive configured secrets")
  fail_if.call(publisher_text.include?("SEGH_PUBLISH_APP_"), "publisher must not receive cross-repository publisher App credentials")
  fail_if.call(publisher_text.include?("SEGH_ORG_SCAN_APP_"), "publisher must not receive organization scan App credentials")
  fail_if.call(publisher_text.include?("target-token") || publisher_text.include?("SEGH_TARGET_SCORECARD_TOKEN"), "publisher must not receive target scan credentials")
  fail_if.call(!publisher_text.include?("github.event.repository.private"), "publisher must enforce a private control repository")
  fail_if.call(!publisher_text.include?("organization-scan-plan"), "publisher must consume the authoritative plan artifact")
  fail_if.call(!publisher_text.include?("repository-summary-*"), "publisher must consume only normalized repository summaries")
  fail_if.call(!publisher_text.include?("publish-dashboard.js"), "publisher must use the trusted dashboard implementation")
  fail_if.call(!publisher_text.include?("always()"), "publisher must reconcile after failed matrix jobs")

  Array(publisher["steps"]).select { |candidate| candidate.fetch("uses", "").start_with?("actions/checkout@") }.each do |checkout|
    fail_if.call(!false_value.call(checkout.fetch("with", {})["persist-credentials"]), "publisher checkout must disable credential persistence")
  end
  Array(publisher["steps"]).select { |candidate| candidate.key?("uses") }.each do |candidate|
    fail_if.call(candidate["uses"] !~ /@[0-9a-f]{40}\z/, "publisher action must be pinned: #{candidate["uses"]}")
  end
end

jobs.each do |name, job|
  text = stringify.call(job)
  issues_write = job.fetch("permissions", {})["issues"] == "write"
  scan_secret = text.include?("SEGH_ORG_SCAN_APP_ID") || text.include?("SEGH_ORG_SCAN_APP_PRIVATE_KEY")
  fail_if.call(issues_write && scan_secret, "job #{name} must not combine issue-write and scan credentials")
end

forbidden_diagnostics = [
  /set\s+-x/,
  /printenv/,
  /env\s*>/,
  /Authorization:/i,
  /Bearer\s+\$\{/i
]
forbidden_diagnostics.each do |pattern|
  fail_if.call(source.match?(pattern), "workflow contains forbidden token-bearing diagnostic pattern #{pattern.inspect}")
end

if errors.empty?
  puts "workflow credential boundary is valid"
else
  warn errors.map { |message| "- #{message}" }.join("\n")
  exit 1
end
