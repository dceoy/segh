#!/usr/bin/env ruby
# frozen_string_literal: true

require "yaml"

ROOT = File.expand_path(ARGV.fetch(0, "."))
SCAN_WORKFLOW = ".github/workflows/organization-scan.yml"

module Boundary
  module_function

  def fail!(path, message)
    warn "::error file=#{path}::#{message}"
    exit 1
  end

  def assert(condition, path, message)
    fail!(path, message) unless condition
  end

  def load_workflow(path)
    YAML.safe_load_file(path, aliases: false)
  rescue Psych::Exception => e
    fail!(path, "invalid YAML: #{e.message.lines.first&.strip}")
  end

  def step(job, id)
    Array(job["steps"]).find { |candidate| candidate["id"] == id }
  end

  def stringify(value)
    value.inspect
  end

  def walk_strings(node, path = [], &block)
    case node
    when Hash
      node.each { |key, value| walk_strings(value, path + [key], &block) }
    when Array
      node.each_with_index { |value, index| walk_strings(value, path + [index], &block) }
    when String
      block.call(path, node)
    end
  end
end

Dir.chdir(ROOT) do
  scan = Boundary.load_workflow(SCAN_WORKFLOW)
  Boundary.assert(scan["permissions"] == {}, SCAN_WORKFLOW, "top-level permissions must be empty")

  jobs = scan.fetch("jobs")
  plan = jobs.fetch("plan")
  target_scan = jobs.fetch("scan")
  publisher = jobs.fetch("publish-dashboard")

  Boundary.assert(plan["permissions"] == {}, SCAN_WORKFLOW, "plan job must not receive GITHUB_TOKEN permissions")
  expected_scan_permissions = {
    "contents" => "read",
    "checks" => "read",
    "issues" => "read",
    "pull-requests" => "read"
  }
  Boundary.assert(target_scan["permissions"] == expected_scan_permissions, SCAN_WORKFLOW, "scan job permissions must stay read-only")
  Boundary.assert(!target_scan["permissions"].value?("write"), SCAN_WORKFLOW, "scan job must not receive write permission")

  plan_token = Boundary.step(plan, "app-token")
  Boundary.assert(plan_token, SCAN_WORKFLOW, "plan must mint the organization installation token")
  plan_with = plan_token.fetch("with", {})
  Boundary.assert(plan_with["app-id"] == "${{ secrets.SEGH_ORG_SCAN_APP_ID }}", SCAN_WORKFLOW, "plan must use the organization scan App ID")
  Boundary.assert(plan_with["private-key"] == "${{ secrets.SEGH_ORG_SCAN_APP_PRIVATE_KEY }}", SCAN_WORKFLOW, "plan must use the organization scan App private key")
  Boundary.assert(
    plan_with.select { |key, _| key.start_with?("permission-") } == {
      "permission-contents" => "read",
      "permission-metadata" => "read"
    },
    SCAN_WORKFLOW,
    "plan token must request only metadata and contents read"
  )

  target_token = Boundary.step(target_scan, "target-token")
  Boundary.assert(target_token, SCAN_WORKFLOW, "scan must mint a repository-scoped token")
  token_with = target_token.fetch("with", {})
  Boundary.assert(token_with["owner"] == "${{ matrix.owner }}", SCAN_WORKFLOW, "target token owner must come from the matrix")
  Boundary.assert(token_with["repositories"] == "${{ matrix.name }}", SCAN_WORKFLOW, "target token must be scoped to one repository")
  Boundary.assert(
    token_with.select { |key, _| key.start_with?("permission-") } == {
      "permission-checks" => "read",
      "permission-contents" => "read",
      "permission-issues" => "read",
      "permission-metadata" => "read",
      "permission-pull-requests" => "read"
    },
    SCAN_WORKFLOW,
    "target token permissions must match the measured Scorecard read-only set"
  )

  checkout = Boundary.step(target_scan, "checkout")
  Boundary.assert(checkout, SCAN_WORKFLOW, "target checkout is required")
  checkout_with = checkout.fetch("with", {})
  Boundary.assert(checkout_with["ref"] == "${{ matrix.commit_sha }}", SCAN_WORKFLOW, "target checkout must bind to the immutable planned SHA")
  Boundary.assert(checkout_with["persist-credentials"] == false, SCAN_WORKFLOW, "target checkout must not persist credentials")
  Boundary.assert(checkout_with["lfs"] == false && checkout_with["submodules"] == false, SCAN_WORKFLOW, "target checkout must not expand LFS or submodules")
  Boundary.assert(
    checkout_with["token"] == "${{ inputs.validation_mode && github.token || steps.target-token.outputs.token }}",
    SCAN_WORKFLOW,
    "target checkout must use only the current target token"
  )

  scorecard = Boundary.step(target_scan, "scorecard")
  Boundary.assert(
    scorecard&.dig("env", "SEGH_TARGET_SCORECARD_TOKEN") == "${{ inputs.validation_mode && github.token || steps.target-token.outputs.token }}",
    SCAN_WORKFLOW,
    "Scorecard must use only the target token"
  )

  scan_steps = Array(target_scan["steps"])
  checkout_index = scan_steps.index(checkout)
  scorecard_index = scan_steps.index(scorecard)
  token_references = []
  Boundary.walk_strings(target_scan) do |node_path, value|
    token_references << node_path.join("/") if value.include?("steps.target-token.outputs.token")
  end
  Boundary.assert(
    token_references.sort == [
      "steps/#{checkout_index}/with/token",
      "steps/#{scorecard_index}/env/SEGH_TARGET_SCORECARD_TOKEN"
    ].sort,
    SCAN_WORKFLOW,
    "target credentials escaped the approved checkout and Scorecard nodes"
  )
  Boundary.assert(!target_scan.fetch("env", {}).key?("SEGH_TARGET_SCORECARD_TOKEN"), SCAN_WORKFLOW, "target token must not be promoted to job environment")

  expected_publisher_permissions = {"actions" => "read", "contents" => "read", "issues" => "write"}
  Boundary.assert(publisher["permissions"] == expected_publisher_permissions, SCAN_WORKFLOW, "publisher permissions exceed the current-run dashboard contract")
  publisher_text = Boundary.stringify(publisher)
  Boundary.assert(!publisher_text.include?("secrets."), SCAN_WORKFLOW, "publisher must not receive configured secrets")
  Boundary.assert(!publisher_text.include?("SEGH_ORG_SCAN_APP_"), SCAN_WORKFLOW, "publisher must not receive organization scan credentials")
  Boundary.assert(!publisher_text.include?("target-token"), SCAN_WORKFLOW, "publisher must not receive target credentials")
  Boundary.assert(publisher_text.include?("github.event.repository.private"), SCAN_WORKFLOW, "publisher must enforce a private control repository")

  jobs.each do |name, job|
    text = Boundary.stringify(job)
    issues_write = job.fetch("permissions", {})["issues"] == "write"
    scan_secret = text.include?("SEGH_ORG_SCAN_APP_ID") || text.include?("SEGH_ORG_SCAN_APP_PRIVATE_KEY")
    Boundary.assert(!(issues_write && scan_secret), SCAN_WORKFLOW, "job #{name} combines issue-write and scan credentials")
  end
end

puts "workflow boundary is valid"
