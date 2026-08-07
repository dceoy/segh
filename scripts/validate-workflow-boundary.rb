# frozen_string_literal: true

require "rubygems"
require "yaml"

ROOT = File.expand_path(ARGV.fetch(0, "."))
ORCHESTRATOR_WORKFLOW = ".github/workflows/organization-dashboard.yml"
ORGANIZATION_WORKFLOW = ".github/workflows/organization-scan.yml"
SELECTION_WORKFLOW = ".github/workflows/organization-selection.yml"
RECONCILE_WORKFLOW = ".github/workflows/dashboard-reconcile.yml"

ALLOWED_REMOTE_ACTIONS = %w[
  actions/checkout
  actions/create-github-app-token
  actions/download-artifact
  actions/github-script
  actions/upload-artifact
  aquaproj/aqua-installer
].freeze

WRITE_JOB_PERMISSIONS = {
  [ORCHESTRATOR_WORKFLOW, "scan"] => {
    "actions" => "read", "contents" => "read", "checks" => "read",
    "issues" => "write", "pull-requests" => "read"
  },
  [ORCHESTRATOR_WORKFLOW, "reconcile"] => {
    "actions" => "read", "contents" => "read", "issues" => "write"
  },
  [ORGANIZATION_WORKFLOW, "publish-dashboard"] => {
    "actions" => "read", "contents" => "read", "issues" => "write"
  },
  [RECONCILE_WORKFLOW, "reconcile"] => {
    "actions" => "read", "contents" => "read", "issues" => "write"
  }
}.freeze

ALLOWED_RESULTS = %w[
  results
  results/actionlint.jsonl
  results/actionlint.log
  results/preflight.txt
  results/scanner-versions.log
  results/scanner-versions.txt
  results/scorecard-permissions.json
  results/scorecard-status.txt
  results/scorecard.json
  results/scorecard.log
  results/shellcheck-status.txt
  results/shellcheck.json
  results/shellcheck.log
  results/summary.json
  results/target.json
  results/trivy-misconfiguration.json
  results/trivy-misconfiguration.log
  results/trivy-secret.json
  results/trivy-secret.log
  results/trivy-vulnerability.json
  results/trivy-vulnerability.log
  results/zizmor.json
  results/zizmor.log
].freeze

MINIMUM_SCANNERS = {
  "ossf/scorecard" => "5.5.0",
  "zizmorcore/zizmor" => "1.28.0",
  "rhysd/actionlint" => "1.7.12",
  "koalaman/shellcheck" => "0.11.0",
  "aquasecurity/trivy" => "0.72.0"
}.freeze

GO_COMMAND = %r{
  (?:^|[;&|()\s])
  (?:["']?(?:\$\(\s*(?:command\s+-v|which)\s+go\s*\)|[^\s;&|()"'`]*\/go|go)["']?)
  \s+(?:test|build|vet|install|run|generate|fmt|env|list|mod|work|tool|version)(?:\s|$)
}x

DIRECT_NETWORK_CLIENT = %r{
  (?:
    \b(?:curl|wget|aria2c|httpie|xh|nc|ncat|netcat|socat)\b |
    \bopenssl\s+s_client\b |
    \bgit\s+(?:clone|fetch|pull|ls-remote)\b |
    \bNet::HTTP\b | \bnet/http\b | \bOpenURI\b | \bURI\.(?:open|parse)\b |
    \b(?:import|from)\s+(?:requests|urllib3?|httpx|aiohttp)\b |
    \b(?:requests|urllib3?|httpx|aiohttp)\s*\.\s*(?:get|post|put|patch|delete|request|Session)\b |
    \b(?:axios|node-fetch)\b |
    \bnode(?:js)?\b[^\n;|&]*\bfetch\s*\(
  )
}x

DIRECT_NETWORK_CLIENT_FIXTURES = [
  "const axios = require('axios')",
  "const fetch = require('node-fetch')",
  "node -e 'fetch(\"https://example.invalid\")'"
].freeze
unless DIRECT_NETWORK_CLIENT_FIXTURES.all? { |fixture| fixture.match?(DIRECT_NETWORK_CLIENT) }
  raise "DIRECT_NETWORK_CLIENT must reject Node direct-network clients"
end

RESULT_PATH = %r{(?<![0-9A-Za-z_.-])results(?:(?:/[0-9A-Za-z_.-]+)+|(?=\s|$))}
VERSION_PATTERN = /\Av?(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)\z/

module Boundary
  module_function

  def fail!(path, message)
    warn "::error file=#{path}::#{message}"
    exit 1
  end

  def load_yaml(path, content)
    YAML.safe_load(content, aliases: false, filename: path)
  rescue Psych::Exception => e
    fail!(path, "Invalid YAML: #{e.message.lines.first&.strip}")
  end

  def read_blob(path, object_id)
    content = IO.popen(["git", "cat-file", "blob", object_id], &:read)
    fail!(path, "Unable to read the tracked blob #{object_id}.") unless $?.success?

    content
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

  def action_identity(action, path)
    fail!(path, "Action reference must be a string.") unless action.is_a?(String)
    return action if action.start_with?("./")

    name = action.sub(/@[^@]+\z/, "")
    fail!(path, "The Go toolchain action is not part of the workflow-only product: #{action}") if name == "actions/setup-go"
    fail!(path, "Remote action is outside the approved workflow profile: #{action}") unless ALLOWED_REMOTE_ACTIONS.include?(name)
    return name if action.match?(/\A[^@\s]+@[0-9a-f]{40}\z/)

    fail!(path, "Remote action is not pinned to a full commit SHA: #{action}")
  end

  def parse_version(value)
    match = value.is_a?(String) && VERSION_PATTERN.match(value)
    match && Gem::Version.new(match[1])
  end
end

Dir.chdir(ROOT) do
  index_entries = IO.popen(["git", "ls-files", "--stage", "-z"], &:read).split("\0").to_h do |entry|
    metadata, path = entry.split("\t", 2)
    mode, object_id, stage = metadata.to_s.split
    [path, {"mode" => mode, "object_id" => object_id, "stage" => stage}]
  end
  Boundary.fail!(".", "The workflow-only product must contain tracked files.") if index_entries.empty?

  index_entries.each do |path, entry|
    mode = entry["mode"]
    unless entry["stage"] == "0" && %w[100644 100755].include?(mode) && entry["object_id"]&.match?(/\A[0-9a-f]{40}\z/)
      Boundary.fail!(path, "Tracked entry must be a stage-0 regular blob with mode 100644 or 100755.")
    end
    if mode == "100755" && !path.start_with?("scripts/")
      Boundary.fail!(path, "Executable tracked files are restricted to scripts/.")
    end
  end

  tracked_files = index_entries.keys
  file_contents = index_entries.to_h do |path, entry|
    [path, Boundary.read_blob(path, entry.fetch("object_id"))]
  end

  required_files = [
    ORCHESTRATOR_WORKFLOW,
    ORGANIZATION_WORKFLOW,
    SELECTION_WORKFLOW,
    RECONCILE_WORKFLOW,
    "scripts/preflight.sh",
    "scripts/validate-workflow-boundary.rb"
  ]
  missing = required_files - tracked_files
  Boundary.fail!(missing.first, "Required workflow-only product surface is missing.") unless missing.empty?

  action_files = tracked_files.select do |path|
    path.match?(%r{\A\.github/workflows/.*\.ya?ml\z}) || File.basename(path).match?(/\Aaction\.ya?ml\z/)
  end
  documents = action_files.to_h do |path|
    [path, Boundary.load_yaml(path, file_contents.fetch(path))]
  end

  forbidden_literals = [
    ["dceoy/gha-for-", "devops"].join,
    ["golang", "ci"].join,
    ["inventory.", "json"].join,
    ["audit.", "json"].join,
    ["scan-manifest.", "json"].join,
    ["scan-summary.", "json"].join,
    ["scan-report.", "md"].join,
    ["reconcile-source-", "scan"].join,
    ["status.", "json"].join
  ]
  file_contents.each do |path, content|
    next if content.include?("\0")

    forbidden_literals.each do |literal|
      Boundary.fail!(path, "Removed product surface reappeared: #{literal}") if content.include?(literal)
    end
  end

  executable_surfaces = []
  documents.each do |path, document|
    Boundary.walk_strings(document) do |node_path, value|
      executable_surfaces << [path, node_path, value] if node_path.last == "run"
    end
  end
  tracked_files.grep(%r{\Ascripts/}).each do |path|
    next if path == "scripts/validate-workflow-boundary.rb"

    content = file_contents.fetch(path)
    executable_surfaces << [path, ["script"], content] unless content.include?("\0")
  end
  executable_surfaces.each do |path, node_path, command|
    Boundary.fail!(path, "Executable surface #{node_path.join("/")} invokes the removed Go toolchain.") if command.match?(GO_COMMAND)
    Boundary.fail!(path, "Executable surface #{node_path.join("/")} uses an unapproved direct network client.") if command.match?(DIRECT_NETWORK_CLIENT)
  end

  documents.each do |path, document|
    next unless path.start_with?(".github/workflows/")

    Boundary.fail!(path, "Top-level permissions must be an explicit empty map.") unless document["permissions"] == {}
    document.fetch("jobs", {}).each do |job_name, job|
      Boundary.fail!(path, "Job #{job_name} must be a mapping.") unless job.is_a?(Hash)
      expected_write = WRITE_JOB_PERMISSIONS[[path, job_name]]
      permissions = job.fetch("permissions", {})
      if expected_write
        Boundary.fail!(path, "Job #{job_name} permissions differ from the approved isolated write contract.") unless permissions == expected_write
      elsif permissions.is_a?(Hash) && permissions.any? { |_, access| access == "write" }
        Boundary.fail!(path, "Job #{job_name} must not request write permissions.")
      end
      Boundary.action_identity(job["uses"], path) if job.key?("uses")
      Array(job["steps"]).each do |step|
        Boundary.fail!(path, "Every workflow step must be a mapping.") unless step.is_a?(Hash)
        Boundary.action_identity(step["uses"], path) if step.key?("uses")
      end
    end
  end

  orchestrator = documents.fetch(ORCHESTRATOR_WORKFLOW)
  orchestrator_jobs = orchestrator.fetch("jobs")
  unless orchestrator.dig("on", "schedule") || file_contents.fetch(ORCHESTRATOR_WORKFLOW).include?("schedule:")
    Boundary.fail!(ORCHESTRATOR_WORKFLOW, "Organization dashboard orchestration must retain a schedule trigger.")
  end
  unless file_contents.fetch(ORCHESTRATOR_WORKFLOW).include?("workflow_dispatch:")
    Boundary.fail!(ORCHESTRATOR_WORKFLOW, "Organization dashboard orchestration must retain manual dispatch.")
  end
  unless orchestrator_jobs.dig("reconcile", "needs") == ["scan", "selection"] &&
         orchestrator_jobs.dig("reconcile", "if").to_s.include?("always()") &&
         orchestrator_jobs.dig("reconcile", "uses") == "./.github/workflows/dashboard-reconcile.yml"
    Boundary.fail!(ORCHESTRATOR_WORKFLOW, "Final reconciliation must run after both scan and selection even when either fails.")
  end

  organization = documents.fetch(ORGANIZATION_WORKFLOW)
  selection = documents.fetch(SELECTION_WORKFLOW)

  organization_jobs = organization.fetch("jobs")
  plan_steps = Array(organization_jobs.fetch("plan")["steps"])
  scan_steps = Array(organization_jobs.fetch("scan")["steps"])
  targets = plan_steps.find { |step| step["id"] == "targets" }
  Boundary.fail!(ORGANIZATION_WORKFLOW, "The immutable target-planning step is missing.") unless targets&.fetch("run", nil).is_a?(String)

  organization_run_steps = organization_jobs.flat_map do |job_name, job|
    Array(job["steps"]).filter_map { |step| [job_name, step["id"], step["run"]] if step["run"].is_a?(String) }
  end
  gh_api_steps = organization_run_steps.select { |_, _, run| run.match?(/\bgh\s+api\b/) }
  unless gh_api_steps.length == 1 && gh_api_steps[0][0, 2] == ["plan", "targets"]
    Boundary.fail!(ORGANIZATION_WORKFLOW, "Only plan/targets may call gh api in the source-scan workflow.")
  end

  targets_run = targets["run"].dup
  [
    /gh\s+api\s+--paginate\s+--slurp\s+\/installation\/repositories/,
    /gh\s+api\s+--method\s+GET\s+"repos\/\$full_name\/commits"\s*\\\s*-f\s+sha="\$default_branch"\s+-f\s+per_page=1/m
  ].each do |pattern|
    Boundary.fail!(ORGANIZATION_WORKFLOW, "The target planner must retain the approved GitHub API calls.") unless targets_run.sub!(pattern, "")
  end
  Boundary.fail!(ORGANIZATION_WORKFLOW, "An unapproved GitHub API call was added to the target planner.") if targets_run.match?(/\bgh\s+api\b/)

  selection_steps = Array(selection.fetch("jobs").fetch("snapshot")["steps"])
  selection_run = selection_steps.find { |step| step["id"] == "selection" }&.fetch("run", nil)
  Boundary.fail!(SELECTION_WORKFLOW, "The complete selection step is missing.") unless selection_run.is_a?(String)
  approved_selection = selection_run.dup
  unless approved_selection.sub!(/gh\s+api\s+--paginate\s+--slurp\s+\/installation\/repositories/, "")
    Boundary.fail!(SELECTION_WORKFLOW, "Selection snapshot must enumerate only the App installation repository endpoint.")
  end
  Boundary.fail!(SELECTION_WORKFLOW, "An unapproved GitHub API call was added to selection capture.") if approved_selection.match?(/\bgh\s+api\b/)

  token_expression = "$" + "{{ inputs.validation_mode && github.token || steps.target-token.outputs.token }}"
  target_index = scan_steps.index { |step| step["id"] == "target-token" }
  checkout_index = scan_steps.index { |step| step["id"] == "checkout" }
  scorecard_index = scan_steps.index { |step| step["id"] == "scorecard" }
  unless target_index && checkout_index && scorecard_index
    Boundary.fail!(ORGANIZATION_WORKFLOW, "The target token, checkout, and Scorecard steps must remain present.")
  end
  expected_token_nodes = {
    ["jobs", "scan", "steps", target_index, "id"] => "target-token",
    ["jobs", "scan", "steps", checkout_index, "with", "token"] => token_expression,
    ["jobs", "scan", "steps", scorecard_index, "env", "SEGH_TARGET_SCORECARD_TOKEN"] => token_expression
  }
  actual_token_nodes = {}
  Boundary.walk_strings(organization) do |node_path, value|
    actual_token_nodes[node_path] = value if value.include?("target-token")
  end
  Boundary.fail!(ORGANIZATION_WORKFLOW, "Target credentials escaped the approved checkout and Scorecard nodes.") unless actual_token_nodes == expected_token_nodes

  artifact_index = scan_steps.index { |step| step["id"] == "artifact" }
  artifact = artifact_index && scan_steps[artifact_index]
  Boundary.fail!(ORGANIZATION_WORKFLOW, "Artifact upload must remain limited to the results directory.") unless artifact&.dig("with", "path") == "results"

  Boundary.walk_strings(organization) do |node_path, value|
    next unless value.match?(/\bresults\b/)
    next if node_path == ["jobs", "scan", "steps", artifact_index, "with", "path"] && value == "results"

    literal_paths = value.scan(RESULT_PATH)
    unexpected = literal_paths.reject { |result| ALLOWED_RESULTS.include?(result) }
    Boundary.fail!(ORGANIZATION_WORKFLOW, "Unapproved results artifact path #{unexpected.first.inspect} at #{node_path.join("/")}.") unless unexpected.empty?

    remaining = value.dup
    literal_paths.uniq.each { |result| remaining.gsub!(result, "") }
    remaining.gsub!(/\bmkdir\s+-p\s+["']?results["']?/, "")
    Boundary.fail!(ORGANIZATION_WORKFLOW, "Dynamically constructed results artifact path at #{node_path.join("/")}.") if remaining.match?(/\bresults\b/)
  end

  aqua = Boundary.load_yaml("aqua.yaml", file_contents.fetch("aqua.yaml"))
  checksum = aqua.fetch("checksum", {})
  unless checksum["enabled"] == true && checksum["require_checksum"] == true
    Boundary.fail!("aqua.yaml", "Aqua checksums must remain enabled and required.")
  end
  registries = aqua.fetch("registries", [])
  registry = registries[0] if registries.is_a?(Array) && registries.length == 1
  registry_version = Boundary.parse_version(registry["ref"]) if registry.is_a?(Hash)
  unless registry.is_a?(Hash) && registry["type"] == "standard" && registry_version && registry_version >= Gem::Version.new("4.544.0")
    Boundary.fail!("aqua.yaml", "The Aqua standard registry must use one explicit non-downgraded semantic-version ref.")
  end
  packages = aqua.fetch("packages", [])
  Boundary.fail!("aqua.yaml", "The trusted Aqua profile must contain exactly five scanners.") unless packages.is_a?(Array) && packages.length == MINIMUM_SCANNERS.length
  MINIMUM_SCANNERS.each_with_index do |(expected, minimum), index|
    package = packages[index]
    name = package.is_a?(Hash) ? package["name"] : nil
    Boundary.fail!("aqua.yaml", "Scanner entry #{index} must contain a string name.") unless name.is_a?(String)
    scanner, separator, package_version = name.rpartition("@")
    actual_version = Boundary.parse_version(package_version)
    next if separator == "@" && scanner == expected && actual_version && actual_version >= Gem::Version.new(minimum)

    Boundary.fail!("aqua.yaml", "Scanner #{index} must be #{expected} at an explicit non-downgraded semantic version.")
  end
end
