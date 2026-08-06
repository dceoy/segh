# frozen_string_literal: true

require "rubygems"
require "yaml"

ROOT = File.expand_path(ARGV.fetch(0, "."))
ORGANIZATION_WORKFLOW = ".github/workflows/organization-scan.yml"
VALIDATION_WORKFLOW = ".github/workflows/validation.yml"
TRUSTED_BOUNDARY_WORKFLOW = ".github/workflows/trusted-boundary.yml"

EXPECTED_PATHS = %w[
  .github/workflows/organization-scan.yml
  .github/workflows/trusted-boundary.yml
  .github/workflows/validation.yml
  CREDENTIALS.md
  LICENSE
  README.md
  SECURITY.md
  aqua-checksums.json
  aqua.yaml
  scripts/preflight.sh
  scripts/test-workflow-security.rb
  scripts/validate-workflow-boundary.rb
].freeze

ALLOWED_RESULTS = %w[
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

ALTERNATE_NETWORK_CLIENT = %r{
  (?:
    \b(?:curl|wget|aria2c|httpie|xh|nc|ncat|netcat|socat)\b |
    \bopenssl\s+s_client\b |
    \bgit\s+(?:clone|fetch|pull|ls-remote)\b |
    \bNet::HTTP\b | \bnet/http\b | \bOpenURI\b | \bURI\.(?:open|parse)\b |
    \b(?:requests|urllib3?|httpx|aiohttp)\b |
    \b(?:axios|node-fetch)\b | \bfetch\s*\( |
    https?://(?:api\.)?github\.com | \bapi\.github\.com\b
  )
}x

RESULT_PATH = %r{(?<![0-9A-Za-z_.-])results(?:/[0-9A-Za-z_.-]+)+}
VERSION_PATTERN = /\Av?(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)\z/

module Boundary
  module_function

  def fail!(path, message)
    warn "::error file=#{path}::#{message}"
    exit 1
  end

  def load_yaml(path)
    YAML.safe_load_file(path, aliases: false)
  rescue Psych::Exception => e
    fail!(path, "Invalid YAML: #{e.message.lines.first&.strip}")
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

  def validate_permissions(permissions, path, scope, publisher: false)
    return if permissions.nil? || permissions == {}

    unless permissions.is_a?(Hash)
      fail!(path, "#{scope} must not request #{permissions} permissions.") if permissions == "write-all"
      return
    end

    if publisher
      allowed = {"issues" => "write", "contents" => "read", "actions" => "read"}
      unless permissions["issues"] == "write" && permissions.all? { |name, access| allowed[name] == access }
        fail!(path, "publish-dashboard permissions exceed the isolated publisher contract.")
      end
    elsif permissions.any? { |_, access| access == "write" }
      fail!(path, "#{scope} must not request write permissions.")
    end
  end

  def validate_action(action, path)
    fail!(path, "Action reference must be a string.") unless action.is_a?(String)
    return if action.start_with?("./")

    name = action.sub(/@[^@]+\z/, "")
    fail!(path, "The Go toolchain action is not part of the workflow-only product: #{action}") if name == "actions/setup-go"
    return if action.match?(/\A[^@\s]+@[0-9a-f]{40}\z/)

    fail!(path, "Remote action is not pinned to a full commit SHA: #{action}")
  end

  def parse_version(value)
    match = value.is_a?(String) && VERSION_PATTERN.match(value)
    match && Gem::Version.new(match[1])
  end
end

Dir.chdir(ROOT) do
  tracked_files = IO.popen(["git", "ls-files", "-z"], &:read).split("\0")
  unless tracked_files == EXPECTED_PATHS
    warn "::error::Tracked path set differs from the workflow-only product allowlist."
    warn "Expected paths:\n  #{EXPECTED_PATHS.join("\n  ")}"
    warn "Actual paths:\n  #{tracked_files.join("\n  ")}"
    exit 1
  end

  action_files = tracked_files.select do |path|
    path.match?(%r{\A\.github/workflows/.*\.ya?ml\z}) || File.basename(path).match?(/\Aaction\.ya?ml\z/)
  end
  documents = action_files.to_h { |path| [path, Boundary.load_yaml(path)] }

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
  tracked_files.each do |path|
    content = File.binread(path)
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

    content = File.binread(path)
    executable_surfaces << [path, ["script"], content] unless content.include?("\0")
  end
  executable_surfaces.each do |path, node_path, command|
    Boundary.fail!(path, "Executable surface #{node_path.join("/")} invokes the removed Go toolchain.") if command.match?(GO_COMMAND)
    if command.match?(ALTERNATE_NETWORK_CLIENT)
      Boundary.fail!(path, "Executable surface #{node_path.join("/")} uses an unapproved network client.")
    end
  end

  documents.each do |path, document|
    if path.start_with?(".github/workflows/")
      Boundary.validate_permissions(document["permissions"], path, "workflow")
      document.fetch("jobs", {}).each do |job_name, job|
        Boundary.fail!(path, "Job #{job_name} must be a mapping.") unless job.is_a?(Hash)
        publisher = path == ORGANIZATION_WORKFLOW && job_name == "publish-dashboard"
        Boundary.validate_permissions(job["permissions"], path, "job #{job_name}", publisher: publisher)
        Boundary.validate_action(job["uses"], path) if job.key?("uses")
        Array(job["steps"]).each do |step|
          Boundary.fail!(path, "Every workflow step must be a mapping.") unless step.is_a?(Hash)
          Boundary.validate_action(step["uses"], path) if step.key?("uses")
        end
      end
    else
      Array(document.dig("runs", "steps")).each do |step|
        Boundary.fail!(path, "Every composite-action step must be a mapping.") unless step.is_a?(Hash)
        Boundary.validate_action(step["uses"], path) if step.key?("uses")
      end
    end
  end

  validation = documents.fetch(VALIDATION_WORKFLOW)
  validation_jobs = validation.fetch("jobs")
  candidate_boundary = validation_jobs.fetch("workflow-only-boundary")
  candidate_steps = Array(candidate_boundary["steps"])
  candidate_validator = candidate_steps.find { |step| step["name"] == "Reject removed product surfaces" }
  unless candidate_validator&.fetch("run", nil) == "ruby scripts/validate-workflow-boundary.rb ." &&
         validation_jobs.dig("production-workflow", "needs") == "workflow-only-boundary" &&
         validation_jobs.dig("production-workflow", "uses") == "./.github/workflows/organization-scan.yml"
    Boundary.fail!(VALIDATION_WORKFLOW, "Candidate validation must retain the boundary gate before the production-path matrix.")
  end

  organization = documents.fetch(ORGANIZATION_WORKFLOW)
  jobs = organization.fetch("jobs")
  plan_steps = Array(jobs.fetch("plan")["steps"])
  scan_steps = Array(jobs.fetch("scan")["steps"])
  targets = plan_steps.find { |step| step["id"] == "targets" }
  Boundary.fail!(ORGANIZATION_WORKFLOW, "The immutable target-planning step is missing.") unless targets&.fetch("run", nil).is_a?(String)

  run_steps = jobs.flat_map do |job_name, job|
    Array(job["steps"]).filter_map do |step|
      [job_name, step["id"], step["run"]] if step["run"].is_a?(String)
    end
  end
  gh_api_steps = run_steps.select { |_, _, run| run.match?(/\bgh\s+api\b/) }
  unless gh_api_steps.length == 1 && gh_api_steps[0][0, 2] == ["plan", "targets"]
    Boundary.fail!(ORGANIZATION_WORKFLOW, "Only plan/targets may call gh api.")
  end

  targets_run = targets["run"].dup
  [
    /gh\s+api\s+--paginate\s+--slurp\s+\/installation\/repositories/,
    /gh\s+api\s+--method\s+GET\s+"repos\/\$full_name\/commits"\s*\\\s*-f\s+sha="\$default_branch"\s+-f\s+per_page=1/m
  ].each do |pattern|
    Boundary.fail!(ORGANIZATION_WORKFLOW, "The target planner must retain the approved GitHub API calls.") unless targets_run.sub!(pattern, "")
  end
  Boundary.fail!(ORGANIZATION_WORKFLOW, "An unapproved GitHub API call was added to the target planner.") if targets_run.match?(/\bgh\s+api\b/)

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
  Boundary.walk_strings(organization) do |path, value|
    actual_token_nodes[path] = value if value.include?("target-token")
  end
  unless actual_token_nodes == expected_token_nodes
    Boundary.fail!(ORGANIZATION_WORKFLOW, "Target credentials must remain limited to the token step, target checkout, and Scorecard environment.")
  end

  artifact_index = scan_steps.index { |step| step["id"] == "artifact" }
  artifact = artifact_index && scan_steps[artifact_index]
  unless artifact&.dig("with", "path") == "results"
    Boundary.fail!(ORGANIZATION_WORKFLOW, "Artifact upload must remain limited to the results directory.")
  end

  Boundary.walk_strings(organization) do |path, value|
    next unless value.match?(/\bresults\b/)
    next if path == ["jobs", "scan", "steps", artifact_index, "with", "path"] && value == "results"

    literal_paths = value.scan(RESULT_PATH)
    unexpected = literal_paths.reject { |result| ALLOWED_RESULTS.include?(result) }
    unless unexpected.empty?
      Boundary.fail!(ORGANIZATION_WORKFLOW, "Unapproved results artifact path #{unexpected.first.inspect} at #{path.join("/")}.")
    end

    remaining = value.dup
    literal_paths.uniq.each { |result| remaining.gsub!(result, "") }
    remaining.gsub!(/\bmkdir\s+-p\s+["']?results["']?/, "")
    if remaining.match?(/\bresults\b/)
      Boundary.fail!(ORGANIZATION_WORKFLOW, "Dynamically constructed results artifact path at #{path.join("/")}.")
    end
  end

  aqua = Boundary.load_yaml("aqua.yaml")
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
  unless packages.is_a?(Array) && packages.length == MINIMUM_SCANNERS.length
    Boundary.fail!("aqua.yaml", "The trusted Aqua profile must contain exactly five scanners.")
  end

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
