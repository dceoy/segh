#!/usr/bin/env ruby
# frozen_string_literal: true

require "yaml"

root = File.expand_path(ARGV.fetch(0, "."))
workflow_path = File.join(root, ".github/workflows/organization-scan.yml")
workflow = YAML.safe_load_file(workflow_path, aliases: false)
steps = workflow.fetch("jobs").fetch("scan").fetch("steps")

failure = lambda do |message|
  warn "::error file=.github/workflows/organization-scan.yml::#{message}"
  exit 1
end
assert = ->(condition, message) { failure.call(message) unless condition }
step = lambda do |id|
  found = steps.find { |candidate| candidate["id"] == id }
  failure.call("missing scan step #{id}") unless found
  found
end
run = ->(id) { step.call(id).fetch("run") }
normalize = ->(text) { text.gsub(/\\\n\s*/, " ").gsub(/\s+/, " ").strip }
git_index_command = lambda do |id|
  lines = run.call(id).lines
  index = lines.index { |line| line.include?("done < <(git -C _target ls-files") }
  failure.call("#{id} must collect inputs from the Git index") unless index

  command = lines.fetch(index).sub(/\A.*done < <\(/, "").rstrip
  while command.end_with?("\\")
    command = command.delete_suffix("\\").rstrip
    index += 1
    command = "#{command} #{lines.fetch(index).strip}"
  end
  failure.call("#{id} Git-index collector must remain a single process substitution") unless command.end_with?(")")
  normalize.call(command.delete_suffix(")"))
end

preflight_index = steps.index(step.call("preflight"))
scanner_ids = %w[zizmor actionlint shellcheck trivy-vulnerability trivy-secret trivy-misconfiguration]
scanner_gate = "always() && steps.preflight.outcome == 'success'"
scanner_ids.each do |id|
  scanner = step.call(id)
  assert.call(steps.index(scanner) > preflight_index, "#{id} must run after target preflight")
  assert.call(
    scanner.fetch("if", "").strip == scanner_gate,
    "#{id} must use the fail-closed target preflight gate"
  )
end
assert.call(
  run.call("preflight").include?("_trusted/scripts/preflight.sh _target"),
  "scanner collection must remain gated by the trusted target preflight"
)

zizmor = run.call("zizmor")
expected_zizmor_index = "git -C _target ls-files --stage -z -- '.github/workflows/*.yml' '.github/workflows/*.yaml' ':(glob)**/action.yml' ':(glob)**/action.yaml'"
assert.call(git_index_command.call("zizmor") == expected_zizmor_index, "zizmor Git-index selection must be exactly the workflow/action YAML policy")
assert.call(zizmor.include?("--offline --no-config --no-ignores --strict-collection"), "zizmor must disable target-owned configuration and ignores")
assert.call(zizmor.include?("printf '[]\\n' > results/zizmor.json"), "zizmor must preserve a successful empty-selection result")

# Native zizmor directory collection is intentionally rejected: workflows/actions modes
# respect target-owned .gitignore files, while collect=all broadens the input kinds.
actionlint = run.call("actionlint")
expected_actionlint_index = "git -C _target ls-files --stage -z -- '.github/workflows/*.yml' '.github/workflows/*.yaml'"
assert.call(git_index_command.call("actionlint") == expected_actionlint_index, "actionlint Git-index selection must be exactly the workflow YAML policy")
assert.call(actionlint.include?("--config-file /dev/null"), "actionlint must not use target-owned configuration")
assert.call(actionlint.include?(": > results/actionlint.jsonl"), "actionlint must preserve a successful empty-selection result")

# Native actionlint repository discovery is intentionally rejected: it recursively walks
# the filesystem and reports a fatal error when no workflow YAML exists.
shellcheck = run.call("shellcheck")
assert.call(git_index_command.call("shellcheck") == "git -C _target ls-files --stage -z", "ShellCheck must enumerate exactly the full Git index before applying its file policy")
path_case_start = shellcheck.index('case "$path" in')
path_case_end = path_case_start && shellcheck.index("esac", path_case_start)
failure.call("ShellCheck extension policy is missing") unless path_case_start && path_case_end
path_case = normalize.call(shellcheck[path_case_start...(path_case_end + "esac".length)])
assert.call(path_case == 'case "$path" in *.sh|*.bash|*.bats) include=true ;; esac', "ShellCheck extension selection must stay limited to .sh, .bash, and .bats")
accepted_interpreters = shellcheck.scan(/^\s*([^\n)]+)\)\s+return 0 ;;/).flatten.map(&:strip)
assert.call(accepted_interpreters == ["sh|bash|dash|ksh", "sh|bash|dash|ksh"], "ShellCheck shebang selection must stay limited to sh, bash, dash, and ksh")
assert.call(shellcheck.include?("--rcfile /dev/null"), "ShellCheck must not use target-owned configuration")
assert.call(shellcheck.include?("printf '[]\\n' > results/shellcheck.json"), "ShellCheck must preserve a successful empty-selection result")

# ShellCheck has no repository-native collector for this extension-plus-shebang policy.
trivy_commands = {
  "trivy-vulnerability" => "trivy filesystem --config /dev/null --ignorefile /dev/null --scanners vuln --exit-code 1 --format json --output results/trivy-vulnerability.json --skip-dirs _target/.git --skip-version-check _target 2> results/trivy-vulnerability.log",
  "trivy-secret" => "trivy filesystem --config /dev/null --ignorefile /dev/null --scanners secret --exit-code 1 --format json --output results/trivy-secret.json --skip-dirs _target/.git --skip-version-check _target 2> results/trivy-secret.log",
  "trivy-misconfiguration" => "trivy filesystem --config /dev/null --ignorefile /dev/null --scanners misconfig --exit-code 1 --format json --output results/trivy-misconfiguration.json --skip-dirs _target/.git --skip-version-check _target 2> results/trivy-misconfiguration.log"
}
trivy_commands.each do |id, expected|
  trivy = run.call(id)
  assert.call(normalize.call(trivy) == expected, "#{id} command must keep the exact trusted filesystem collection boundary")
end

puts "scanner collection boundary is valid"
