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
assert.call(zizmor.include?("git -C _target ls-files --stage -z"), "zizmor must keep Git-index file selection")
zizmor_pathspecs = [".github/workflows/*.yml", ".github/workflows/*.yaml", "**/action.yml", "**/action.yaml"]
assert.call(zizmor_pathspecs.all? { |pathspec| zizmor.include?(pathspec) }, "zizmor selection must stay limited to workflow and action YAML")
assert.call(zizmor.include?("--offline --no-config --no-ignores --strict-collection"), "zizmor must disable target-owned configuration and ignores")
assert.call(zizmor.include?("printf '[]\\n' > results/zizmor.json"), "zizmor must preserve a successful empty-selection result")

# Native zizmor directory collection is intentionally rejected: workflows/actions modes
# respect target-owned .gitignore files, while collect=all broadens the input kinds.
actionlint = run.call("actionlint")
assert.call(actionlint.include?("git -C _target ls-files --stage -z"), "actionlint must keep Git-index file selection")
assert.call(actionlint.include?(".github/workflows/*.yml") && actionlint.include?(".github/workflows/*.yaml"), "actionlint selection must stay limited to workflow YAML")
assert.call(actionlint.include?("--config-file /dev/null"), "actionlint must not use target-owned configuration")
assert.call(actionlint.include?(": > results/actionlint.jsonl"), "actionlint must preserve a successful empty-selection result")

# Native actionlint repository discovery is intentionally rejected: it recursively walks
# the filesystem and reports a fatal error when no workflow YAML exists.
shellcheck = run.call("shellcheck")
assert.call(shellcheck.include?("git -C _target ls-files --stage -z"), "ShellCheck must keep Git-index file selection")
assert.call(shellcheck.include?("*.sh|*.bash|*.bats") && shellcheck.include?("has_supported_shell_shebang"), "ShellCheck must keep extension and shebang selection")
assert.call(shellcheck.include?("--rcfile /dev/null"), "ShellCheck must not use target-owned configuration")
assert.call(shellcheck.include?("printf '[]\\n' > results/shellcheck.json"), "ShellCheck must preserve a successful empty-selection result")

# ShellCheck has no repository-native collector for this extension-plus-shebang policy.
%w[trivy-vulnerability trivy-secret trivy-misconfiguration].each do |id|
  trivy = run.call(id)
  assert.call(trivy.include?("trivy filesystem"), "#{id} must keep Trivy native filesystem collection")
  assert.call(trivy.include?("--config /dev/null --ignorefile /dev/null"), "#{id} must disable target-owned Trivy config and ignore files")
  assert.call(trivy.include?("--skip-dirs _target/.git"), "#{id} must exclude Git metadata")
  assert.call(trivy.match?(/--skip-version-check\s+_target(?:\s|\\|$)/), "#{id} must scan the preflighted target as the positional filesystem operand")
  assert.call(!trivy.include?("git -C _target ls-files"), "#{id} must not duplicate Trivy's native filesystem collection")
end

puts "scanner collection boundary is valid"
