"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const {buildSummary} = require("./build-dashboard-summary.js");

function json(file, value) {
  fs.writeFileSync(file, `${JSON.stringify(value)}\n`);
}

const root = fs.mkdtempSync(path.join(os.tmpdir(), "segh-fingerprint-test-"));
json(path.join(root, "target.json"), {
  repository_id: 123, repository: "example/project", visibility: "private", default_branch: "main",
  commit_sha: "a".repeat(40), workflow_run_id: 456, workflow_run_attempt: 1,
});
json(path.join(root, "scorecard.json"), {checks: [{Name: "Token-Permissions", Score: 10}]});
json(path.join(root, "zizmor.json"), []);
fs.writeFileSync(path.join(root, "actionlint.jsonl"), "");
json(path.join(root, "shellcheck.json"), {comments: []});
fs.writeFileSync(path.join(root, "shellcheck-status.txt"), "0\n");
json(path.join(root, "trivy-vulnerability.json"), {Results: []});
json(path.join(root, "trivy-misconfiguration.json"), {Results: []});
const env = {
  CHECKOUT_OUTCOME: "success", TOOLS_OUTCOME: "success", VERSIONS_OUTCOME: "success", PREFLIGHT_OUTCOME: "success",
  SCORECARD_OUTCOME: "success", ZIZMOR_OUTCOME: "success", ACTIONLINT_OUTCOME: "success", SHELLCHECK_OUTCOME: "success",
  TRIVY_VULNERABILITY_OUTCOME: "success", TRIVY_SECRET_OUTCOME: "failure", TRIVY_MISCONFIGURATION_OUTCOME: "success",
  DASHBOARD_REPOSITORY: "control/private",
};
json(path.join(root, "trivy-secret.json"), {Results: [{Target: "a", Secrets: [{RuleID: "aws", Match: "SECRET_A"}]}]});
const first = buildSummary({resultsDir: root, env});
json(path.join(root, "trivy-secret.json"), {Results: [{Target: "a", Secrets: [{RuleID: "aws", Match: "SECRET_B"}]}]});
const second = buildSummary({resultsDir: root, env});
assert.notEqual(first.findings.fingerprint, second.findings.fingerprint);
assert.ok(!JSON.stringify(first).includes("SECRET_A"));
assert.ok(!JSON.stringify(second).includes("SECRET_B"));
console.log("finding fingerprint test passed");
