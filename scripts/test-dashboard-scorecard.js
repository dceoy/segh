"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const {buildSummary} = require("./build-dashboard-summary.js");

function writeJson(file, value) {
  fs.writeFileSync(file, `${JSON.stringify(value)}\n`);
}

const root = fs.mkdtempSync(path.join(os.tmpdir(), "segh-scorecard-policy-"));
writeJson(path.join(root, "target.json"), {
  repository_id: 123,
  repository: "example/project",
  visibility: "private",
  default_branch: "main",
  commit_sha: "a".repeat(40),
  workflow_run_id: 456,
  workflow_run_attempt: 1,
});
writeJson(path.join(root, "zizmor.json"), []);
fs.writeFileSync(path.join(root, "actionlint.jsonl"), "");
writeJson(path.join(root, "shellcheck.json"), {comments: []});
fs.writeFileSync(path.join(root, "shellcheck-status.txt"), "0\n");
writeJson(path.join(root, "trivy-vulnerability.json"), {Results: []});
writeJson(path.join(root, "trivy-secret.json"), {Results: []});
writeJson(path.join(root, "trivy-misconfiguration.json"), {Results: []});

const env = {
  CHECKOUT_OUTCOME: "success",
  TOOLS_OUTCOME: "success",
  VERSIONS_OUTCOME: "success",
  PREFLIGHT_OUTCOME: "success",
  SCORECARD_OUTCOME: "success",
  ZIZMOR_OUTCOME: "success",
  ACTIONLINT_OUTCOME: "success",
  SHELLCHECK_OUTCOME: "success",
  TRIVY_VULNERABILITY_OUTCOME: "success",
  TRIVY_SECRET_OUTCOME: "success",
  TRIVY_MISCONFIGURATION_OUTCOME: "success",
  DASHBOARD_REPOSITORY: "control/private",
};

writeJson(path.join(root, "scorecard.json"), {
  checks: [
    {Name: "Token-Permissions", Score: 0},
    {Name: "Pinned-Dependencies", Score: 10},
  ],
});
const findings = buildSummary({resultsDir: root, env});
assert.equal(findings.overall_status, "findings");
assert.equal(findings.scanners[0].status, "findings");
assert.equal(findings.scanners[0].findings, 1);
assert.deepEqual(findings.findings.categories, ["scorecard"]);
const firstFingerprint = findings.findings.fingerprint;

writeJson(path.join(root, "scorecard.json"), {
  checks: [
    {Name: "Token-Permissions", Score: 10},
    {Name: "Pinned-Dependencies", Score: 9},
  ],
});
const changed = buildSummary({resultsDir: root, env});
assert.notEqual(changed.findings.fingerprint, firstFingerprint);

writeJson(path.join(root, "scorecard.json"), {
  checks: [
    {Name: "Token-Permissions", Score: 10},
    {Name: "Pinned-Dependencies", Score: 10},
  ],
});
const pass = buildSummary({resultsDir: root, env});
assert.equal(pass.overall_status, "pass");
assert.equal(pass.scanners[0].findings, 0);

console.log("scorecard dashboard policy tests passed");
