"use strict";

const fs = require("node:fs");
const path = require("node:path");

function scanner(name, category) {
  return {name, status: "pass", findings: 0, ...(category ? {category} : {})};
}

function summary(overrides = {}) {
  return {
    schema_version: 1,
    repository: {id: 123, full_name: "example/project", visibility: "private", default_branch: "main", commit_sha: "a".repeat(40)},
    scan: {timestamp: "2026-08-07T00:00:00.000Z", workflow_run_id: 456, workflow_run_attempt: 1,
      workflow_repository: "dceoy/segh", workflow_url: "https://github.com/control/private/actions/runs/456", evidence_artifact: "repository-scan-123"},
    overall_status: "pass",
    scanners: [scanner("scorecard"), scanner("zizmor", "actions"), scanner("actionlint", "actions"),
      scanner("shellcheck", "shell"), scanner("trivy-vulnerability", "vulnerability"),
      scanner("trivy-secret", "secret"), scanner("trivy-misconfiguration", "misconfiguration")],
    findings: {total: 0, categories: [], fingerprint: `sha256:${"0".repeat(64)}`},
    remediation_categories: [], ...overrides,
  };
}

function input(root, value) {
  const planPath = path.join(root, "matrix.json");
  const summariesPath = path.join(root, "summaries");
  fs.mkdirSync(path.join(summariesPath, "repository-summary-123"), {recursive: true});
  fs.writeFileSync(planPath, `${JSON.stringify({include: [{id: 123, full_name: "example/project", owner: "example", name: "project", visibility: "private", fork: false, default_branch: "main", commit_sha: "a".repeat(40)}]})}\n`);
  fs.writeFileSync(path.join(summariesPath, "repository-summary-123", "summary.json"), `${JSON.stringify(value)}\n`);
  return {planPath, summariesPath};
}

module.exports = {input, scanner, summary};
