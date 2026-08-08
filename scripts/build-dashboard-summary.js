#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const path = require("node:path");

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function exists(file) {
  try {
    return fs.statSync(file).isFile();
  } catch {
    return false;
  }
}

function result(name, status, findings = 0, category = null) {
  const scanner = {name, status, findings};
  if (category) scanner.category = category;
  return scanner;
}

function parseScorecard(resultsDir, outcome) {
  if (outcome === "skipped") return result("scorecard", "skipped");
  if (outcome !== "success") return result("scorecard", "error");
  const file = path.join(resultsDir, "scorecard.json");
  if (!exists(file)) return result("scorecard", "error");
  try {
    const data = readJson(file);
    if (!Array.isArray(data?.checks) || data.checks.length === 0 || !data.checks.every((check) =>
      check && typeof check === "object" && typeof check.Name === "string" && check.Name.trim().length > 0 &&
      Number.isFinite(check.Score))) return result("scorecard", "error");
    return result("scorecard", "pass");
  } catch {
    return result("scorecard", "error");
  }
}

function parseJsonArrayScanner(resultsDir, outcome, name, fileName, category) {
  if (outcome === "skipped") return result(name, "skipped", 0, category);
  const file = path.join(resultsDir, fileName);
  if (!exists(file)) return result(name, "error", 0, category);
  try {
    const findings = readJson(file);
    if (!Array.isArray(findings)) return result(name, "error", 0, category);
    if (findings.length) return result(name, "findings", findings.length, category);
    return result(name, outcome === "success" ? "pass" : "error", 0, category);
  } catch {
    return result(name, "error", 0, category);
  }
}

function parseActionlint(resultsDir, outcome) {
  if (outcome === "skipped") return result("actionlint", "skipped", 0, "actions");
  const file = path.join(resultsDir, "actionlint.jsonl");
  if (!exists(file)) return result("actionlint", "error", 0, "actions");
  try {
    const raw = fs.readFileSync(file, "utf8").trim();
    let findings = [];
    if (raw) {
      try {
        const parsed = JSON.parse(raw);
        findings = Array.isArray(parsed) ? parsed : [parsed];
      } catch {
        findings = raw.split(/\r?\n/).filter(Boolean).map((line) => JSON.parse(line));
      }
    }
    if (findings.length) return result("actionlint", "findings", findings.length, "actions");
    return result("actionlint", outcome === "success" ? "pass" : "error", 0, "actions");
  } catch {
    return result("actionlint", "error", 0, "actions");
  }
}

function parseShellcheck(resultsDir, outcome) {
  if (outcome === "skipped") return result("shellcheck", "skipped", 0, "shell");
  const file = path.join(resultsDir, "shellcheck.json");
  const statusFile = path.join(resultsDir, "shellcheck-status.txt");
  if (!exists(file) || !exists(statusFile)) return result("shellcheck", "error", 0, "shell");
  try {
    const data = readJson(file);
    const comments = Array.isArray(data) ? data : data.comments;
    const status = Number.parseInt(fs.readFileSync(statusFile, "utf8").trim(), 10);
    if (!Array.isArray(comments) || !Number.isInteger(status)) return result("shellcheck", "error", 0, "shell");
    if (status === 1 && comments.length) return result("shellcheck", "findings", comments.length, "shell");
    if (status === 0 && outcome === "success" && comments.length === 0) return result("shellcheck", "pass", 0, "shell");
    return result("shellcheck", "error", 0, "shell");
  } catch {
    return result("shellcheck", "error", 0, "shell");
  }
}

function parseTrivy(resultsDir, outcome, kind, property, category) {
  const name = `trivy-${kind}`;
  if (outcome === "skipped") return result(name, "skipped", 0, category);
  const file = path.join(resultsDir, `${name}.json`);
  if (!exists(file)) return result(name, "error", 0, category);
  try {
    const data = readJson(file);
    if (!data || typeof data !== "object" || Array.isArray(data)) return result(name, "error", 0, category);
    let rows;
    if (Array.isArray(data.Results)) rows = data.Results;
    else if (outcome === "success" && data.Results === undefined && data.SchemaVersion === 2 && data.Trivy && typeof data.Trivy === "object") rows = [];
    else return result(name, "error", 0, category);
    const findings = rows.reduce((count, row) => count + (Array.isArray(row?.[property]) ? row[property].length : 0), 0);
    if (findings) return result(name, "findings", findings, category);
    return result(name, outcome === "success" ? "pass" : "error", 0, category);
  } catch {
    return result(name, "error", 0, category);
  }
}

function normalizeOutcome(value) {
  return ["success", "failure", "cancelled", "skipped"].includes(value) ? value : "skipped";
}

function validateTarget(target) {
  if (!Number.isSafeInteger(target?.repository_id) || target.repository_id <= 0) throw new Error("invalid repository_id");
  if (typeof target.repository !== "string" || !target.repository.includes("/")) throw new Error("invalid repository");
  if (!/^[0-9a-f]{40}$/.test(target.commit_sha || "")) throw new Error("invalid commit_sha");
  if (!["public", "private", "internal"].includes(target.visibility)) throw new Error("invalid visibility");
}

function buildSummary({resultsDir, env = process.env, now = new Date()}) {
  const target = readJson(path.join(resultsDir, "target.json"));
  validateTarget(target);
  const outcomes = {
    checkout: normalizeOutcome(env.CHECKOUT_OUTCOME),
    tools: normalizeOutcome(env.TOOLS_OUTCOME),
    versions: normalizeOutcome(env.VERSIONS_OUTCOME),
    preflight: normalizeOutcome(env.PREFLIGHT_OUTCOME),
    scorecard: normalizeOutcome(env.SCORECARD_OUTCOME),
    zizmor: normalizeOutcome(env.ZIZMOR_OUTCOME),
    actionlint: normalizeOutcome(env.ACTIONLINT_OUTCOME),
    shellcheck: normalizeOutcome(env.SHELLCHECK_OUTCOME),
    trivyVulnerability: normalizeOutcome(env.TRIVY_VULNERABILITY_OUTCOME),
    trivySecret: normalizeOutcome(env.TRIVY_SECRET_OUTCOME),
    trivyMisconfiguration: normalizeOutcome(env.TRIVY_MISCONFIGURATION_OUTCOME),
  };

  const scanners = [
    parseScorecard(resultsDir, outcomes.scorecard),
    parseJsonArrayScanner(resultsDir, outcomes.zizmor, "zizmor", "zizmor.json", "actions"),
    parseActionlint(resultsDir, outcomes.actionlint),
    parseShellcheck(resultsDir, outcomes.shellcheck),
    parseTrivy(resultsDir, outcomes.trivyVulnerability, "vulnerability", "Vulnerabilities", "vulnerability"),
    parseTrivy(resultsDir, outcomes.trivySecret, "secret", "Secrets", "secret"),
    parseTrivy(resultsDir, outcomes.trivyMisconfiguration, "misconfiguration", "Misconfigurations", "misconfiguration"),
  ];

  let overallStatus = "pass";
  if (outcomes.checkout !== "success" || outcomes.tools === "failure" || outcomes.versions === "failure") overallStatus = "error";
  else if (outcomes.preflight === "failure") overallStatus = "incomplete";
  else if (scanners.some((scanner) => scanner.status === "error")) overallStatus = "error";
  else if (scanners.some((scanner) => scanner.status === "findings")) overallStatus = "findings";
  else if (scanners.every((scanner) => scanner.status === "skipped")) overallStatus = "error";

  return {
    schema_version: 1,
    repository: {
      id: target.repository_id,
      full_name: target.repository,
      visibility: target.visibility,
      default_branch: target.default_branch,
      commit_sha: target.commit_sha,
    },
    scan: {
      timestamp: now.toISOString(),
      workflow_run_id: target.workflow_run_id,
      workflow_run_attempt: target.workflow_run_attempt,
      workflow_repository: target.trusted_workflow_repository || env.WORKFLOW_REPOSITORY || "",
      workflow_url: `https://github.com/${env.DASHBOARD_REPOSITORY || target.repository}/actions/runs/${target.workflow_run_id}`,
      evidence_artifact: `repository-scan-${target.repository_id}`,
    },
    overall_status: overallStatus,
    scanners,
    findings: {
      total: scanners.reduce((sum, scanner) => sum + scanner.findings, 0),
      categories: [...new Set(scanners.filter((scanner) => scanner.status === "findings" && scanner.category).map((scanner) => scanner.category))].sort(),
    },
  };
}

function main() {
  const resultsDir = process.argv[2] || "results";
  const output = process.argv[3] || path.join(resultsDir, "summary.json");
  const serialized = `${JSON.stringify(buildSummary({resultsDir}), null, 2)}\n`;
  if (Buffer.byteLength(serialized) > 32 * 1024) throw new Error("normalized summary exceeds 32 KiB");
  fs.writeFileSync(output, serialized, {mode: 0o600});
}

if (require.main === module) {
  try {
    main();
  } catch (error) {
    console.error(`build-dashboard-summary: ${error.message}`);
    process.exit(1);
  }
}

module.exports = {buildSummary};
