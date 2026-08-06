#!/usr/bin/env node

"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const STATUS = new Set(["pass", "findings", "incomplete", "error", "skipped"]);
const SCORECARD_CHECKS = new Set([
  "Branch-Protection",
  "Code-Review",
  "Dangerous-Workflow",
  "Pinned-Dependencies",
  "Token-Permissions",
  "Vulnerabilities",
]);

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function fileExists(file) {
  try {
    return fs.statSync(file).isFile();
  } catch {
    return false;
  }
}

function finiteInteger(value, fallback = 0) {
  return Number.isInteger(value) && value >= 0 ? value : fallback;
}

function sha256(value) {
  return `sha256:${crypto.createHash("sha256").update(value).digest("hex")}`;
}

function scanner(name, status, findings, category = null, selectedChecks = []) {
  if (!STATUS.has(status)) throw new Error(`invalid scanner status: ${status}`);
  const result = {
    name,
    status,
    findings: finiteInteger(findings),
  };
  if (category) result.category = category;
  if (selectedChecks.length > 0) result.selected_checks = selectedChecks;
  return result;
}

function parseScorecard(resultsDir, outcome) {
  const file = path.join(resultsDir, "scorecard.json");
  if (outcome === "skipped") return scanner("scorecard", "skipped", 0);
  if (outcome !== "success" || !fileExists(file)) return scanner("scorecard", "error", 0);
  try {
    const data = readJson(file);
    if (!data || typeof data !== "object" || !Array.isArray(data.checks) || data.checks.length === 0) {
      return scanner("scorecard", "error", 0);
    }
    const selected = data.checks
      .map((check) => ({
        name: check.Name ?? check.name,
        score: check.Score ?? check.score,
      }))
      .filter((check) => SCORECARD_CHECKS.has(check.name) && Number.isFinite(check.score))
      .map((check) => ({name: check.name, score: Math.max(0, Math.min(10, check.score))}))
      .sort((a, b) => a.name.localeCompare(b.name));
    return scanner("scorecard", "pass", 0, null, selected);
  } catch {
    return scanner("scorecard", "error", 0);
  }
}

function parseZizmor(resultsDir, outcome) {
  const file = path.join(resultsDir, "zizmor.json");
  if (outcome === "skipped") return scanner("zizmor", "skipped", 0, "actions");
  if (!fileExists(file)) return scanner("zizmor", "error", 0, "actions");
  try {
    const data = readJson(file);
    if (!Array.isArray(data)) return scanner("zizmor", "error", 0, "actions");
    const count = data.length;
    if (outcome === "success" && count === 0) return scanner("zizmor", "pass", 0, "actions");
    if (count > 0) return scanner("zizmor", "findings", count, "actions");
    return scanner("zizmor", "error", 0, "actions");
  } catch {
    return scanner("zizmor", "error", 0, "actions");
  }
}

function parseActionlint(resultsDir, outcome) {
  const file = path.join(resultsDir, "actionlint.jsonl");
  if (outcome === "skipped") return scanner("actionlint", "skipped", 0, "actions");
  if (!fileExists(file)) return scanner("actionlint", "error", 0, "actions");
  try {
    const lines = fs.readFileSync(file, "utf8").split(/\r?\n/).filter(Boolean);
    for (const line of lines) JSON.parse(line);
    if (outcome === "success" && lines.length === 0) return scanner("actionlint", "pass", 0, "actions");
    if (lines.length > 0) return scanner("actionlint", "findings", lines.length, "actions");
    return scanner("actionlint", "error", 0, "actions");
  } catch {
    return scanner("actionlint", "error", 0, "actions");
  }
}

function parseShellcheck(resultsDir, outcome) {
  const file = path.join(resultsDir, "shellcheck.json");
  const statusFile = path.join(resultsDir, "shellcheck-status.txt");
  if (outcome === "skipped") return scanner("shellcheck", "skipped", 0, "shell");
  if (!fileExists(file) || !fileExists(statusFile)) return scanner("shellcheck", "error", 0, "shell");
  try {
    const status = Number.parseInt(fs.readFileSync(statusFile, "utf8").trim(), 10);
    const data = readJson(file);
    const comments = Array.isArray(data) ? data : data.comments;
    if (!Array.isArray(comments) || !Number.isInteger(status)) return scanner("shellcheck", "error", 0, "shell");
    if (status === 0 && outcome === "success" && comments.length === 0) {
      return scanner("shellcheck", "pass", 0, "shell");
    }
    if (status === 1 && comments.length > 0) {
      return scanner("shellcheck", "findings", comments.length, "shell");
    }
    return scanner("shellcheck", "error", 0, "shell");
  } catch {
    return scanner("shellcheck", "error", 0, "shell");
  }
}

function parseTrivy(resultsDir, outcome, kind, property, category) {
  const name = `trivy-${kind}`;
  const file = path.join(resultsDir, `${name}.json`);
  if (outcome === "skipped") return scanner(name, "skipped", 0, category);
  if (!fileExists(file)) return scanner(name, "error", 0, category);
  try {
    const data = readJson(file);
    if (!data || typeof data !== "object" || !Array.isArray(data.Results)) {
      return scanner(name, "error", 0, category);
    }
    const count = data.Results.reduce((sum, result) => {
      const entries = result && Array.isArray(result[property]) ? result[property] : [];
      return sum + entries.length;
    }, 0);
    if (outcome === "success" && count === 0) return scanner(name, "pass", 0, category);
    if (count > 0) return scanner(name, "findings", count, category);
    return scanner(name, "error", 0, category);
  } catch {
    return scanner(name, "error", 0, category);
  }
}

function validateTarget(target) {
  const requiredStrings = ["repository", "visibility", "default_branch", "commit_sha"];
  if (!target || typeof target !== "object") throw new Error("target.json must contain an object");
  if (!Number.isInteger(target.repository_id) || target.repository_id <= 0) {
    throw new Error("target.json contains an invalid repository_id");
  }
  for (const field of requiredStrings) {
    if (typeof target[field] !== "string" || target[field].length === 0) {
      throw new Error(`target.json contains an invalid ${field}`);
    }
  }
  if (!/^[0-9a-f]{40}$/.test(target.commit_sha)) throw new Error("target.json contains an invalid commit_sha");
  if (!Number.isInteger(target.workflow_run_id) || target.workflow_run_id <= 0) {
    throw new Error("target.json contains an invalid workflow_run_id");
  }
  if (!Number.isInteger(target.workflow_run_attempt) || target.workflow_run_attempt <= 0) {
    throw new Error("target.json contains an invalid workflow_run_attempt");
  }
}

function normalizeOutcome(value) {
  return ["success", "failure", "cancelled", "skipped"].includes(value) ? value : "skipped";
}

function remediationCategories(scanners) {
  const categories = new Set();
  for (const item of scanners) {
    if (item.status !== "findings") continue;
    switch (item.category) {
      case "actions": categories.add("Harden GitHub Actions workflows and pin trusted dependencies."); break;
      case "shell": categories.add("Correct shell diagnostics and unsafe scripting patterns."); break;
      case "vulnerability": categories.add("Update vulnerable dependencies or base components."); break;
      case "secret": categories.add("Revoke exposed credentials and remove secret material from history."); break;
      case "misconfiguration": categories.add("Harden infrastructure and deployment configuration."); break;
      default: break;
    }
  }
  return [...categories].sort().slice(0, 8);
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
    parseZizmor(resultsDir, outcomes.zizmor),
    parseActionlint(resultsDir, outcomes.actionlint),
    parseShellcheck(resultsDir, outcomes.shellcheck),
    parseTrivy(resultsDir, outcomes.trivyVulnerability, "vulnerability", "Vulnerabilities", "vulnerability"),
    parseTrivy(resultsDir, outcomes.trivySecret, "secret", "Secrets", "secret"),
    parseTrivy(resultsDir, outcomes.trivyMisconfiguration, "misconfiguration", "Misconfigurations", "misconfiguration"),
  ];

  let overallStatus = "pass";
  if (outcomes.checkout !== "success" || outcomes.tools === "failure" || outcomes.versions === "failure") {
    overallStatus = "error";
  } else if (outcomes.preflight === "failure") {
    overallStatus = "incomplete";
  } else if (scanners.some((item) => item.status === "error")) {
    overallStatus = "error";
  } else if (scanners.some((item) => item.status === "findings")) {
    overallStatus = "findings";
  } else if (scanners.every((item) => item.status === "skipped")) {
    overallStatus = "error";
  }

  const categories = [...new Set(scanners.filter((item) => item.findings > 0 && item.category).map((item) => item.category))].sort();
  const totalFindings = scanners.reduce((sum, item) => sum + item.findings, 0);
  const fingerprintInput = scanners
    .map((item) => `${item.name}:${item.status}:${item.findings}:${item.category ?? ""}`)
    .sort()
    .join("\n");

  const scannedAt = now.toISOString();
  const workflowRepository = target.trusted_workflow_repository || env.WORKFLOW_REPOSITORY || "";
  const runUrl = `https://github.com/${env.DASHBOARD_REPOSITORY || target.repository}/actions/runs/${target.workflow_run_id}`;

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
      timestamp: scannedAt,
      workflow_run_id: target.workflow_run_id,
      workflow_run_attempt: target.workflow_run_attempt,
      workflow_repository: workflowRepository,
      workflow_url: runUrl,
      evidence_artifact: `repository-scan-${target.repository_id}`,
    },
    overall_status: overallStatus,
    scanners,
    findings: {
      total: totalFindings,
      categories,
      fingerprint: sha256(fingerprintInput),
    },
    remediation_categories: remediationCategories(scanners),
  };
}

function main() {
  const resultsDir = process.argv[2] || "results";
  const output = process.argv[3] || path.join(resultsDir, "summary.json");
  const summary = buildSummary({resultsDir});
  const serialized = `${JSON.stringify(summary, null, 2)}\n`;
  if (Buffer.byteLength(serialized, "utf8") > 32 * 1024) {
    throw new Error("normalized summary exceeds the 32 KiB limit");
  }
  fs.writeFileSync(output, serialized, {encoding: "utf8", mode: 0o600});
}

if (require.main === module) {
  try {
    main();
  } catch (error) {
    console.error(`build-dashboard-summary: ${error.message}`);
    process.exit(1);
  }
}

module.exports = {
  buildSummary,
  parseActionlint,
  parseScorecard,
  parseShellcheck,
  parseTrivy,
  parseZizmor,
  sha256,
};
