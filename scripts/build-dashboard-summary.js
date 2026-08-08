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
  if (category && status === "findings") scanner.category = category;
  return scanner;
}

function parseScorecard(resultsDir, outcome) {
  if (outcome === "skipped") return result("scorecard", "skipped");
  if (outcome !== "success") return result("scorecard", "error");
  const file = path.join(resultsDir, "scorecard.json");
  if (!exists(file)) return result("scorecard", "error");
  try {
    const data = readJson(file);
    if (!Array.isArray(data?.checks) || data.checks.length === 0 || !data.checks.every((check) => {
      if (!check || typeof check !== "object") return false;
      const name = check.name ?? check.Name;
      const score = check.score ?? check.Score;
      return typeof name === "string" && name.trim().length > 0 && Number.isFinite(score);
    })) return result("scorecard", "error");
    return result("scorecard", "pass");
  } catch {
    return result("scorecard", "error");
  }
}

function parseJsonArrayScanner(resultsDir, outcome, name, fileName, category) {
  if (outcome === "skipped") return result(name, "skipped");
  const file = path.join(resultsDir, fileName);
  if (!exists(file)) return result(name, "error");
  try {
    const findings = readJson(file);
    if (!Array.isArray(findings)) return result(name, "error");
    if (findings.length) return result(name, "findings", findings.length, category);
    return result(name, outcome === "success" ? "pass" : "error");
  } catch {
    return result(name, "error");
  }
}

function parseActionlint(resultsDir, outcome) {
  if (outcome === "skipped") return result("actionlint", "skipped");
  const file = path.join(resultsDir, "actionlint.jsonl");
  if (!exists(file)) return result("actionlint", "error");
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
    return result("actionlint", outcome === "success" ? "pass" : "error");
  } catch {
    return result("actionlint", "error");
  }
}

function parseShellcheck(resultsDir, outcome) {
  if (outcome === "skipped") return result("shellcheck", "skipped");
  const file = path.join(resultsDir, "shellcheck.json");
  const statusFile = path.join(resultsDir, "shellcheck-status.txt");
  if (!exists(file) || !exists(statusFile)) return result("shellcheck", "error");
  try {
    const data = readJson(file);
    const comments = Array.isArray(data) ? data : data.comments;
    const status = Number.parseInt(fs.readFileSync(statusFile, "utf8").trim(), 10);
    if (!Array.isArray(comments) || !Number.isInteger(status)) return result("shellcheck", "error");
    if (status === 1 && comments.length) return result("shellcheck", "findings", comments.length, "shell");
    if (status === 0 && outcome === "success" && comments.length === 0) return result("shellcheck", "pass");
    return result("shellcheck", "error");
  } catch {
    return result("shellcheck", "error");
  }
}

function parseTrivy(resultsDir, outcome, kind, property, category) {
  const name = `trivy-${kind}`;
  if (outcome === "skipped") return result(name, "skipped");
  const file = path.join(resultsDir, `${name}.json`);
  if (!exists(file)) return result(name, "error");
  try {
    const data = readJson(file);
    if (!data || typeof data !== "object" || Array.isArray(data)) return result(name, "error");
    let rows;
    if (Array.isArray(data.Results)) rows = data.Results;
    else if (outcome === "success" && data.Results === undefined && data.SchemaVersion === 2 && data.Trivy && typeof data.Trivy === "object") rows = [];
    else return result(name, "error");
    const findings = rows.reduce((count, row) => count + (Array.isArray(row?.[property]) ? row[property].length : 0), 0);
    if (findings) return result(name, "findings", findings, category);
    return result(name, outcome === "success" ? "pass" : "error");
  } catch {
    return result(name, "error");
  }
}

function normalizeOutcome(value) {
  return ["success", "failure", "cancelled", "skipped"].includes(value) ? value : "skipped";
}

function validateTarget(target) {
  if (!Number.isSafeInteger(target?.repository_id) || target.repository_id <= 0) throw new Error("invalid repository_id");
  if (typeof target.repository !== "string" || !target.repository.includes("/")) throw new Error("invalid repository");
  if (!/^[0-9a-f]{40}$/.test(target.commit_sha || "")) throw new Error("invalid commit_sha");
}

function buildSummary({resultsDir, env = process.env}) {
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
    repository: {
      id: target.repository_id,
      full_name: target.repository,
      commit_sha: target.commit_sha,
    },
    overall_status: overallStatus,
    scanners,
    evidence_artifact: `repository-scan-${target.repository_id}`,
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
