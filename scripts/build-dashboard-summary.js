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

function parseCheckov(resultsDir, outcome) {
  if (outcome === "skipped") return result("checkov", "skipped");
  const file = path.join(resultsDir, "checkov.json");
  const statusFile = path.join(resultsDir, "checkov-status.txt");
  if (!exists(file) || !exists(statusFile)) return result("checkov", "error");
  try {
    const data = readJson(file);
    const reports = Array.isArray(data) ? data : [data];
    const status = Number.parseInt(fs.readFileSync(statusFile, "utf8").trim(), 10);
    if (!Number.isInteger(status) || reports.length === 0 || !reports.every((report) => {
      const summary = report?.summary;
      return report && typeof report === "object" && !Array.isArray(report) &&
        summary && typeof summary === "object" &&
        Number.isSafeInteger(summary.failed) && summary.failed >= 0 &&
        Number.isSafeInteger(summary.skipped) && summary.skipped >= 0 &&
        Number.isSafeInteger(summary.parsing_errors) && summary.parsing_errors >= 0;
    })) return result("checkov", "error");
    const findings = reports.reduce((count, report) => count + report.summary.failed, 0);
    const skipped = reports.reduce((count, report) => count + report.summary.skipped, 0);
    const parsingErrors = reports.reduce((count, report) => count + report.summary.parsing_errors, 0);
    if (parsingErrors > 0) return result("checkov", "error");
    // A scanned repository can suppress individual checks with inline
    // `checkov:skip=`/`bridgecrew:skip=`/`cortex:skip=` comments, which
    // Checkov honors regardless of this scanner's own skip-check: []
    // config. Treat any such target-controlled suppression as lost
    // evidence rather than a clean scan, the same way parsing errors are.
    if (skipped > 0) return result("checkov", "error");
    if (status === 1 && findings > 0) return result("checkov", "findings", findings, "misconfiguration");
    if (status === 0 && outcome === "success" && findings === 0) return result("checkov", "pass");
    return result("checkov", "error");
  } catch {
    return result("checkov", "error");
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
    checkov: normalizeOutcome(env.CHECKOV_OUTCOME),
    trivyVulnerability: normalizeOutcome(env.TRIVY_VULNERABILITY_OUTCOME),
    trivySecret: normalizeOutcome(env.TRIVY_SECRET_OUTCOME),
  };

  const scanners = [
    parseScorecard(resultsDir, outcomes.scorecard),
    parseJsonArrayScanner(resultsDir, outcomes.zizmor, "zizmor", "zizmor.json", "actions"),
    parseActionlint(resultsDir, outcomes.actionlint),
    parseShellcheck(resultsDir, outcomes.shellcheck),
    parseCheckov(resultsDir, outcomes.checkov),
    parseTrivy(resultsDir, outcomes.trivyVulnerability, "vulnerability", "Vulnerabilities", "vulnerability"),
    parseTrivy(resultsDir, outcomes.trivySecret, "secret", "Secrets", "secret"),
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
