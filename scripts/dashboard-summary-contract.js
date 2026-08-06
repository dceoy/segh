"use strict";

const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const REQUIRED = new Set([
  "scorecard", "zizmor", "actionlint", "shellcheck",
  "trivy-vulnerability", "trivy-secret", "trivy-misconfiguration",
]);

function completeScannerSet(summary) {
  if (!Array.isArray(summary?.scanners) || summary.scanners.length !== REQUIRED.size) return false;
  const names = new Set(summary.scanners.map((scanner) => scanner?.name));
  if (names.size !== REQUIRED.size || [...REQUIRED].some((name) => !names.has(name))) return false;
  if (summary.scanners.some((scanner) => !Number.isSafeInteger(scanner?.findings) || scanner.findings < 0)) return false;

  const statuses = summary.scanners.map((scanner) => scanner.status);
  const totalFindings = summary.scanners.reduce((sum, scanner) => sum + scanner.findings, 0);
  switch (summary.overall_status) {
    case "pass":
      return totalFindings === 0 && statuses.every((status) => status === "pass");
    case "findings":
      return totalFindings > 0 && statuses.some((status) => status === "findings") &&
        statuses.every((status) => status === "pass" || status === "findings");
    case "incomplete":
      return statuses.some((status) => status === "incomplete" || status === "skipped") &&
        statuses.every((status) => status !== "error");
    case "error":
      return statuses.some((status) => status === "error") || statuses.every((status) => status === "skipped");
    default:
      return false;
  }
}

function findSummaries(root) {
  const files = [];
  if (!fs.existsSync(root)) return files;
  for (const entry of fs.readdirSync(root, {withFileTypes: true})) {
    const file = path.join(root, entry.name);
    if (entry.isDirectory()) files.push(...findSummaries(file));
    else if (entry.isFile() && entry.name === "summary.json") files.push(file);
  }
  return files;
}

function hardenedSummaryCopy(root) {
  const copy = fs.mkdtempSync(path.join(os.tmpdir(), "segh-dashboard-summaries-"));
  if (fs.existsSync(root)) fs.cpSync(root, copy, {recursive: true});
  for (const file of findSummaries(copy)) {
    try {
      if (!completeScannerSet(JSON.parse(fs.readFileSync(file, "utf8")))) {
        fs.writeFileSync(file, '{"schema_version":0}\n', {mode: 0o600});
      }
    } catch {
      // The core publisher converts malformed JSON into scan:error.
    }
  }
  return copy;
}

module.exports = {completeScannerSet, hardenedSummaryCopy};
