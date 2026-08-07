"use strict";

const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const REQUIRED = new Set([
  "scorecard", "zizmor", "actionlint", "shellcheck",
  "trivy-vulnerability", "trivy-secret", "trivy-misconfiguration",
]);
const SCANNER_STATUS = new Set(["pass", "findings", "incomplete", "error", "skipped"]);
const ARTIFACT_DIRECTORY = /^repository-summary-([0-9]+)$/;

function completeScannerSet(summary) {
  if (!Array.isArray(summary?.scanners) || summary.scanners.length !== REQUIRED.size) return false;
  const names = new Set(summary.scanners.map((scanner) => scanner?.name));
  if (names.size !== REQUIRED.size || [...REQUIRED].some((name) => !names.has(name))) return false;
  if (summary.scanners.some((scanner) => !SCANNER_STATUS.has(scanner?.status) ||
      !Number.isSafeInteger(scanner.findings) || scanner.findings < 0 ||
      (scanner.status === "findings" ? scanner.findings === 0 : scanner.findings !== 0))) return false;

  const statuses = summary.scanners.map((scanner) => scanner.status);
  const totalFindings = summary.scanners.reduce((sum, scanner) => sum + scanner.findings, 0);
  if (!Number.isSafeInteger(summary?.findings?.total) || summary.findings.total !== totalFindings) return false;
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

function artifactRepositoryId(file) {
  for (let directory = path.dirname(file); directory && directory !== path.dirname(directory); directory = path.dirname(directory)) {
    const match = path.basename(directory).match(ARTIFACT_DIRECTORY);
    if (!match) continue;
    const id = Number.parseInt(match[1], 10);
    return Number.isSafeInteger(id) && id > 0 ? id : null;
  }
  return null;
}

function hardenedSummaryCopy(root) {
  const copy = fs.mkdtempSync(path.join(os.tmpdir(), "segh-dashboard-summaries-"));
  if (fs.existsSync(root)) fs.cpSync(root, copy, {recursive: true});
  for (const file of findSummaries(copy)) {
    try {
      const summary = JSON.parse(fs.readFileSync(file, "utf8"));
      const artifactId = artifactRepositoryId(file);
      const payloadId = summary?.repository?.id;
      const identityMatches = artifactId === null ||
        (Number.isSafeInteger(payloadId) && payloadId > 0 && payloadId === artifactId);
      if (!identityMatches || !completeScannerSet(summary)) {
        fs.writeFileSync(file, '{"schema_version":0}\n', {mode: 0o600});
      }
    } catch {
      // The core publisher converts malformed JSON into scan:error.
    }
  }
  return copy;
}

module.exports = {artifactRepositoryId, completeScannerSet, hardenedSummaryCopy};
