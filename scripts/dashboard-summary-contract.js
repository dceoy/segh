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
  const scanners = summary?.scanners;
  if (!Array.isArray(scanners) || scanners.length !== REQUIRED.size) return false;

  const names = new Set();
  let findings = 0;
  for (const scanner of scanners) {
    if (!scanner || !REQUIRED.has(scanner.name) || names.has(scanner.name) || !SCANNER_STATUS.has(scanner.status) ||
        !Number.isSafeInteger(scanner.findings) || scanner.findings < 0 ||
        (scanner.status === "findings" ? scanner.findings === 0 : scanner.findings !== 0)) return false;
    names.add(scanner.name);
    findings += scanner.findings;
  }
  const totalFindings = summary?.findings?.total;
  if (!Number.isSafeInteger(totalFindings) || findings !== totalFindings) return false;

  const statuses = scanners.map(({status}) => status);
  switch (summary.overall_status) {
    case "pass":
      return statuses.every((status) => status === "pass");
    case "findings":
      return findings > 0 && statuses.includes("findings") && statuses.every((status) => status === "pass" || status === "findings");
    case "incomplete":
      return statuses.some((status) => status === "incomplete" || status === "skipped") && !statuses.includes("error");
    case "error":
      return statuses.includes("error") || statuses.every((status) => status === "skipped");
    default:
      return false;
  }
}

function findSummaries(root) {
  if (!fs.existsSync(root)) return [];
  return fs.readdirSync(root, {withFileTypes: true}).flatMap((entry) => {
    const file = path.join(root, entry.name);
    if (entry.isDirectory()) return findSummaries(file);
    return entry.isFile() && entry.name === "summary.json" ? [file] : [];
  });
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
      if ((artifactId !== null && artifactId !== payloadId) || !completeScannerSet(summary)) {
        fs.writeFileSync(file, '{"schema_version":0}\n', {mode: 0o600});
      }
    } catch {
      // The publisher converts malformed JSON into scan:error.
    }
  }
  return copy;
}

module.exports = {artifactRepositoryId, completeScannerSet, hardenedSummaryCopy};
