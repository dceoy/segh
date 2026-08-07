#!/usr/bin/env node

"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const production = require("./build-dashboard-summary.js");
const core = require("./core/build-dashboard-summary.js");
const {hardenedSummaryCopy} = require("./dashboard-summary-contract.js");

function tempDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "segh-dashboard-native-"));
}

function writeJson(file, value) {
  fs.mkdirSync(path.dirname(file), {recursive: true});
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
}

function successfulEnv() {
  return {
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
}

function writeNativeCleanResults(dir) {
  writeJson(path.join(dir, "target.json"), {
    repository_id: 123,
    repository: "example/project",
    owner: "example",
    name: "project",
    visibility: "private",
    fork: false,
    default_branch: "main",
    commit_sha: "a".repeat(40),
    workflow_run_id: 456,
    workflow_run_attempt: 1,
    trusted_workflow_repository: "dceoy/segh",
    trusted_workflow_sha: "b".repeat(40),
  });
  writeJson(path.join(dir, "scorecard.json"), {
    checks: [
      "Branch-Protection",
      "Code-Review",
      "Dangerous-Workflow",
      "Pinned-Dependencies",
      "Token-Permissions",
      "Vulnerabilities",
    ].map((Name) => ({Name, Score: 10})),
  });
  writeJson(path.join(dir, "zizmor.json"), []);

  // actionlint's current custom JSON formatter emits one JSON array, including []
  // for a clean workflow, rather than newline-delimited finding objects.
  fs.writeFileSync(path.join(dir, "actionlint.jsonl"), "[]\n");
  writeJson(path.join(dir, "shellcheck.json"), {comments: []});
  fs.writeFileSync(path.join(dir, "shellcheck-status.txt"), "0\n");

  // Trivy 0.72 omits Results entirely when a successful filesystem scan has no
  // findings. Keep the report metadata so absence is distinguishable from a
  // malformed empty object.
  const cleanTrivy = {
    SchemaVersion: 2,
    ArtifactName: "fixture",
    ArtifactType: "filesystem",
    Metadata: {},
    Trivy: {Version: "0.72.0"},
  };
  for (const name of ["vulnerability", "secret", "misconfiguration"]) {
    writeJson(path.join(dir, `trivy-${name}.json`), cleanTrivy);
  }
}

function main() {
  assert.strictEqual(core.buildSummary, production.buildSummary, "core tests must use the production normalizer");

  const results = tempDir();
  writeNativeCleanResults(results);
  const summary = production.buildSummary({
    resultsDir: results,
    env: successfulEnv(),
    now: new Date("2026-08-07T00:00:00Z"),
  });
  assert.equal(summary.overall_status, "pass");
  assert.equal(summary.findings.total, 0);
  assert.equal(summary.scanners.length, 7);
  assert.ok(summary.scanners.every((scanner) => scanner.status === "pass"));

  const input = tempDir();
  const mismatched = path.join(input, "repository-summary-999", "summary.json");
  writeJson(mismatched, summary);
  const hardenedMismatch = hardenedSummaryCopy(input);
  assert.equal(
    JSON.parse(fs.readFileSync(path.join(hardenedMismatch, "repository-summary-999", "summary.json"), "utf8")).schema_version,
    0,
    "artifact directory ID must be bound to the summary repository ID",
  );
  fs.rmSync(hardenedMismatch, {recursive: true, force: true});

  fs.rmSync(input, {recursive: true, force: true});
  const matching = tempDir();
  writeJson(path.join(matching, "repository-summary-123", "summary.json"), summary);
  const hardenedMatch = hardenedSummaryCopy(matching);
  assert.equal(
    JSON.parse(fs.readFileSync(path.join(hardenedMatch, "repository-summary-123", "summary.json"), "utf8")).schema_version,
    1,
  );

  for (const dir of [results, matching, hardenedMatch]) fs.rmSync(dir, {recursive: true, force: true});
  console.log("dashboard native-output tests passed");
}

main();
