#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const {buildSummary} = require("../scripts/build-dashboard-summary.js");

function writeJson(file, value) {
  fs.writeFileSync(file, `${JSON.stringify(value)}\n`);
}

function fixture() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "segh-checkov-"));
  writeJson(path.join(dir, "target.json"), {
    repository_id: 7,
    repository: "example/repo",
    commit_sha: "a".repeat(40),
  });
  writeJson(path.join(dir, "scorecard.json"), {checks: [{name: "Pinned-Dependencies", score: 1}]});
  writeJson(path.join(dir, "zizmor.json"), []);
  fs.writeFileSync(path.join(dir, "actionlint.jsonl"), "");
  writeJson(path.join(dir, "shellcheck.json"), []);
  fs.writeFileSync(path.join(dir, "shellcheck-status.txt"), "0\n");
  writeJson(path.join(dir, "trivy-vulnerability.json"), {SchemaVersion: 2, Trivy: {}, Results: []});
  writeJson(path.join(dir, "trivy-secret.json"), {SchemaVersion: 2, Trivy: {}, Results: []});
  return dir;
}

function env(overrides = {}) {
  return {
    CHECKOUT_OUTCOME: "success",
    TOOLS_OUTCOME: "success",
    VERSIONS_OUTCOME: "success",
    PREFLIGHT_OUTCOME: "success",
    SCORECARD_OUTCOME: "success",
    ZIZMOR_OUTCOME: "success",
    ACTIONLINT_OUTCOME: "success",
    SHELLCHECK_OUTCOME: "success",
    CHECKOV_OUTCOME: "success",
    TRIVY_VULNERABILITY_OUTCOME: "success",
    TRIVY_SECRET_OUTCOME: "success",
    ...overrides,
  };
}

function report({failed = 0, parsingErrors = 0} = {}) {
  return {
    check_type: "terraform",
    results: {failed_checks: [], parsing_errors: []},
    summary: {
      passed: 0,
      failed,
      skipped: 0,
      parsing_errors: parsingErrors,
      resource_count: failed > 0 ? 1 : 0,
      checkov_version: "3.3.9",
    },
  };
}

test("Checkov's bare no-IaC summary is a successful no-findings result", () => {
  const dir = fixture();
  try {
    writeJson(path.join(dir, "checkov.json"), {
      summary: {passed: 0, failed: 0, skipped: 0, parsing_errors: 0, resource_count: 0, checkov_version: "3.3.9"},
    });
    fs.writeFileSync(path.join(dir, "checkov-status.txt"), "0\n");
    const summary = buildSummary({resultsDir: dir, env: env()});
    assert.equal(summary.overall_status, "pass");
    assert.deepEqual(summary.scanners.find((scanner) => scanner.name === "checkov"), {
      name: "checkov", status: "pass", findings: 0,
    });
  } finally {
    fs.rmSync(dir, {recursive: true, force: true});
  }
});

test("Checkov literal empty report list is a scanner error, not a clean scan", () => {
  const dir = fixture();
  try {
    writeJson(path.join(dir, "checkov.json"), []);
    fs.writeFileSync(path.join(dir, "checkov-status.txt"), "0\n");
    const summary = buildSummary({resultsDir: dir, env: env()});
    assert.equal(summary.overall_status, "error");
    assert.equal(summary.scanners.find((scanner) => scanner.name === "checkov").status, "error");
  } finally {
    fs.rmSync(dir, {recursive: true, force: true});
  }
});

test("Checkov missing/malformed native evidence is a scanner error", () => {
  const dir = fixture();
  try {
    writeJson(path.join(dir, "checkov.json"), null);
    fs.writeFileSync(path.join(dir, "checkov-status.txt"), "2\n");
    const summary = buildSummary({resultsDir: dir, env: env({CHECKOV_OUTCOME: "failure"})});
    assert.equal(summary.overall_status, "error");
    assert.equal(summary.scanners.find((scanner) => scanner.name === "checkov").status, "error");
  } finally {
    fs.rmSync(dir, {recursive: true, force: true});
  }
});

test("Checkov policy violations become findings", () => {
  const dir = fixture();
  try {
    writeJson(path.join(dir, "checkov.json"), [report({failed: 2}), report({failed: 1})]);
    fs.writeFileSync(path.join(dir, "checkov-status.txt"), "1\n");
    const summary = buildSummary({resultsDir: dir, env: env({CHECKOV_OUTCOME: "failure"})});
    assert.equal(summary.overall_status, "findings");
    assert.deepEqual(summary.scanners.find((scanner) => scanner.name === "checkov"), {
      name: "checkov", status: "findings", findings: 3, category: "misconfiguration",
    });
  } finally {
    fs.rmSync(dir, {recursive: true, force: true});
  }
});

test("Checkov parsing and runtime failures remain scanner errors", () => {
  const dir = fixture();
  try {
    writeJson(path.join(dir, "checkov.json"), report({parsingErrors: 1}));
    fs.writeFileSync(path.join(dir, "checkov-status.txt"), "1\n");
    let summary = buildSummary({resultsDir: dir, env: env({CHECKOV_OUTCOME: "failure"})});
    assert.equal(summary.overall_status, "error");
    assert.equal(summary.scanners.find((scanner) => scanner.name === "checkov").status, "error");

    writeJson(path.join(dir, "checkov.json"), report());
    fs.writeFileSync(path.join(dir, "checkov-status.txt"), "2\n");
    summary = buildSummary({resultsDir: dir, env: env({CHECKOV_OUTCOME: "failure"})});
    assert.equal(summary.overall_status, "error");
    assert.equal(summary.scanners.find((scanner) => scanner.name === "checkov").status, "error");
  } finally {
    fs.rmSync(dir, {recursive: true, force: true});
  }
});
