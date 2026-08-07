#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const {buildSummary} = require("./build-dashboard-summary.js");
const publish = require("./publish-dashboard.js");

function tempDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "segh-dashboard-"));
}

function writeJson(file, value) {
  fs.writeFileSync(file, `${JSON.stringify(value)}\n`);
}

function fixture(dir) {
  writeJson(path.join(dir, "target.json"), {
    repository_id: 7,
    repository: "example/repo",
    visibility: "private",
    default_branch: "main",
    commit_sha: "a".repeat(40),
    workflow_run_id: 42,
    workflow_run_attempt: 1,
    trusted_workflow_repository: "dceoy/segh",
  });
  writeJson(path.join(dir, "scorecard.json"), {checks: [{Name: "Pinned-Dependencies", Score: 10}]});
  writeJson(path.join(dir, "zizmor.json"), []);
  fs.writeFileSync(path.join(dir, "actionlint.jsonl"), "");
  writeJson(path.join(dir, "shellcheck.json"), []);
  fs.writeFileSync(path.join(dir, "shellcheck-status.txt"), "0\n");
  writeJson(path.join(dir, "trivy-vulnerability.json"), {SchemaVersion: 2, Trivy: {}, Results: []});
  writeJson(path.join(dir, "trivy-secret.json"), {SchemaVersion: 2, Trivy: {}, Results: []});
  writeJson(path.join(dir, "trivy-misconfiguration.json"), {SchemaVersion: 2, Trivy: {}, Results: []});
}

function successEnv(overrides = {}) {
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
    ...overrides,
  };
}

test("summary reports pass and findings from native scanner outputs", () => {
  const dir = tempDir();
  try {
    fixture(dir);
    const clean = buildSummary({resultsDir: dir, env: successEnv(), now: new Date("2026-01-01T00:00:00Z")});
    assert.equal(clean.overall_status, "pass");
    assert.equal(clean.findings.total, 0);

    writeJson(path.join(dir, "zizmor.json"), [{rule: "unpinned-uses"}]);
    const findings = buildSummary({resultsDir: dir, env: successEnv({ZIZMOR_OUTCOME: "failure"})});
    assert.equal(findings.overall_status, "findings");
    assert.equal(findings.scanners.find((scanner) => scanner.name === "zizmor").findings, 1);
  } finally {
    fs.rmSync(dir, {recursive: true, force: true});
  }
});

test("summary distinguishes incomplete preflight from scanner runtime error", () => {
  const dir = tempDir();
  try {
    fixture(dir);
    assert.equal(buildSummary({resultsDir: dir, env: successEnv({PREFLIGHT_OUTCOME: "failure"})}).overall_status, "incomplete");
    fs.writeFileSync(path.join(dir, "shellcheck-status.txt"), "2\n");
    assert.equal(buildSummary({resultsDir: dir, env: successEnv({SHELLCHECK_OUTCOME: "failure"})}).overall_status, "error");
  } finally {
    fs.rmSync(dir, {recursive: true, force: true});
  }
});

function mockGitHub(existing = []) {
  const calls = {labels: [], creates: [], updates: []};
  return {
    calls,
    paginate: async () => existing,
    rest: {
      issues: {
        listForRepo: async () => ({data: existing}),
        createLabel: async (params) => { calls.labels.push(params.name); return {data: params}; },
        create: async (params) => { calls.creates.push(params); return {data: {number: 99, ...params, state: "open"}}; },
        update: async (params) => { calls.updates.push(params); return {data: params}; },
      },
    },
  };
}

test("publisher creates one current-run issue without reconciliation machinery", async () => {
  const root = tempDir();
  try {
    const summaries = path.join(root, "summaries", "repository-summary-7");
    fs.mkdirSync(summaries, {recursive: true});
    writeJson(path.join(root, "matrix.json"), {include: [{
      id: 7,
      full_name: "example/repo",
      visibility: "private",
      default_branch: "main",
      commit_sha: "a".repeat(40),
    }]});
    writeJson(path.join(summaries, "summary.json"), {
      repository: {id: 7, full_name: "example/repo", commit_sha: "a".repeat(40)},
      scan: {evidence_artifact: "repository-scan-7"},
      overall_status: "findings",
      scanners: [{name: "zizmor", status: "findings", findings: 1, category: "actions"}],
    });
    const github = mockGitHub();
    const core = {info() {}, warning(message) { throw new Error(message); }};
    const results = await publish({
      github,
      core,
      context: {repo: {owner: "control", repo: "private"}, runId: 123},
      planPath: path.join(root, "matrix.json"),
      summariesPath: path.join(root, "summaries"),
      repositoryPrivate: "true",
    });
    assert.deepEqual(results, [{repository_id: 7, status: "findings", action: "created"}]);
    assert.equal(github.calls.creates.length, 1);
    assert.deepEqual(github.calls.creates[0].labels.sort(), ["finding:actions", "scan:findings"]);
    assert.match(github.calls.creates[0].body, /Scanner results/);
  } finally {
    fs.rmSync(root, {recursive: true, force: true});
  }
});

test("publisher closes an existing dashboard after a passing scan", async () => {
  const root = tempDir();
  try {
    const summaries = path.join(root, "summaries");
    fs.mkdirSync(summaries, {recursive: true});
    writeJson(path.join(root, "matrix.json"), {include: [{
      id: 7,
      full_name: "example/repo",
      visibility: "private",
      default_branch: "main",
      commit_sha: "a".repeat(40),
    }]});
    writeJson(path.join(summaries, "summary.json"), {
      repository: {id: 7, full_name: "example/repo", commit_sha: "a".repeat(40)},
      scan: {evidence_artifact: "repository-scan-7"},
      overall_status: "pass",
      scanners: [{name: "zizmor", status: "pass", findings: 0, category: "actions"}],
    });
    const github = mockGitHub([{
      number: 3,
      title: "[Security dashboard] example/repo",
      body: "<!-- segh-dashboard: v1 -->\n<!-- segh-repository-id: 7 -->\nold\n",
      state: "open",
      labels: [{name: "scan:findings"}],
    }]);
    await publish({
      github,
      core: {info() {}, warning() {}},
      context: {repo: {owner: "control", repo: "private"}, runId: 124},
      planPath: path.join(root, "matrix.json"),
      summariesPath: summaries,
      repositoryPrivate: "true",
    });
    assert.equal(github.calls.updates.length, 1);
    assert.equal(github.calls.updates[0].state, "closed");
    assert.deepEqual(github.calls.updates[0].labels, ["scan:pass"]);
  } finally {
    fs.rmSync(root, {recursive: true, force: true});
  }
});
