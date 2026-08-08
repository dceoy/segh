#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const {buildSummary} = require("./build-dashboard-summary.js");
const publish = require("./publish-dashboard.js");

const TARGET = {
  id: 7,
  full_name: "example/repo",
  visibility: "private",
  default_branch: "main",
  commit_sha: "a".repeat(40),
};

function tempDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "segh-dashboard-"));
}

function writeJson(file, value) {
  fs.mkdirSync(path.dirname(file), {recursive: true});
  fs.writeFileSync(file, `${JSON.stringify(value)}\n`);
}

function scannerFixture(dir) {
  writeJson(path.join(dir, "target.json"), {
    repository_id: TARGET.id,
    repository: TARGET.full_name,
    commit_sha: TARGET.commit_sha,
  });
  writeJson(path.join(dir, "scorecard.json"), {checks: [{name: "Pinned-Dependencies", score: 1}]});
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
    ...overrides,
  };
}

function summary(target = TARGET, status = "findings") {
  return {
    repository: {id: target.id, full_name: target.full_name, commit_sha: target.commit_sha},
    overall_status: status,
    scanners: status === "findings"
      ? [{name: "zizmor", status: "findings", findings: 1, category: "actions"}]
      : [{name: "zizmor", status: "pass", findings: 0}],
    evidence_artifact: `repository-scan-${target.id}`,
  };
}

function writeInputs(root, targets, summaries) {
  writeJson(path.join(root, "matrix.json"), {include: targets});
  for (const [id, value] of summaries) {
    const file = path.join(root, "summaries", `repository-summary-${id}`, "summary.json");
    if (typeof value === "string") {
      fs.mkdirSync(path.dirname(file), {recursive: true});
      fs.writeFileSync(file, value);
    } else {
      writeJson(file, value);
    }
  }
}

function managedIssue(number, id, name, state = "open", labels = []) {
  return {
    number,
    title: `[Security dashboard] ${name}`,
    body: `<!-- segh-dashboard: v1 -->\n<!-- segh-repository-id: ${id} -->\nold\n`,
    state,
    labels: labels.map((label) => ({name: label})),
  };
}

function mockGitHub(existing = [], {ambiguousCreate = false, failUpdateFor = null} = {}) {
  const calls = {creates: [], updates: []};
  let failCreate = ambiguousCreate;
  return {
    calls,
    issues: existing,
    paginate: async () => existing,
    rest: {
      issues: {
        listForRepo: async () => ({data: existing}),
        create: async (params) => {
          calls.creates.push(params);
          const issue = {number: 90 + existing.length, ...params, state: "open", labels: params.labels};
          existing.push(issue);
          if (failCreate) {
            failCreate = false;
            const error = new Error("ambiguous create failure");
            error.status = 502;
            throw error;
          }
          return {data: issue};
        },
        update: async (params) => {
          calls.updates.push(params);
          if (params.issue_number === failUpdateFor) throw new Error("definitive update failure");
          const issue = existing.find((candidate) => candidate.number === params.issue_number);
          if (issue) Object.assign(issue, params);
          return {data: params};
        },
      },
    },
  };
}

async function runPublisher(root, github, runId = 123) {
  return publish({
    github,
    core: {info() {}, warning() {}},
    context: {repo: {owner: "control", repo: "private"}, runId},
    planPath: path.join(root, "matrix.json"),
    summariesPath: path.join(root, "summaries"),
    repositoryPrivate: "true",
  });
}

test("summary keeps only current-state dashboard data", () => {
  const dir = tempDir();
  try {
    scannerFixture(dir);
    const clean = buildSummary({resultsDir: dir, env: successEnv()});
    assert.deepEqual(Object.keys(clean).sort(), ["evidence_artifact", "overall_status", "repository", "scanners"]);
    assert.deepEqual(Object.keys(clean.repository).sort(), ["commit_sha", "full_name", "id"]);
    assert.deepEqual(clean.scanners.find((scanner) => scanner.name === "scorecard"), {
      name: "scorecard", status: "pass", findings: 0,
    });

    writeJson(path.join(dir, "zizmor.json"), [{rule: "unpinned-uses"}]);
    const findings = buildSummary({resultsDir: dir, env: successEnv({ZIZMOR_OUTCOME: "failure"})});
    assert.equal(findings.overall_status, "findings");
    assert.deepEqual(findings.scanners.find((scanner) => scanner.name === "zizmor"), {
      name: "zizmor", status: "findings", findings: 1, category: "actions",
    });
  } finally {
    fs.rmSync(dir, {recursive: true, force: true});
  }
});

test("summary fails closed on incomplete or invalid scanner evidence", () => {
  const dir = tempDir();
  try {
    scannerFixture(dir);
    assert.equal(buildSummary({resultsDir: dir, env: successEnv({PREFLIGHT_OUTCOME: "failure"})}).overall_status, "incomplete");
    assert.equal(buildSummary({resultsDir: dir, env: successEnv({SCORECARD_OUTCOME: "failure"})}).overall_status, "error");

    fs.rmSync(path.join(dir, "scorecard.json"));
    assert.equal(buildSummary({resultsDir: dir, env: successEnv()}).overall_status, "error");

    writeJson(path.join(dir, "scorecard.json"), {checks: []});
    assert.equal(buildSummary({resultsDir: dir, env: successEnv()}).overall_status, "error");
  } finally {
    fs.rmSync(dir, {recursive: true, force: true});
  }
});

test("publisher keeps one issue across rename, close, and reopen", async () => {
  const root = tempDir();
  try {
    const renamed = {...TARGET, full_name: "example/renamed"};
    writeInputs(root, [renamed], [[renamed.id, summary(renamed, "pass")]]);
    const github = mockGitHub([
      managedIssue(3, renamed.id, TARGET.full_name, "open", ["scan:findings", "scan:retired", "owner:security"]),
    ]);

    await runPublisher(root, github);
    assert.equal(github.calls.creates.length, 0);
    assert.equal(github.calls.updates.at(-1).issue_number, 3);
    assert.equal(github.calls.updates.at(-1).state, "closed");
    assert.equal(github.calls.updates.at(-1).title, "[Security dashboard] example/renamed");
    assert.deepEqual(github.calls.updates.at(-1).labels, ["owner:security", "scan:pass"]);

    writeInputs(root, [renamed], [[renamed.id, summary(renamed, "findings")]]);
    await runPublisher(root, github, 124);
    assert.equal(github.calls.updates.at(-1).issue_number, 3);
    assert.equal(github.calls.updates.at(-1).state, "open");
    assert.deepEqual(github.calls.updates.at(-1).labels, ["finding:actions", "owner:security", "scan:findings"]);
  } finally {
    fs.rmSync(root, {recursive: true, force: true});
  }
});

test("publisher recovers an ambiguous create without duplicating the issue", async () => {
  const root = tempDir();
  try {
    writeInputs(root, [TARGET], [[TARGET.id, summary()]]);
    const github = mockGitHub([], {ambiguousCreate: true});
    const results = await runPublisher(root, github);
    assert.deepEqual(results, [{repository_id: TARGET.id, status: "findings", action: "created"}]);
    assert.equal(github.calls.creates.length, 1);
    assert.equal(github.calls.creates[0].request.retries, 0);
    assert.equal(github.issues.length, 1);
  } finally {
    fs.rmSync(root, {recursive: true, force: true});
  }
});

test("publisher fails closed for missing, malformed, or mismatched summaries", async () => {
  for (const value of [
    undefined,
    "{not-json",
    summary({...TARGET, full_name: "example/wrong"}),
    (() => {
      const value = summary();
      delete value.evidence_artifact;
      return value;
    })(),
    {...summary(), evidence_artifact: "repository-scan-999"},
    {...summary(TARGET, "pass"), scanners: [{name: "zizmor", status: "pass", findings: 1}]},
    {...summary(), scanners: [{name: "zizmor", status: "findings", findings: 0, category: "actions"}]},
    {...summary(TARGET, "pass"), scanners: [{name: "zizmor", status: "findings", findings: 1, category: "actions"}]},
    {...summary(TARGET, "pass"), scanners: [{name: "zizmor", status: "error", findings: 0}]},
    {...summary(TARGET, "findings"), scanners: [{name: "zizmor", status: "pass", findings: 0}]},
  ]) {
    const root = tempDir();
    try {
      writeInputs(root, [TARGET], value === undefined ? [] : [[TARGET.id, value]]);
      const github = mockGitHub();
      const results = await runPublisher(root, github);
      assert.deepEqual(results, [{repository_id: TARGET.id, status: "error", action: "created"}]);
      assert.equal(github.calls.creates[0].labels[0], "scan:error");
      assert.match(github.calls.creates[0].body, /did not produce a valid normalized summary/);
    } finally {
      fs.rmSync(root, {recursive: true, force: true});
    }
  }
});

test("publisher rejects duplicate managed issues and continues other repositories", async () => {
  const root = tempDir();
  try {
    const other = {...TARGET, id: 8, full_name: "example/other", commit_sha: "b".repeat(40)};
    writeInputs(root, [TARGET, other], [[TARGET.id, summary()], [other.id, summary(other)]]);
    const github = mockGitHub([
      managedIssue(3, TARGET.id, TARGET.full_name),
      managedIssue(4, TARGET.id, TARGET.full_name),
    ]);

    await assert.rejects(() => runPublisher(root, github), /failed for repository ids: 7/);
    assert.equal(github.calls.creates.length, 1);
    assert.equal(github.calls.creates[0].title, "[Security dashboard] example/other");
  } finally {
    fs.rmSync(root, {recursive: true, force: true});
  }
});

test("publisher continues after a write failure then fails the job", async () => {
  const root = tempDir();
  try {
    const other = {...TARGET, id: 8, full_name: "example/other", commit_sha: "b".repeat(40)};
    writeInputs(root, [TARGET, other], [[TARGET.id, summary()], [other.id, summary(other)]]);
    const github = mockGitHub([managedIssue(3, TARGET.id, TARGET.full_name)], {failUpdateFor: 3});

    await assert.rejects(() => runPublisher(root, github), /failed for repository ids: 7/);
    assert.equal(github.calls.updates.length, 1);
    assert.equal(github.calls.creates.length, 1);
    assert.equal(github.calls.creates[0].title, "[Security dashboard] example/other");
  } finally {
    fs.rmSync(root, {recursive: true, force: true});
  }
});

test("publisher refuses public control repositories", async () => {
  await assert.rejects(() => publish({repositoryPrivate: "false"}), /private control repository/);
});
