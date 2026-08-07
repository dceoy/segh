#!/usr/bin/env node

"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const reconcile = require("./reconcile-organization-dashboard.js");
const {sha256} = require("./publish-dashboard.js")._internal;

function tempDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "segh-reconcile-test-"));
}

function writeJson(file, value) {
  fs.mkdirSync(path.dirname(file), {recursive: true});
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
}

function selected(id, name, overrides = {}) {
  return {
    id,
    full_name: `example/${name}`,
    owner: "example",
    name,
    visibility: "private",
    fork: false,
    archived: false,
    disabled: false,
    default_branch: "main",
    disposition: "active",
    reason: "selected by the GitHub App installation",
    ...overrides,
  };
}

function target(entry, commit = "a".repeat(40)) {
  return {
    id: entry.id,
    full_name: entry.full_name,
    owner: entry.owner,
    name: entry.name,
    visibility: entry.visibility,
    fork: entry.fork,
    default_branch: entry.default_branch,
    commit_sha: commit,
  };
}

function cleanSummary(entry, commit = "a".repeat(40), runId = 101, timestamp = "2026-08-07T00:00:00.000Z") {
  return {
    schema_version: 1,
    repository: {
      id: entry.id,
      full_name: entry.full_name,
      visibility: entry.visibility,
      default_branch: entry.default_branch,
      commit_sha: commit,
    },
    scan: {
      timestamp,
      workflow_run_id: runId,
      workflow_run_attempt: 1,
      workflow_repository: "control/private",
      workflow_url: `https://github.com/control/private/actions/runs/${runId}`,
      evidence_artifact: `repository-scan-${entry.id}`,
    },
    overall_status: "pass",
    scanners: [
      {name: "scorecard", status: "pass", findings: 0, selected_checks: [{name: "Pinned-Dependencies", score: 10}]},
      {name: "zizmor", status: "pass", findings: 0, category: "actions"},
      {name: "actionlint", status: "pass", findings: 0, category: "actions"},
      {name: "shellcheck", status: "pass", findings: 0, category: "shell"},
      {name: "trivy-vulnerability", status: "pass", findings: 0, category: "vulnerability"},
      {name: "trivy-secret", status: "pass", findings: 0, category: "secret"},
      {name: "trivy-misconfiguration", status: "pass", findings: 0, category: "misconfiguration"},
    ],
    findings: {total: 0, categories: [], fingerprint: sha256(`clean:${entry.id}`)},
    remediation_categories: [],
  };
}

class FakeGitHub {
  constructor() {
    this.labels = [];
    this.issues = [];
    this.comments = [];
    this.artifacts = [];
    this.calls = [];
    this.nextNumber = 1;
    this.rest = {
      actions: {
        listArtifactsForRepo: async () => ({data: {total_count: this.artifacts.length, artifacts: this.artifacts}}),
      },
      issues: {
        listLabelsForRepo: async () => ({data: this.labels}),
        createLabel: async (params) => {
          this.calls.push(["createLabel", params]);
          const label = {name: params.name, color: params.color, description: params.description};
          this.labels.push(label);
          return {data: label};
        },
        listForRepo: async () => ({data: this.issues}),
        create: async (params) => {
          this.calls.push(["create", params]);
          const issue = {
            number: this.nextNumber++,
            title: params.title,
            body: params.body,
            state: "open",
            labels: (params.labels || []).map((name) => ({name})),
          };
          this.issues.push(issue);
          return {data: issue};
        },
        update: async (params) => {
          this.calls.push(["update", params]);
          const issue = this.issues.find((candidate) => candidate.number === params.issue_number);
          assert.ok(issue, `missing fake issue ${params.issue_number}`);
          for (const field of ["title", "body", "state"]) {
            if (params[field] !== undefined) issue[field] = params[field];
          }
          if (params.labels) issue.labels = params.labels.map((name) => ({name}));
          return {data: issue};
        },
        createComment: async (params) => {
          this.calls.push(["createComment", params]);
          this.comments.push(params);
          return {data: {id: this.comments.length, ...params}};
        },
      },
    };
  }
}

function fakeCore() {
  return {
    info: () => {},
    warning: () => {},
    summary: {
      addHeading() { return this; },
      addRaw() { return this; },
      addTable() { return this; },
      async write() { return this; },
    },
  };
}

function input(root, selection, targets, summaries = []) {
  const selectionPath = path.join(root, "selection.json");
  const planPath = path.join(root, "matrix.json");
  const summariesPath = path.join(root, "summaries");
  writeJson(selectionPath, {repositories: selection});
  writeJson(planPath, {include: targets});
  for (const summary of summaries) {
    writeJson(path.join(summariesPath, `repository-summary-${summary.repository.id}`, "summary.json"), summary);
  }
  return {selectionPath, planPath, summariesPath};
}

async function testCompleteReconciliation() {
  const root = tempDir();
  const active = selected(123, "project");
  const retired = selected(456, "archive", {archived: true, disposition: "retired", reason: "repository is archived"});
  const files = input(root, [active, retired], [target(active)], [cleanSummary(active)]);
  const github = new FakeGitHub();
  const context = {repo: {owner: "control", repo: "private"}, runId: 101, runAttempt: 1};

  const result = await reconcile({
    github,
    context,
    core: fakeCore(),
    repositoryPrivate: true,
    staleAfterHours: "192",
    scanResult: "success",
    selectionAvailable: true,
    planAvailable: true,
    summariesAvailable: true,
    ...files,
  });

  assert.deepEqual(result, [
    {repository_id: 123, status: "pass", action: "created"},
    {repository_id: 456, status: "retired", action: "retired-untracked"},
  ]);
  assert.equal(github.issues.length, 1);
  assert.equal(github.issues[0].title, "[Security dashboard] example/project");
  assert.equal(github.issues[0].state, "closed");
  assert.ok(github.issues[0].labels.some((label) => label.name === "scan:pass"));

  github.calls = [];
  const rerun = await reconcile({
    github,
    context,
    core: fakeCore(),
    repositoryPrivate: "true",
    staleAfterHours: "192",
    scanResult: "success",
    selectionAvailable: true,
    planAvailable: true,
    summariesAvailable: true,
    ...files,
  });
  assert.deepEqual(rerun, [
    {repository_id: 123, status: "pass", action: "unchanged"},
    {repository_id: 456, status: "retired", action: "retired-untracked"},
  ]);
  assert.equal(github.calls.length, 0, "unchanged reconciliation must perform no API writes");
}

async function testMissingPlanFailsClosed() {
  const root = tempDir();
  const active = selected(123, "project");
  const files = input(root, [active], [], []);
  const github = new FakeGitHub();
  const context = {repo: {owner: "control", repo: "private"}, runId: 202, runAttempt: 1};

  await assert.rejects(() => reconcile({
    github,
    context,
    core: fakeCore(),
    repositoryPrivate: true,
    staleAfterHours: "192",
    scanResult: "failure",
    selectionAvailable: true,
    planAvailable: false,
    summariesAvailable: false,
    selectionPath: files.selectionPath,
    planPath: path.join(root, "missing-plan.json"),
    summariesPath: files.summariesPath,
  }), /scan plan is unavailable/);

  assert.equal(github.issues.length, 1, "selected repository must not disappear when planning fails");
  assert.equal(github.issues[0].state, "open");
  assert.ok(github.issues[0].labels.some((label) => label.name === "scan:error"));
  assert.ok(github.issues[0].body.includes("immutable scan target is missing"));
}

async function testFailedRunInvalidatesPassingDashboard() {
  const root = tempDir();
  const active = selected(123, "project");
  const files = input(root, [active], [target(active)], [cleanSummary(active)]);
  const github = new FakeGitHub();
  const context = {repo: {owner: "control", repo: "private"}, runId: 303, runAttempt: 1};

  await reconcile({
    github,
    context,
    core: fakeCore(),
    repositoryPrivate: true,
    staleAfterHours: "192",
    scanResult: "success",
    selectionAvailable: true,
    planAvailable: true,
    summariesAvailable: true,
    ...files,
  });
  assert.equal(github.issues[0].state, "closed");

  await assert.rejects(() => reconcile({
    github,
    context: {...context, runId: 304},
    core: fakeCore(),
    repositoryPrivate: true,
    staleAfterHours: "192",
    scanResult: "failure",
    selectionAvailable: false,
    planAvailable: false,
    summariesAvailable: false,
    selectionPath: path.join(root, "missing-selection.json"),
    planPath: path.join(root, "missing-plan.json"),
    summariesPath: path.join(root, "missing-summaries"),
  }), /selection snapshot is unavailable/);

  assert.equal(github.issues[0].state, "open");
  assert.ok(github.issues[0].labels.some((label) => label.name === "scan:error"));
  assert.ok(github.comments.length >= 1, "pass-to-error transition must append bounded history");
}

async function testRecentArtifactPreventsFalseStaleAfterUnchangedScans() {
  const root = tempDir();
  const active = selected(123, "project");
  const oldSummary = cleanSummary(active, "a".repeat(40), 401, "2026-07-01T00:00:00.000Z");
  let files = input(root, [active], [target(active)], [oldSummary]);
  const github = new FakeGitHub();
  const context = {repo: {owner: "control", repo: "private"}, runId: 401, runAttempt: 1};

  await reconcile({
    github,
    context,
    core: fakeCore(),
    repositoryPrivate: true,
    staleAfterHours: "192",
    scanResult: "success",
    selectionAvailable: true,
    planAvailable: true,
    summariesAvailable: true,
    ...files,
  });
  assert.equal(github.issues[0].state, "closed");
  assert.ok(github.issues[0].body.includes("2026-07-01T00:00:00.000Z"));

  files = input(root, [active], [target(active)], [cleanSummary(active, "a".repeat(40), 402, new Date().toISOString())]);
  github.calls = [];
  const unchanged = await reconcile({
    github,
    context: {...context, runId: 402},
    core: fakeCore(),
    repositoryPrivate: true,
    staleAfterHours: "192",
    scanResult: "success",
    selectionAvailable: true,
    planAvailable: true,
    summariesAvailable: true,
    ...files,
  });
  assert.deepEqual(unchanged, [{repository_id: 123, status: "pass", action: "unchanged"}]);
  assert.equal(github.calls.length, 0, "unchanged successful scans must not write the issue");
  assert.ok(github.issues[0].body.includes("2026-07-01T00:00:00.000Z"), "no-op publication keeps the old rendered scan timestamp");

  github.artifacts = [{name: "repository-summary-123", created_at: new Date().toISOString(), expired: false}];
  github.calls = [];
  await assert.rejects(() => reconcile({
    github,
    context: {...context, runId: 403},
    core: fakeCore(),
    repositoryPrivate: true,
    staleAfterHours: "192",
    scanResult: "success",
    selectionAvailable: false,
    planAvailable: false,
    summariesAvailable: false,
    selectionPath: path.join(root, "missing-selection.json"),
    planPath: path.join(root, "missing-plan.json"),
    summariesPath: path.join(root, "missing-summaries"),
  }), /selection snapshot is unavailable/);

  assert.equal(github.issues[0].state, "closed", "recent immutable scan artifacts must prevent false stale promotion");
  assert.ok(github.issues[0].labels.some((label) => label.name === "scan:pass"));
  assert.equal(github.calls.length, 0, "freshness fallback must not mutate a still-current dashboard");
}

async function testFailedSummaryDownloadFailsClosed() {
  const root = tempDir();
  const active = selected(123, "project");
  const files = input(root, [active], [target(active)], []);
  const github = new FakeGitHub();
  const context = {repo: {owner: "control", repo: "private"}, runId: 501, runAttempt: 1};

  await assert.rejects(() => reconcile({
    github,
    context,
    core: fakeCore(),
    repositoryPrivate: true,
    staleAfterHours: "192",
    scanResult: "success",
    selectionAvailable: true,
    planAvailable: true,
    summariesAvailable: false,
    ...files,
  }), /normalized summary artifacts are unavailable/);

  assert.equal(github.issues.length, 1);
  assert.equal(github.issues[0].state, "open");
  assert.ok(github.issues[0].labels.some((label) => label.name === "scan:error"));
}

async function testPartialSummaryDownloadFailsClosed() {
  const root = tempDir();
  const first = selected(123, "first");
  const second = selected(456, "second");
  const files = input(root, [first, second], [target(first), target(second)], [cleanSummary(first)]);
  const github = new FakeGitHub();
  const context = {repo: {owner: "control", repo: "private"}, runId: 502, runAttempt: 1};

  await assert.rejects(() => reconcile({
    github,
    context,
    core: fakeCore(),
    repositoryPrivate: true,
    staleAfterHours: "192",
    scanResult: "success",
    selectionAvailable: true,
    planAvailable: true,
    summariesAvailable: true,
    ...files,
  }), /normalized summary artifacts are incomplete/);

  assert.equal(github.issues.length, 2);
  const firstIssue = github.issues.find((issue) => issue.title.endsWith("example/first"));
  const secondIssue = github.issues.find((issue) => issue.title.endsWith("example/second"));
  assert.equal(firstIssue.state, "closed");
  assert.equal(secondIssue.state, "open");
  assert.ok(secondIssue.labels.some((label) => label.name === "scan:error"));
}

async function testSelectionValidation() {
  const root = tempDir();
  const file = path.join(root, "selection.json");
  writeJson(file, {repositories: [selected(1, "one"), selected(1, "duplicate")]});
  assert.throws(() => reconcile._internal.loadSelection(file), /duplicate repository id/);

  const timestamp = Date.parse("2026-08-01T00:00:00.000Z");
  assert.equal(reconcile._internal.isStale(timestamp, new Date("2026-08-10T00:00:00Z"), 192), true);
  assert.equal(reconcile._internal.isStale(timestamp, new Date("2026-08-02T00:00:00Z"), 192), false);
}

(async () => {
  await testCompleteReconciliation();
  await testMissingPlanFailsClosed();
  await testFailedRunInvalidatesPassingDashboard();
  await testRecentArtifactPreventsFalseStaleAfterUnchangedScans();
  await testFailedSummaryDownloadFailsClosed();
  await testPartialSummaryDownloadFailsClosed();
  await testSelectionValidation();
  process.stdout.write("organization dashboard reconciliation tests passed\n");
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
