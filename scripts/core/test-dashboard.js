#!/usr/bin/env node

"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {buildSummary} = require("./build-dashboard-summary.js");
const publish = require("./publish-dashboard.js");
const {
  MANAGED_LABELS,
  loadSummaries,
  renderIssue,
  sha256,
} = publish._internal;

function tempDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "segh-dashboard-test-"));
}

function writeJson(file, value) {
  fs.mkdirSync(path.dirname(file), {recursive: true});
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
}

function target(overrides = {}) {
  return {
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
    ...overrides,
  };
}

function successfulEnv(overrides = {}) {
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

function writeCleanResults(dir) {
  writeJson(path.join(dir, "target.json"), target());
  writeJson(path.join(dir, "scorecard.json"), {
    checks: [
      {Name: "Pinned-Dependencies", Score: 8, Reason: "unbounded source text"},
      {Name: "Token-Permissions", Score: 10},
      {Name: "Unselected-Check", Score: 2, Reason: "must not render"},
    ],
  });
  writeJson(path.join(dir, "zizmor.json"), []);
  fs.writeFileSync(path.join(dir, "actionlint.jsonl"), "");
  writeJson(path.join(dir, "shellcheck.json"), {comments: []});
  fs.writeFileSync(path.join(dir, "shellcheck-status.txt"), "0\n");
  writeJson(path.join(dir, "trivy-vulnerability.json"), {Results: []});
  writeJson(path.join(dir, "trivy-secret.json"), {Results: []});
  writeJson(path.join(dir, "trivy-misconfiguration.json"), {Results: []});
}

function cleanSummary(overrides = {}) {
  return {
    schema_version: 1,
    repository: {
      id: 123,
      full_name: "example/project",
      visibility: "private",
      default_branch: "main",
      commit_sha: "a".repeat(40),
    },
    scan: {
      timestamp: "2026-08-06T00:00:00.000Z",
      workflow_run_id: 456,
      workflow_run_attempt: 1,
      workflow_repository: "dceoy/segh",
      workflow_url: "https://github.com/control/private/actions/runs/456",
      evidence_artifact: "repository-scan-123",
    },
    overall_status: "pass",
    scanners: [
      {name: "scorecard", status: "pass", findings: 0, selected_checks: [{name: "Pinned-Dependencies", score: 8}]},
      {name: "zizmor", status: "pass", findings: 0, category: "actions"},
    ],
    findings: {total: 0, categories: [], fingerprint: sha256("clean")},
    remediation_categories: [],
    ...overrides,
  };
}

class FakeGitHub {
  constructor() {
    this.labels = [];
    this.issues = [];
    this.comments = [];
    this.nextNumber = 1;
    this.calls = [];
    this.rest = {
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
            labels: params.labels.map((name) => ({name})),
          };
          this.issues.push(issue);
          return {data: issue};
        },
        update: async (params) => {
          this.calls.push(["update", params]);
          const issue = this.issues.find((candidate) => candidate.number === params.issue_number);
          assert.ok(issue, `missing fake issue ${params.issue_number}`);
          for (const key of ["title", "body", "state"]) {
            if (params[key] !== undefined) issue[key] = params[key];
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

  async paginate(method, params) {
    const response = await method(params);
    return response.data;
  }
}

function writePublicationInput(root, summaries) {
  const plan = {
    include: summaries.map((summary) => ({
      id: summary.repository.id,
      full_name: summary.repository.full_name,
      owner: summary.repository.full_name.split("/")[0],
      name: summary.repository.full_name.split("/")[1],
      visibility: summary.repository.visibility,
      fork: false,
      default_branch: summary.repository.default_branch,
      commit_sha: summary.repository.commit_sha,
    })),
  };
  const planPath = path.join(root, "matrix.json");
  writeJson(planPath, plan);
  const summariesPath = path.join(root, "summaries");
  summaries.forEach((summary) => writeJson(path.join(summariesPath, `repository-summary-${summary.repository.id}`, "summary.json"), summary));
  return {planPath, summariesPath};
}

async function testBuildSummary() {
  const dir = tempDir();
  writeCleanResults(dir);
  const summary = buildSummary({resultsDir: dir, env: successfulEnv(), now: new Date("2026-08-06T00:00:00Z")});
  assert.equal(summary.overall_status, "pass");
  assert.equal(summary.findings.total, 0);
  assert.deepEqual(summary.scanners[0].selected_checks, [
    {name: "Pinned-Dependencies", score: 8},
    {name: "Token-Permissions", score: 10},
  ]);
  assert.ok(!JSON.stringify(summary).includes("unbounded source text"));
  assert.ok(!JSON.stringify(summary).includes("Unselected-Check"));

  writeJson(path.join(dir, "zizmor.json"), [{rule: "dangerous-trigger", path: ".github/workflows/x.yml", snippet: "secret"}]);
  fs.writeFileSync(path.join(dir, "actionlint.jsonl"), `${JSON.stringify({filepath: ".github/workflows/x.yml", message: "bad"})}\n`);
  writeJson(path.join(dir, "shellcheck.json"), {comments: [{file: "secret.sh", line: 1, message: "quote"}]});
  fs.writeFileSync(path.join(dir, "shellcheck-status.txt"), "1\n");
  writeJson(path.join(dir, "trivy-vulnerability.json"), {Results: [{Vulnerabilities: [{VulnerabilityID: "CVE-1"}]}]});
  writeJson(path.join(dir, "trivy-secret.json"), {Results: [{Secrets: [{Match: "TOP_SECRET_VALUE"}]}]});
  writeJson(path.join(dir, "trivy-misconfiguration.json"), {Results: [{Misconfigurations: [{Message: "privileged"}]}]});
  const findings = buildSummary({
    resultsDir: dir,
    env: successfulEnv({
      ZIZMOR_OUTCOME: "failure",
      ACTIONLINT_OUTCOME: "failure",
      SHELLCHECK_OUTCOME: "failure",
      TRIVY_VULNERABILITY_OUTCOME: "failure",
      TRIVY_SECRET_OUTCOME: "failure",
      TRIVY_MISCONFIGURATION_OUTCOME: "failure",
    }),
  });
  assert.equal(findings.overall_status, "findings");
  assert.equal(findings.findings.total, 6);
  assert.deepEqual(findings.findings.categories, ["actions", "misconfiguration", "secret", "shell", "vulnerability"]);
  const serialized = JSON.stringify(findings);
  for (const forbidden of ["TOP_SECRET_VALUE", "secret.sh", ".github/workflows/x.yml", "privileged"]) {
    assert.ok(!serialized.includes(forbidden), `summary leaked ${forbidden}`);
  }

  const incomplete = buildSummary({resultsDir: dir, env: successfulEnv({PREFLIGHT_OUTCOME: "failure", SCORECARD_OUTCOME: "skipped", ZIZMOR_OUTCOME: "skipped", ACTIONLINT_OUTCOME: "skipped", SHELLCHECK_OUTCOME: "skipped", TRIVY_VULNERABILITY_OUTCOME: "skipped", TRIVY_SECRET_OUTCOME: "skipped", TRIVY_MISCONFIGURATION_OUTCOME: "skipped"})});
  assert.equal(incomplete.overall_status, "incomplete");

  fs.writeFileSync(path.join(dir, "shellcheck-status.txt"), "2\n");
  const runtimeError = buildSummary({resultsDir: dir, env: successfulEnv({SHELLCHECK_OUTCOME: "failure"})});
  assert.equal(runtimeError.overall_status, "error");
}

async function testPublisherLifecycle() {
  const root = tempDir();
  const firstSummary = cleanSummary();
  const input = writePublicationInput(root, [firstSummary]);
  const github = new FakeGitHub();
  const core = {info: () => {}};
  const context = {repo: {owner: "control", repo: "private"}, runId: 456, runAttempt: 1};

  let result = await publish({github, context, core, ...input, repositoryPrivate: true});
  assert.deepEqual(result, [{repository_id: 123, action: "created"}]);
  assert.equal(github.issues.length, 1);
  assert.equal(github.issues[0].state, "closed");
  assert.ok(github.issues[0].body.includes("<!-- segh-repository-id: 123 -->"));
  assert.deepEqual(github.issues[0].labels.map((label) => label.name), ["scan:pass"]);
  assert.equal(github.comments.length, 0);
  assert.deepEqual(new Set(github.labels.map((label) => label.name)), MANAGED_LABELS);

  github.calls = [];
  const rerunSummary = cleanSummary({scan: {...firstSummary.scan, timestamp: "2026-08-06T01:00:00.000Z", workflow_run_id: 999, workflow_url: "https://github.com/control/private/actions/runs/999"}});
  writeJson(path.join(input.summariesPath, "repository-summary-123", "summary.json"), rerunSummary);
  result = await publish({github, context: {...context, runId: 999}, core, ...input, repositoryPrivate: "true"});
  assert.deepEqual(result, [{repository_id: 123, action: "unchanged"}]);
  assert.equal(github.calls.length, 0, "unchanged rerun must perform no API write");

  github.issues[0].labels.push({name: "operator:owned"});
  const renamed = cleanSummary({repository: {...firstSummary.repository, full_name: "example/renamed"}});
  const renamedPlan = {
    include: [{id: 123, full_name: "example/renamed", owner: "example", name: "renamed", visibility: "private", fork: false, default_branch: "main", commit_sha: "a".repeat(40)}],
  };
  writeJson(input.planPath, renamedPlan);
  writeJson(path.join(input.summariesPath, "repository-summary-123", "summary.json"), renamed);
  github.calls = [];
  result = await publish({github, context, core, ...input, repositoryPrivate: true});
  assert.deepEqual(result, [{repository_id: 123, action: "updated"}]);
  assert.equal(github.issues.length, 1, "rename must reuse the existing issue");
  assert.equal(github.issues[0].title, "[Security dashboard] example/renamed");
  assert.ok(github.issues[0].labels.some((label) => label.name === "operator:owned"));
  assert.equal(github.comments.length, 0, "rename without status/fingerprint change must not add history");

  const findingFingerprint = sha256("finding");
  const findings = cleanSummary({
    repository: {...firstSummary.repository, full_name: "example/renamed"},
    overall_status: "findings",
    scanners: [{name: "zizmor", status: "findings", findings: 2, category: "actions"}],
    findings: {total: 2, categories: ["actions"], fingerprint: findingFingerprint},
    remediation_categories: ["Harden GitHub Actions workflows and pin trusted dependencies."],
  });
  writeJson(path.join(input.summariesPath, "repository-summary-123", "summary.json"), findings);
  result = await publish({github, context, core, ...input, repositoryPrivate: true});
  assert.deepEqual(result, [{repository_id: 123, action: "updated"}]);
  assert.equal(github.issues[0].state, "open");
  assert.ok(github.issues[0].labels.some((label) => label.name === "scan:findings"));
  assert.ok(github.issues[0].labels.some((label) => label.name === "finding:actions"));
  assert.equal(github.comments.length, 1);

  const recovered = cleanSummary({
    repository: {...firstSummary.repository, full_name: "example/renamed"},
    scan: {...firstSummary.scan, timestamp: "2026-08-06T02:00:00.000Z", workflow_run_id: 1000, workflow_url: "https://github.com/control/private/actions/runs/1000"},
  });
  writeJson(path.join(input.summariesPath, "repository-summary-123", "summary.json"), recovered);
  result = await publish({github, context: {...context, runId: 1000}, core, ...input, repositoryPrivate: true});
  assert.deepEqual(result, [{repository_id: 123, action: "updated"}]);
  assert.equal(github.issues[0].state, "closed");
  assert.ok(github.issues[0].labels.some((label) => label.name === "scan:pass"));
  assert.ok(!github.issues[0].labels.some((label) => label.name === "finding:actions"));
  assert.equal(github.comments.length, 2, "recovery must append one bounded history entry");

  writeJson(input.planPath, {include: [{id: 999, full_name: "example/other", owner: "example", name: "other", visibility: "private", fork: false, default_branch: "main", commit_sha: "c".repeat(40)}]});
  const other = cleanSummary({repository: {id: 999, full_name: "example/other", visibility: "private", default_branch: "main", commit_sha: "c".repeat(40)}, findings: {total: 0, categories: [], fingerprint: sha256("other")}});
  writeJson(path.join(input.summariesPath, "repository-summary-999", "summary.json"), other);
  result = await publish({github, context, core, ...input, repositoryPrivate: true});
  assert.deepEqual(result.map((entry) => entry.repository_id), [999, 123]);
  const retired = github.issues.find((issue) => issue.number === 1);
  assert.equal(retired.state, "closed");
  assert.ok(retired.labels.some((label) => label.name === "scan:retired"));
}

async function testMissingAndMalformedSummary() {
  const root = tempDir();
  const summary = cleanSummary();
  const {planPath, summariesPath} = writePublicationInput(root, [summary]);
  fs.rmSync(summariesPath, {recursive: true, force: true});
  const context = {repo: {owner: "control", repo: "private"}, runId: 1, runAttempt: 1};
  const loaded = loadSummaries(summariesPath, [{id: 123, full_name: "example/project", visibility: "private", default_branch: "main", commit_sha: "a".repeat(40)}], context);
  assert.equal(loaded.get(123).overall_status, "error");

  const github = new FakeGitHub();
  await publish({github, context, core: {info: () => {}}, planPath, summariesPath, repositoryPrivate: true});
  assert.equal(github.issues[0].state, "open");
  assert.ok(github.issues[0].labels.some((label) => label.name === "scan:error"));

  fs.mkdirSync(path.join(summariesPath, "repository-summary-123"), {recursive: true});
  fs.writeFileSync(path.join(summariesPath, "repository-summary-123", "summary.json"), "{not-json\n");
  let malformed = loadSummaries(summariesPath, [{id: 123, full_name: "example/project", visibility: "private", default_branch: "main", commit_sha: "a".repeat(40)}], context);
  assert.equal(malformed.get(123).overall_status, "error");

  writeJson(path.join(summariesPath, "repository-summary-123", "summary.json"), cleanSummary({repository: {...summary.repository, full_name: "example/mismatch"}}));
  const mismatched = loadSummaries(summariesPath, [{id: 123, full_name: "example/project", visibility: "private", default_branch: "main", commit_sha: "a".repeat(40)}], context);
  assert.equal(mismatched.get(123).overall_status, "error");

  writeJson(path.join(summariesPath, "repository-summary-123", "summary.json"), summary);
  writeJson(path.join(summariesPath, "duplicate", "repository-summary-123", "summary.json"), summary);
  const duplicate = loadSummaries(summariesPath, [{id: 123, full_name: "example/project", visibility: "private", default_branch: "main", commit_sha: "a".repeat(40)}], context);
  assert.equal(duplicate.get(123).overall_status, "error");
}

async function testPublicRefusalAndDuplicateDetection() {
  const root = tempDir();
  const input = writePublicationInput(root, [cleanSummary()]);
  const context = {repo: {owner: "control", repo: "public"}, runId: 1, runAttempt: 1};
  const github = new FakeGitHub();
  await assert.rejects(() => publish({github, context, core: {info: () => {}}, ...input, repositoryPrivate: false}), /private control repository/);
  assert.equal(github.calls.length, 0);

  const desired = renderIssue(cleanSummary());
  github.issues.push(
    {number: 1, title: desired.title, body: desired.body, state: desired.state, labels: desired.labels.map((name) => ({name}))},
    {number: 2, title: desired.title, body: desired.body, state: desired.state, labels: desired.labels.map((name) => ({name}))},
  );
  await assert.rejects(() => publish({github, context: {...context, repo: {owner: "control", repo: "private"}}, core: {info: () => {}}, ...input, repositoryPrivate: true}), /2 managed dashboard issues/);
  assert.equal(github.calls.length, 0, "duplicate detection must fail before API writes");
}

(async () => {
  await testBuildSummary();
  await testPublisherLifecycle();
  await testMissingAndMalformedSummary();
  await testPublicRefusalAndDuplicateDetection();
  console.log("dashboard publisher tests passed");
})().catch((error) => {
  console.error(error.stack || error);
  process.exit(1);
});
