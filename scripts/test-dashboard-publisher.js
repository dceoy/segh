"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const publish = require("./publish-dashboard.js");
const {GitHub} = require("./test-dashboard-github.js");
const {input, scanner, summary} = require("./test-dashboard-data.js");

const context = {repo: {owner: "control", repo: "private"}, runId: 456, runAttempt: 1};
const core = {info: () => {}};
const temp = () => fs.mkdtempSync(path.join(os.tmpdir(), "segh-publisher-test-"));

(async () => {
  let root = temp();
  let files = input(root, summary({scanners: [scanner("scorecard"), scanner("zizmor", "actions")]}));
  let github = new GitHub();
  await publish({github, context, core, ...files, repositoryPrivate: true});
  assert.equal(github.issues[0].state, "open");
  assert.ok(github.issues[0].labels.some(({name}) => name === "scan:error"));

  const mixedCoverage = summary({
    overall_status: "findings",
    scanners: summary().scanners.map((item) => {
      if (item.name === "zizmor") return {...item, status: "findings", findings: 1};
      if (item.name === "actionlint") return {...item, status: "skipped"};
      return item;
    }),
    findings: {total: 1, categories: ["actions"], fingerprint: `sha256:${"1".repeat(64)}`},
    remediation_categories: ["Harden GitHub Actions workflows and pin trusted dependencies."],
  });
  root = temp(); files = input(root, mixedCoverage); github = new GitHub();
  await publish({github, context, core, ...files, repositoryPrivate: true});
  assert.ok(github.issues[0].labels.some(({name}) => name === "scan:error"));

  root = temp(); files = input(root, summary()); github = new GitHub(); github.failCreateLabel = true;
  await publish({github, context, core, ...files, repositoryPrivate: true});
  assert.equal(github.labels.length, 11, "ambiguous label creation must reconcile without duplicates");
  assert.equal(github.issues.length, 1);

  root = temp(); files = input(root, summary()); github = new GitHub(); github.failCreate = true;
  await publish({github, context, core, ...files, repositoryPrivate: true});
  assert.equal(github.issues.length, 1);
  assert.match(github.issues[0].body, /segh-body-integrity: sha256:[0-9a-f]{64}/);

  const canonicalBody = github.issues[0].body;
  github.issues[0].body = canonicalBody.replace("# Security dashboard:", "# Operator-edited dashboard:");
  await publish({github, context, core, ...files, repositoryPrivate: true});
  assert.equal(github.issues[0].body, canonicalBody, "publisher must restore a modified managed issue body");
  assert.equal(github.comments.length, 0, "body repair without a result transition must not add history");

  const findings = summary({overall_status: "findings",
    scanners: summary().scanners.map((item) => item.name === "zizmor" ? {...item, status: "findings", findings: 1} : item),
    findings: {total: 1, categories: ["actions"], fingerprint: `sha256:${"1".repeat(64)}`},
    remediation_categories: ["Harden GitHub Actions workflows and pin trusted dependencies."]});
  fs.writeFileSync(path.join(files.summariesPath, "repository-summary-123", "summary.json"), `${JSON.stringify(findings)}\n`);
  github.failComment = true;
  await publish({github, context, core, ...files, repositoryPrivate: true});
  assert.equal(github.comments.length, 1);
  assert.match(github.comments[0].body, /segh-history-event: sha256:/);

  root = temp(); files = input(root, summary()); github = new GitHub();
  github.issues.push({number: 99, title: "Unrelated", body: "<!-- segh-repository-id: 123 -->", state: "open", labels: []});
  await publish({github, context, core, ...files, repositoryPrivate: true});
  assert.equal(github.issues.length, 2, "an unrelated repository-ID marker must not be adopted as a dashboard");
  assert.equal(github.issues.find((issue) => issue.number === 99).state, "open");
  const managed = github.issues.find((issue) => /segh-dashboard: v1/.test(issue.body));
  assert.ok(managed);
  assert.equal(managed.state, "closed");

  root = temp(); files = input(root, summary()); github = new GitHub();
  await publish({github, context, core, ...files, repositoryPrivate: true});
  fs.writeFileSync(path.join(files.summariesPath, "repository-summary-123", "summary.json"), `${JSON.stringify(findings)}\n`);
  github.failUpdate = true;
  await assert.rejects(
    () => publish({github, context, core, ...files, repositoryPrivate: true}),
    /definitive update failure/,
  );
  assert.equal(github.comments.length, 1, "the transition event must be persisted before the issue update");
  assert.match(github.issues[0].body, /segh-overall-status: pass/);

  const nextRunFindings = {...findings, scan: {
    ...findings.scan,
    timestamp: "2026-08-07T01:00:00.000Z",
    workflow_run_id: 789,
    workflow_url: "https://github.com/control/private/actions/runs/789",
  }};
  fs.writeFileSync(path.join(files.summariesPath, "repository-summary-123", "summary.json"), `${JSON.stringify(nextRunFindings)}\n`);
  const nextContext = {...context, runId: 789};
  await publish({github, context: nextContext, core, ...files, repositoryPrivate: true});
  assert.equal(github.comments.length, 1, "cross-run retry must reuse the persisted transition event");
  assert.match(github.issues[0].body, /segh-overall-status: findings/);
  assert.match(github.issues[0].body, /actions\/runs\/789/);
  console.log("publisher hardening tests passed");
})().catch((error) => { console.error(error.stack || error); process.exit(1); });
