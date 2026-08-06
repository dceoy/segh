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

  root = temp(); files = input(root, summary()); github = new GitHub(); github.failCreate = true;
  await publish({github, context, core, ...files, repositoryPrivate: true});
  assert.equal(github.issues.length, 1);

  const findings = summary({overall_status: "findings",
    scanners: summary().scanners.map((item) => item.name === "zizmor" ? {...item, status: "findings", findings: 1} : item),
    findings: {total: 1, categories: ["actions"], fingerprint: `sha256:${"1".repeat(64)}`},
    remediation_categories: ["Harden GitHub Actions workflows and pin trusted dependencies."]});
  fs.writeFileSync(path.join(files.summariesPath, "repository-summary-123", "summary.json"), `${JSON.stringify(findings)}\n`);
  github.failComment = true;
  await publish({github, context, core, ...files, repositoryPrivate: true});
  assert.equal(github.comments.length, 1);
  assert.match(github.comments[0].body, /segh-history-event: sha256:/);
  console.log("publisher hardening tests passed");
})().catch((error) => { console.error(error.stack || error); process.exit(1); });
