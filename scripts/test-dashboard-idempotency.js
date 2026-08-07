#!/usr/bin/env node

"use strict";

const assert = require("node:assert/strict");
const {idempotentGitHub} = require("./dashboard-idempotent-github.js");

const MANAGED_LABELS = new Set(["scan:pass", "scan:findings"]);
const fp = (character) => `sha256:${character.repeat(64)}`;

function body(status, fingerprint, run) {
  return [
    "<!-- segh-dashboard: v1 -->",
    "<!-- segh-repository-id: 123 -->",
    `<!-- segh-overall-status: ${status} -->`,
    `<!-- segh-finding-fingerprint: ${fingerprint} -->`,
    `run:${run}`,
    "<!-- segh-result-digest: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa -->",
    "",
  ].join("\n");
}

class GitHub {
  constructor() {
    this.comments = [];
    this.issue = {
      number: 1,
      title: "dashboard",
      body: body("pass", fp("0"), 0),
      state: "closed",
      labels: [{name: "Scan:Pass"}, {name: "operator-owned"}],
    };
    this.rest = {issues: {
      listForRepo: async () => ({data: [this.issue]}),
      listLabelsForRepo: async () => ({data: []}),
      listComments: async () => ({data: this.comments}),
      createLabel: async (params) => ({data: {name: params.name}}),
      create: async () => { throw new Error("not used"); },
      update: async (params) => {
        this.issue = {...this.issue, ...params, number: this.issue.number};
        return {data: this.issue};
      },
      createComment: async (params) => {
        const comment = {id: this.comments.length + 1, body: params.body};
        this.comments.push(comment);
        return {data: comment};
      },
    }};
  }
}

async function transition(github, api, status, fingerprint, run, comment) {
  await api.rest.issues.update({
    owner: "control",
    repo: "private",
    issue_number: 1,
    body: body(status, fingerprint, run),
  });
  await api.rest.issues.createComment({
    owner: "control",
    repo: "private",
    issue_number: 1,
    body: comment,
  });
  assert.match(github.issue.body, new RegExp(`run:${run}`));
}

(async () => {
  const github = new GitHub();
  const api = idempotentGitHub(github);

  const listed = await api.rest.issues.listForRepo({owner: "control", repo: "private", state: "all"});
  const names = listed.data[0].labels.map((label) => typeof label === "string" ? label : label.name);
  assert.deepEqual(names, ["scan:pass", "operator-owned"]);
  assert.deepEqual(names.filter((name) => MANAGED_LABELS.has(name)), ["scan:pass"]);
  assert.deepEqual(names.filter((name) => !MANAGED_LABELS.has(name)), ["operator-owned"]);

  const passToFindings = "Security dashboard state changed.\n\n- Status: pass → findings";
  const findingsToPass = "Security dashboard state changed.\n\n- Status: findings → pass";
  const findingsChanged = "Security dashboard state changed.\n\n- Status: findings → findings\n- Finding fingerprint changed.";

  await transition(github, api, "findings", fp("1"), 1, passToFindings);
  await transition(github, api, "pass", fp("0"), 2, findingsToPass);
  await transition(github, api, "findings", fp("1"), 3, passToFindings);
  await transition(github, api, "pass", fp("0"), 4, findingsToPass);
  await transition(github, api, "findings", fp("1"), 5, passToFindings);
  assert.equal(github.comments.length, 5, "A→B→A→B transitions must each retain a history event");

  await transition(github, api, "findings", fp("2"), 6, findingsChanged);
  await transition(github, api, "findings", fp("3"), 7, findingsChanged);
  assert.equal(github.comments.length, 7, "consecutive finding changes must not reuse an older event marker");
  assert.equal(new Set(github.comments.map((comment) => comment.body.match(/segh-history-event: sha256:([0-9a-f]{64})/)[1])).size, 7);

  console.log("dashboard idempotency regression tests passed");
})().catch((error) => { console.error(error.stack || error); process.exit(1); });
