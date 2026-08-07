"use strict";

const assert = require("node:assert/strict");
const {
  hasCurrentRendererContract,
  hasValidBodyIntegrity,
  idempotentGitHub,
  withBodyIntegrity,
} = require("./dashboard-idempotent-github.js");

const digest = `sha256:${"a".repeat(64)}`;
const fingerprint = `sha256:${"0".repeat(64)}`;
const body = [
  "<!-- segh-dashboard: v1 -->",
  "<!-- segh-repository-id: 123 -->",
  "<!-- segh-overall-status: pass -->",
  `<!-- segh-finding-fingerprint: ${fingerprint} -->`,
  `<!-- segh-result-digest: ${digest} -->`,
  "",
].join("\n");

class GitHub {
  constructor() {
    this.issue = {
      number: 1,
      title: "dashboard",
      body: withBodyIntegrity(body),
      state: "closed",
      labels: [{name: "scan:pass"}],
    };
    this.rest = {issues: {
      listForRepo: async () => ({data: [this.issue]}),
      listLabelsForRepo: async () => ({data: []}),
      listComments: async () => ({data: []}),
      createLabel: async (params) => ({data: {name: params.name}}),
      create: async () => { throw new Error("not used"); },
      update: async (params) => {
        this.issue = {...this.issue, ...params, number: this.issue.number};
        return {data: this.issue};
      },
      createComment: async (params) => ({data: params}),
    }};
  }
}

(async () => {
  const github = new GitHub();
  const api = idempotentGitHub(github);

  const listed = await api.rest.issues.listForRepo({owner: "control", repo: "private", state: "all"});
  assert.match(
    listed.data[0].body,
    /segh-result-digest: invalid/,
    "a body with valid legacy integrity but no renderer contract must migrate",
  );

  await api.rest.issues.update({
    owner: "control",
    repo: "private",
    issue_number: 1,
    body,
  });
  assert.ok(hasValidBodyIntegrity(github.issue.body));
  assert.ok(hasCurrentRendererContract(github.issue.body));
  assert.match(github.issue.body, /segh-renderer-version: 1/);
  assert.match(github.issue.body, /segh-renderer-digest: sha256:[0-9a-f]{64}/);

  console.log("dashboard renderer contract tests passed");
})().catch((error) => {
  console.error(error.stack || error);
  process.exit(1);
});
