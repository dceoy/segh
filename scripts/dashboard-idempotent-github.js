"use strict";

const {list, managedDashboard, repositoryId} = require("./dashboard-github-common.js");
const {idempotentCreate} = require("./dashboard-idempotent-issue.js");
const {idempotentComment} = require("./dashboard-idempotent-comment.js");

const OVERALL_STATUS = /<!-- segh-overall-status: (pass|findings|incomplete|error|retired) -->/;
const FINDING_FINGERPRINT = /<!-- segh-finding-fingerprint: (sha256:[0-9a-f]{64}) -->/;

function marker(body, pattern) {
  return String(body || "").match(pattern)?.[1] || "none";
}

function historyChanged(before, after) {
  return managedDashboard(after) &&
    (marker(before, OVERALL_STATUS) !== marker(after, OVERALL_STATUS) ||
     marker(before, FINDING_FINGERPRINT) !== marker(after, FINDING_FINGERPRINT));
}

function issueKey(params) {
  return `${params.owner}/${params.repo}#${params.issue_number}`;
}

async function findIssue(github, params) {
  const issues = await list(github.rest.issues.listForRepo, {owner: params.owner, repo: params.repo, state: "all"});
  return issues.find((issue) => !issue.pull_request && issue.number === params.issue_number) || null;
}

function idempotentGitHub(github) {
  const issues = {...github.rest.issues};
  const update = github.rest.issues.update.bind(github.rest.issues);
  const createComment = idempotentComment(github);
  const pendingUpdates = new Map();

  issues.create = idempotentCreate(github);
  issues.update = async (params) => {
    if (typeof params.body !== "string" || !managedDashboard(params.body)) return update(params);
    const current = await findIssue(github, params);
    if (!current || !historyChanged(current.body, params.body)) return update(params);
    pendingUpdates.set(issueKey(params), params);
    return {data: current};
  };
  issues.createComment = async (params) => {
    const result = await createComment(params);
    const key = issueKey(params);
    const pending = pendingUpdates.get(key);
    if (pending) {
      await update(pending);
      pendingUpdates.delete(key);
    }
    return result;
  };
  return {...github, rest: {...github.rest, issues}};
}

module.exports = {idempotentGitHub, repositoryId};
