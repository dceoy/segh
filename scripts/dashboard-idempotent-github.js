"use strict";

const crypto = require("node:crypto");
const {list, managedDashboard, repositoryId} = require("./dashboard-github-common.js");
const {idempotentCreate} = require("./dashboard-idempotent-issue.js");
const {idempotentComment} = require("./dashboard-idempotent-comment.js");

const OVERALL_STATUS = /<!-- segh-overall-status: (pass|findings|incomplete|error|retired) -->/;
const FINDING_FINGERPRINT = /<!-- segh-finding-fingerprint: (sha256:[0-9a-f]{64}) -->/;
const RESULT_DIGEST = /<!-- segh-result-digest: sha256:[0-9a-f]{64} -->/;
const BODY_INTEGRITY = /<!-- segh-body-integrity: sha256:([0-9a-f]{64}) -->\n?$/;

function marker(body, pattern) {
  return String(body || "").match(pattern)?.[1] || "none";
}

function sha256(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function withoutBodyIntegrity(body) {
  return String(body || "").replace(BODY_INTEGRITY, "");
}

function withBodyIntegrity(body) {
  const canonical = withoutBodyIntegrity(body);
  const normalized = canonical.endsWith("\n") ? canonical : `${canonical}\n`;
  return `${normalized}<!-- segh-body-integrity: sha256:${sha256(normalized)} -->\n`;
}

function hasValidBodyIntegrity(body) {
  const text = String(body || "");
  const match = text.match(BODY_INTEGRITY);
  return Boolean(match) && sha256(withoutBodyIntegrity(text)) === match[1];
}

function invalidateUntrustedDigest(issue) {
  if (!managedDashboard(issue.body) || hasValidBodyIntegrity(issue.body)) return issue;
  return {
    ...issue,
    body: String(issue.body || "").replace(RESULT_DIGEST, "<!-- segh-result-digest: invalid -->"),
  };
}

function withManagedBodyIntegrity(params) {
  if (typeof params.body !== "string" || !managedDashboard(params.body)) return params;
  return {...params, body: withBodyIntegrity(params.body)};
}

function disableOctokitRetries(github) {
  const source = github.rest.issues;
  const issues = {};
  for (const [name, value] of Object.entries(source)) {
    issues[name] = typeof value === "function"
      ? (params = {}) => value.call(source, {
          ...params,
          request: {...(params.request || {}), retries: 0},
        })
      : value;
  }
  const listForRepo = issues.listForRepo;
  issues.listForRepo = async (params) => {
    const response = await listForRepo(params);
    if (!Array.isArray(response?.data)) return response;
    return {...response, data: response.data.map(invalidateUntrustedDigest)};
  };
  return {...github, rest: {...github.rest, issues}};
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
  const hardened = disableOctokitRetries(github);
  const issues = {...hardened.rest.issues};
  const create = hardened.rest.issues.create;
  const update = hardened.rest.issues.update;
  hardened.rest.issues.create = (params) => create(withManagedBodyIntegrity(params));
  hardened.rest.issues.update = (params) => update(withManagedBodyIntegrity(params));

  const persistUpdate = hardened.rest.issues.update;
  const createComment = idempotentComment(hardened);
  const pendingUpdates = new Map();

  issues.create = idempotentCreate(hardened);
  issues.update = async (params) => {
    if (typeof params.body !== "string" || !managedDashboard(params.body)) return persistUpdate(params);
    const current = await findIssue(hardened, params);
    if (!current || !historyChanged(current.body, params.body)) return persistUpdate(params);
    pendingUpdates.set(issueKey(params), params);
    return {data: current};
  };
  issues.createComment = async (params) => {
    const result = await createComment(params);
    const key = issueKey(params);
    const pending = pendingUpdates.get(key);
    if (pending) {
      await persistUpdate(pending);
      pendingUpdates.delete(key);
    }
    return result;
  };
  return {...hardened, rest: {...hardened.rest, issues}};
}

module.exports = {
  hasValidBodyIntegrity,
  idempotentGitHub,
  repositoryId,
  withBodyIntegrity,
};
