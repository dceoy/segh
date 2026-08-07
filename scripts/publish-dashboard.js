"use strict";

const fs = require("node:fs");
const core = require("./core/publish-dashboard.js");
const {hardenedSummaryCopy, completeScannerSet} = require("./dashboard-summary-contract.js");
const {idempotentGitHub, repositoryId} = require("./dashboard-idempotent-github.js");

const MANAGED_DASHBOARD = /<!-- segh-dashboard: v1 -->/;
const RETIRED_LABEL = {
  name: "scan:retired",
  color: "6e7781",
  description: "Repository is no longer in the active scan selection",
};

function hasAuthoritativeEmptyPlan(planPath) {
  try {
    const plan = JSON.parse(fs.readFileSync(planPath, "utf8"));
    return Boolean(plan && typeof plan === "object" && Array.isArray(plan.include) && plan.include.length === 0);
  } catch {
    return false;
  }
}

async function listManagedIssues(github, owner, repo) {
  const issues = [];
  for (let page = 1; page <= 10; page += 1) {
    const response = await core._internal.requestWithRetry(() => github.rest.issues.listForRepo({
      owner,
      repo,
      state: "all",
      per_page: 100,
      page,
    }));
    if (!Array.isArray(response?.data)) throw new Error("GitHub list API returned a malformed response");
    issues.push(...response.data.filter((issue) => !issue.pull_request && MANAGED_DASHBOARD.test(String(issue.body || ""))));
    if (response.data.length < 100) return issues;
  }
  throw new Error("GitHub list API exceeded the 1000 item bound");
}

async function retireEmptySelection(options, github) {
  const {owner, repo} = options.context.repo;
  const managed = await listManagedIssues(github, owner, repo);
  const issueById = core._internal.indexManagedIssues(managed);
  if (issueById.size > 0) {
    await core._internal.requestWithRetry(() => github.rest.issues.createLabel({owner, repo, ...RETIRED_LABEL}));
  }
  const results = [];
  for (const [id, entries] of [...issueById.entries()].sort((a, b) => a[0] - b[0])) {
    const desired = core._internal.renderRetiredIssue(entries[0]);
    const result = await core._internal.applyDesired(github, owner, repo, entries[0], desired);
    results.push({repository_id: id, action: result.action});
  }
  const counts = results.reduce((acc, result) => {
    acc[result.action] = (acc[result.action] || 0) + 1;
    return acc;
  }, {});
  options.core.info(`dashboard publication complete: ${JSON.stringify(counts)}`);
  return results;
}

async function publish(options) {
  const github = idempotentGitHub(options.github);
  if (hasAuthoritativeEmptyPlan(options.planPath)) {
    return retireEmptySelection(options, github);
  }
  const summariesPath = hardenedSummaryCopy(options.summariesPath);
  try {
    return await core({...options, github, summariesPath});
  } finally {
    fs.rmSync(summariesPath, {recursive: true, force: true});
  }
}

module.exports = publish;
module.exports._internal = {
  ...core._internal,
  completeScannerSet,
  hasAuthoritativeEmptyPlan,
  idempotentGitHub,
  repositoryId,
  retireEmptySelection,
};
