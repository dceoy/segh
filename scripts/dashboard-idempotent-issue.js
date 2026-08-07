"use strict";

const {list, managedDashboard, repositoryId, retryable} = require("./dashboard-github-common.js");

async function findIssue(github, owner, repo, id) {
  const matches = (await list(github.rest.issues.listForRepo, {owner, repo, state: "all"}))
    .filter((issue) => !issue.pull_request && managedDashboard(issue.body) && repositoryId(issue.body) === id);
  if (matches.length > 1) throw new Error(`repository id ${id} has ${matches.length} managed dashboard issues`);
  return matches[0] || null;
}

function idempotentCreate(github) {
  const create = github.rest.issues.create.bind(github.rest.issues);
  return async (params) => {
    const managed = managedDashboard(params.body);
    const id = managed ? repositoryId(params.body) : null;
    const existing = id && await findIssue(github, params.owner, params.repo, id);
    if (existing) return {data: existing};
    try {
      return await create(params);
    } catch (error) {
      if (!id || !retryable(error)) throw error;
      const reconciled = await findIssue(github, params.owner, params.repo, id);
      if (reconciled) return {data: reconciled};
      throw error;
    }
  };
}

module.exports = {idempotentCreate};
