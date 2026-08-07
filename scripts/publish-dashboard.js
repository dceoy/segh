"use strict";

const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const core = require("./core/publish-dashboard.js");
const {hardenedSummaryCopy, completeScannerSet} = require("./dashboard-summary-contract.js");
const {idempotentGitHub, repositoryId} = require("./dashboard-idempotent-github.js");

const MANAGED_DASHBOARD = /<!-- segh-dashboard: v1 -->/;
const RETIRED_LABEL = {
  name: "scan:retired",
  color: "6e7781",
  description: "Repository is no longer in the active scan selection",
};
const MAX_API_PAGES = 10;
const API_PAGE_SIZE = 100;

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
  for (let page = 1; page <= MAX_API_PAGES; page += 1) {
    const response = await core._internal.requestWithRetry(() => github.rest.issues.listForRepo({
      owner,
      repo,
      state: "all",
      per_page: API_PAGE_SIZE,
      page,
    }));
    if (!Array.isArray(response?.data)) throw new Error("GitHub list API returned a malformed response");
    issues.push(...response.data.filter((issue) => !issue.pull_request && MANAGED_DASHBOARD.test(String(issue.body || ""))));
    if (response.data.length < API_PAGE_SIZE) return issues;
  }
  throw new Error(`GitHub list API exceeded the ${MAX_API_PAGES * API_PAGE_SIZE} item bound`);
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

function workflowRunTimestamp(run, field) {
  const value = Date.parse(run?.[field]);
  return Number.isFinite(value) ? value : null;
}

async function trustedSuccessfulWorkflowRuns(github, context) {
  const {owner, repo} = context.repo;
  const current = await github.rest.actions.getWorkflowRun({owner, repo, run_id: context.runId});
  const workflowId = current?.data?.workflow_id;
  if (!Number.isSafeInteger(workflowId) || workflowId <= 0) {
    throw new Error("current reconciliation run has no valid workflow identity");
  }

  const trusted = new Map();
  for (let page = 1; page <= MAX_API_PAGES; page += 1) {
    const response = await github.rest.actions.listWorkflowRuns({
      owner,
      repo,
      workflow_id: workflowId,
      status: "completed",
      per_page: API_PAGE_SIZE,
      page,
    });
    const runs = response?.data?.workflow_runs;
    if (!Array.isArray(runs)) throw new Error("GitHub Actions workflow-run API returned a malformed response");
    for (const run of runs) {
      if (run?.conclusion !== "success" || !Number.isSafeInteger(run?.id) || run.id <= 0) continue;
      const startedAt = workflowRunTimestamp(run, "run_started_at") ?? workflowRunTimestamp(run, "created_at");
      const completedAt = workflowRunTimestamp(run, "updated_at");
      if (!Number.isFinite(startedAt) || !Number.isFinite(completedAt) || completedAt < startedAt) continue;
      trusted.set(run.id, {startedAt, completedAt});
    }
    if (runs.length < API_PAGE_SIZE) return trusted;
  }
  throw new Error(`GitHub Actions workflow-run API exceeded the ${MAX_API_PAGES * API_PAGE_SIZE} item bound`);
}

function withTrustedSummaryArtifacts(github, context) {
  const actions = github?.rest?.actions;
  if (!actions || typeof actions.listArtifactsForRepo !== "function" ||
      typeof actions.getWorkflowRun !== "function" || typeof actions.listWorkflowRuns !== "function") {
    throw new Error("GitHub Actions read API is unavailable for authoritative scan freshness");
  }

  const listArtifactsForRepo = actions.listArtifactsForRepo.bind(actions);
  let trustedRunsPromise = null;
  let trustedArtifactsPromise = null;

  const loadTrustedRuns = () => {
    trustedRunsPromise ||= trustedSuccessfulWorkflowRuns(github, context);
    return trustedRunsPromise;
  };

  const loadTrustedArtifacts = async (owner, repo) => {
    if (!trustedArtifactsPromise) {
      trustedArtifactsPromise = (async () => {
        const artifacts = [];
        for (let page = 1; page <= MAX_API_PAGES; page += 1) {
          const response = await listArtifactsForRepo({owner, repo, per_page: API_PAGE_SIZE, page});
          const pageArtifacts = response?.data?.artifacts;
          if (!Array.isArray(pageArtifacts)) throw new Error("GitHub Actions artifact API returned a malformed response");
          artifacts.push(...pageArtifacts);
          if (pageArtifacts.length < API_PAGE_SIZE) break;
          if (page === MAX_API_PAGES) {
            throw new Error(`GitHub Actions artifact API exceeded the ${MAX_API_PAGES * API_PAGE_SIZE} item bound`);
          }
        }

        const trustedRuns = await loadTrustedRuns();
        return artifacts.flatMap((artifact) => {
          const runId = artifact?.workflow_run?.id;
          const trustedRun = trustedRuns.get(runId);
          const createdAt = Date.parse(artifact?.created_at);
          if (!trustedRun || !Number.isFinite(createdAt) || createdAt < trustedRun.startedAt || createdAt > trustedRun.completedAt) {
            return [];
          }
          return [{...artifact, created_at: new Date(trustedRun.completedAt).toISOString()}];
        });
      })();
    }
    return trustedArtifactsPromise;
  };

  const trustedActions = {
    ...actions,
    listArtifactsForRepo: async (params = {}) => {
      const owner = params.owner || context.repo.owner;
      const repo = params.repo || context.repo.repo;
      const perPage = Number.isSafeInteger(params.per_page) && params.per_page > 0 ? params.per_page : API_PAGE_SIZE;
      const page = Number.isSafeInteger(params.page) && params.page > 0 ? params.page : 1;
      const artifacts = await loadTrustedArtifacts(owner, repo);
      const offset = (page - 1) * perPage;
      return {
        data: {
          total_count: artifacts.length,
          artifacts: artifacts.slice(offset, offset + perPage),
        },
      };
    },
  };

  return {...github, rest: {...github.rest, actions: trustedActions}};
}

async function reconcileOrganization(options) {
  const reconcileDashboard = require("./reconcile-organization-dashboard.js");
  const scanResult = String(options.scanResult || "unknown");
  const github = withTrustedSummaryArtifacts(options.github, options.context);
  let suppressedSummaries = null;
  const forwarded = {...options, github};

  if (scanResult !== "success") {
    suppressedSummaries = fs.mkdtempSync(path.join(os.tmpdir(), "segh-failed-scan-summaries-"));
    forwarded.summariesAvailable = false;
    forwarded.summariesPath = suppressedSummaries;
  }

  try {
    const results = await reconcileDashboard(forwarded);
    if (scanResult !== "success") throw new Error(`source scan result is ${scanResult}`);
    return results;
  } catch (error) {
    if (scanResult !== "success" && !String(error.message || "").includes("source scan result is")) {
      throw new Error(`source scan result is ${scanResult}; ${error.message}`);
    }
    throw error;
  } finally {
    if (suppressedSummaries) fs.rmSync(suppressedSummaries, {recursive: true, force: true});
  }
}

module.exports = publish;
module.exports.reconcileOrganization = reconcileOrganization;
module.exports._internal = {
  ...core._internal,
  completeScannerSet,
  hasAuthoritativeEmptyPlan,
  idempotentGitHub,
  repositoryId,
  retireEmptySelection,
  trustedSuccessfulWorkflowRuns,
  withTrustedSummaryArtifacts,
};
