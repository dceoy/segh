"use strict";

const fs = require("node:fs");
const path = require("node:path");

const MANAGED = /<!-- segh-dashboard: v1 -->/;
const REPOSITORY_ID = /<!-- segh-repository-id: ([0-9]+) -->/;
const OWNED_LABEL = /^(?:scan|finding):/;
const MANAGED_LABELS = new Set([
  "scan:pass",
  "scan:findings",
  "scan:incomplete",
  "scan:error",
  "finding:actions",
  "finding:shell",
  "finding:vulnerability",
  "finding:secret",
  "finding:misconfiguration",
]);
const VALID_STATUS = new Set(["pass", "findings", "incomplete", "error"]);
const VALID_SCANNER_STATUS = new Set(["pass", "findings", "skipped", "error"]);

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function readPlan(file) {
  const plan = readJson(file);
  if (!Array.isArray(plan?.include) || plan.include.length > 100) throw new Error("invalid scan plan");
  const ids = new Set();
  for (const target of plan.include) {
    if (!Number.isSafeInteger(target?.id) || target.id <= 0 || typeof target.full_name !== "string" || ids.has(target.id)) {
      throw new Error("invalid scan target");
    }
    ids.add(target.id);
  }
  return plan.include;
}

function summaryFiles(root) {
  if (!fs.existsSync(root)) return [];
  return fs.readdirSync(root, {withFileTypes: true}).flatMap((entry) => {
    const candidate = path.join(root, entry.name);
    if (entry.isDirectory()) return summaryFiles(candidate);
    return entry.isFile() && entry.name === "summary.json" ? [candidate] : [];
  });
}

function loadSummaries(root) {
  const summaries = new Map();
  for (const file of summaryFiles(root)) {
    let summary;
    try {
      summary = readJson(file);
    } catch {
      continue;
    }
    const id = summary?.repository?.id;
    if (!Number.isSafeInteger(id) || id <= 0) continue;
    if (summaries.has(id)) throw new Error(`duplicate dashboard summary for repository id ${id}`);
    summaries.set(id, summary);
  }
  return summaries;
}

function repositoryId(issue) {
  const value = String(issue?.body || "").match(REPOSITORY_ID)?.[1];
  const id = Number.parseInt(value || "", 10);
  return Number.isSafeInteger(id) && id > 0 ? id : null;
}

function labelNames(labels) {
  return (labels || []).map((label) => typeof label === "string" ? label : label?.name).filter(Boolean).sort();
}

function desiredLabels(summary) {
  const names = [`scan:${summary.overall_status}`];
  for (const scanner of summary.scanners || []) {
    if (scanner.status === "findings" && scanner.category) names.push(`finding:${scanner.category}`);
  }
  return [...new Set(names)].filter((name) => MANAGED_LABELS.has(name)).sort();
}

function mergedLabels(existing, desired) {
  const unmanaged = labelNames(existing?.labels).filter((name) => !OWNED_LABEL.test(name));
  return [...new Set([...unmanaged, ...desired.labels])].sort();
}

function validateSummary(target, summary) {
  if (!summary || !VALID_STATUS.has(summary.overall_status) || !Array.isArray(summary.scanners)) return false;
  if (summary.repository?.id !== target.id || summary.repository?.full_name !== target.full_name ||
      summary.repository?.commit_sha !== target.commit_sha) return false;
  if (summary.evidence_artifact !== `repository-scan-${target.id}`) return false;
  if (!summary.scanners.every((scanner) =>
    scanner && typeof scanner.name === "string" && VALID_SCANNER_STATUS.has(scanner.status) &&
    Number.isSafeInteger(scanner.findings) && scanner.findings >= 0 &&
    (scanner.status === "findings" ? scanner.findings > 0 : scanner.findings === 0) &&
    (scanner.category === undefined || typeof scanner.category === "string"))) return false;

  const statuses = summary.scanners.map((scanner) => scanner.status);
  if (summary.overall_status === "pass") {
    return statuses.some((status) => status === "pass") && statuses.every((status) => status === "pass" || status === "skipped");
  }
  if (summary.overall_status === "findings") {
    return statuses.includes("findings") && !statuses.includes("error");
  }
  if (summary.overall_status === "incomplete") return statuses.every((status) => status === "skipped");
  return true;
}

function render(target, summary, context) {
  const valid = validateSummary(target, summary);
  const status = valid ? summary.overall_status : "error";
  const labels = valid ? desiredLabels(summary) : ["scan:error"];
  const title = `[Security dashboard] ${target.full_name}`;
  const state = status === "pass" ? "closed" : "open";
  const runUrl = `https://github.com/${context.repo.owner}/${context.repo.repo}/actions/runs/${context.runId}`;
  const lines = [
    "<!-- segh-dashboard: v1 -->",
    `<!-- segh-repository-id: ${target.id} -->`,
    "",
    `# Security dashboard: ${target.full_name}`,
    "",
    "## Current state",
    "",
    `- **Overall status:** ${status}`,
    `- **Repository ID:** ${target.id}`,
    `- **Visibility:** ${target.visibility}`,
    `- **Default branch:** ${target.default_branch}`,
    `- **Scanned commit:** ${target.commit_sha}`,
    `- **Workflow run:** ${runUrl}`,
    "",
  ];

  if (!valid) {
    lines.push("The current run did not produce a valid normalized summary for this repository.", "");
  } else {
    lines.push("## Scanner results", "", "| Scanner | Status | Findings |", "| --- | --- | ---: |");
    for (const scanner of summary.scanners) {
      lines.push(`| ${scanner.name} | ${scanner.status} | ${scanner.findings} |`);
    }
    lines.push("", `Raw evidence remains in the private workflow artifact \`${summary.evidence_artifact}\`.`, "");
  }

  return {title, state, labels, body: `${lines.join("\n")}\n`, status};
}

async function managedIssues(github, owner, repo) {
  const issues = await github.paginate(github.rest.issues.listForRepo, {owner, repo, state: "all", per_page: 100});
  return issues.filter((issue) => !issue.pull_request && MANAGED.test(String(issue.body || "")));
}

function retryable(error) {
  const status = error?.status || error?.response?.status;
  return status === 429 || (Number.isInteger(status) && status >= 500 && status <= 599) ||
    (status === 403 && /secondary rate limit|rate limit/i.test(String(error?.message || "")));
}

async function findManagedIssue(github, owner, repo, id) {
  const matches = (await managedIssues(github, owner, repo)).filter((issue) => repositoryId(issue) === id);
  if (matches.length > 1) throw new Error(`repository id ${id} has ${matches.length} managed dashboard issues`);
  return matches[0] || null;
}

async function createIssue(github, owner, repo, desired) {
  const id = repositoryId({body: desired.body});
  if (!id) throw new Error("managed dashboard body lacks a repository id");
  const params = {
    owner,
    repo,
    title: desired.title,
    body: desired.body,
    labels: desired.labels,
    request: {retries: 0},
  };
  try {
    return await github.rest.issues.create(params);
  } catch (error) {
    if (!retryable(error)) throw error;
    const existing = await findManagedIssue(github, owner, repo, id);
    if (existing) return {data: existing};
    throw error;
  }
}

function sameIssue(issue, desired, labels = desired.labels) {
  return issue.title === desired.title && issue.body === desired.body && issue.state === desired.state &&
    JSON.stringify(labelNames(issue.labels)) === JSON.stringify([...labels].sort());
}

async function apply(github, owner, repo, existing, desired) {
  if (!existing) {
    const created = await createIssue(github, owner, repo, desired);
    if (desired.state === "closed") {
      await github.rest.issues.update({owner, repo, issue_number: created.data.number, state: "closed"});
    }
    return "created";
  }
  const labels = mergedLabels(existing, desired);
  if (sameIssue(existing, desired, labels)) return "unchanged";
  await github.rest.issues.update({
    owner,
    repo,
    issue_number: existing.number,
    title: desired.title,
    body: desired.body,
    labels,
    state: desired.state,
  });
  return "updated";
}

async function publish(options) {
  if (String(options.repositoryPrivate) !== "true") throw new Error("dashboard publication requires a private control repository");
  const targets = readPlan(options.planPath);
  const summaries = loadSummaries(options.summariesPath);
  const {owner, repo} = options.context.repo;
  const byId = new Map();
  const duplicateIds = new Set();
  for (const issue of (await managedIssues(options.github, owner, repo)).sort((a, b) => a.number - b.number)) {
    const id = repositoryId(issue);
    if (!id) continue;
    if (byId.has(id)) duplicateIds.add(id);
    else byId.set(id, issue);
  }

  const results = [];
  for (const target of targets) {
    try {
      if (duplicateIds.has(target.id)) throw new Error(`repository id ${target.id} has duplicate managed dashboard issues`);
      const desired = render(target, summaries.get(target.id), options.context);
      const action = await apply(options.github, owner, repo, byId.get(target.id), desired);
      results.push({repository_id: target.id, status: desired.status, action});
    } catch (error) {
      options.core.warning(`dashboard publication failed for repository id ${target.id}: ${error.message}`);
      results.push({repository_id: target.id, status: "error", action: "failed"});
    }
  }
  options.core.info(`dashboard publication complete: ${JSON.stringify(results)}`);
  const failures = results.filter((result) => result.action === "failed");
  if (failures.length) {
    throw new Error(`dashboard publication failed for repository ids: ${failures.map((result) => result.repository_id).join(", ")}`);
  }
  return results;
}

module.exports = publish;
module.exports._internal = {loadSummaries, readPlan, render, repositoryId};
