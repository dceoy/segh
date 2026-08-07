"use strict";

const fs = require("node:fs");
const path = require("node:path");

const MANAGED = /<!-- segh-dashboard: v1 -->/;
const REPOSITORY_ID = /<!-- segh-repository-id: ([0-9]+) -->/;
const LABELS = Object.freeze({
  "scan:pass": ["1f883d", "Latest security scan passed"],
  "scan:findings": ["d1242f", "Latest security scan has actionable findings"],
  "scan:incomplete": ["bf8700", "Latest security scan has incomplete coverage"],
  "scan:error": ["b60205", "Latest security scan encountered an error"],
  "finding:scorecard": ["8250df", "OpenSSF Scorecard finding category"],
  "finding:actions": ["0969da", "GitHub Actions finding category"],
  "finding:shell": ["0550ae", "Shell finding category"],
  "finding:vulnerability": ["cf222e", "Dependency vulnerability finding category"],
  "finding:secret": ["a40e26", "Secret exposure finding category"],
  "finding:misconfiguration": ["9a6700", "Configuration finding category"],
});
const VALID_STATUS = new Set(["pass", "findings", "incomplete", "error"]);

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function readPlan(file) {
  const plan = readJson(file);
  if (!Array.isArray(plan?.include) || plan.include.length > 100) throw new Error("invalid scan plan");
  for (const target of plan.include) {
    if (!Number.isSafeInteger(target?.id) || target.id <= 0 || typeof target.full_name !== "string") {
      throw new Error("invalid scan target");
    }
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
    const summary = readJson(file);
    const id = summary?.repository?.id;
    if (!Number.isSafeInteger(id) || id <= 0 || summaries.has(id)) throw new Error("invalid or duplicate dashboard summary");
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
  return [...new Set(names)].filter((name) => Object.hasOwn(LABELS, name)).sort();
}

function validateSummary(target, summary) {
  if (!summary || !VALID_STATUS.has(summary.overall_status) || !Array.isArray(summary.scanners)) return false;
  return summary.repository?.id === target.id && summary.repository?.full_name === target.full_name &&
    summary.repository?.commit_sha === target.commit_sha;
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
    lines.push("", `Raw evidence remains in the private workflow artifact \`${summary.scan?.evidence_artifact || `repository-scan-${target.id}`}\`.`, "");
  }

  return {title, state, labels, body: `${lines.join("\n")}\n`, status};
}

async function ensureLabels(github, owner, repo) {
  for (const [name, [color, description]] of Object.entries(LABELS)) {
    try {
      await github.rest.issues.createLabel({owner, repo, name, color, description});
    } catch (error) {
      if ((error?.status || error?.response?.status) !== 422) throw error;
    }
  }
}

async function managedIssues(github, owner, repo) {
  const issues = await github.paginate(github.rest.issues.listForRepo, {owner, repo, state: "all", per_page: 100});
  return issues.filter((issue) => !issue.pull_request && MANAGED.test(String(issue.body || "")));
}

function sameIssue(issue, desired) {
  return issue.title === desired.title && issue.body === desired.body && issue.state === desired.state &&
    JSON.stringify(labelNames(issue.labels)) === JSON.stringify([...desired.labels].sort());
}

async function apply(github, owner, repo, existing, desired) {
  if (!existing) {
    const created = await github.rest.issues.create({owner, repo, title: desired.title, body: desired.body, labels: desired.labels});
    if (desired.state === "closed") {
      await github.rest.issues.update({owner, repo, issue_number: created.data.number, state: "closed"});
    }
    return "created";
  }
  if (sameIssue(existing, desired)) return "unchanged";
  await github.rest.issues.update({
    owner,
    repo,
    issue_number: existing.number,
    title: desired.title,
    body: desired.body,
    labels: desired.labels,
    state: desired.state,
  });
  return "updated";
}

async function publish(options) {
  if (String(options.repositoryPrivate) !== "true") throw new Error("dashboard publication requires a private control repository");
  const targets = readPlan(options.planPath);
  const summaries = loadSummaries(options.summariesPath);
  const {owner, repo} = options.context.repo;
  await ensureLabels(options.github, owner, repo);
  const existing = await managedIssues(options.github, owner, repo);
  const byId = new Map();
  for (const issue of existing.sort((a, b) => a.number - b.number)) {
    const id = repositoryId(issue);
    if (id && !byId.has(id)) byId.set(id, issue);
  }

  const results = [];
  for (const target of targets) {
    try {
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
