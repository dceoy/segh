"use strict";

const fs = require("node:fs");
const path = require("node:path");
const publisher = require("./publish-dashboard.js");
const {idempotentGitHub} = require("./dashboard-idempotent-github.js");
const {hardenedSummaryCopy} = require("./dashboard-summary-contract.js");

const dashboard = publisher._internal;
const MANAGED = /<!-- segh-dashboard: v1 -->/;
const REPOSITORY_ID = /<!-- segh-repository-id: ([0-9]+) -->/;
const OVERALL_STATUS = /<!-- segh-overall-status: (pass|findings|incomplete|error|retired) -->/;
const PREVIOUS_STATUS = /<!-- segh-previous-status: (none|pass|findings|incomplete|error|retired) -->/;
const FINDING_FINGERPRINT = /<!-- segh-finding-fingerprint: (sha256:[0-9a-f]{64}) -->/;
const SCAN_TIMESTAMP = /^- \*\*Scan timestamp:\*\* ([^\n]+)$/m;

const LABEL_DEFINITIONS = Object.freeze({
  "scan:pass": {color: "1f883d", description: "Latest security scan passed"},
  "scan:findings": {color: "d1242f", description: "Latest security scan has actionable findings"},
  "scan:incomplete": {color: "bf8700", description: "Latest security scan has incomplete coverage"},
  "scan:error": {color: "b60205", description: "Latest security scan or publication encountered an error"},
  "scan:retired": {color: "6e7781", description: "Repository is no longer in the active scan selection"},
  "finding:scorecard": {color: "8250df", description: "OpenSSF Scorecard finding category"},
  "finding:actions": {color: "0969da", description: "GitHub Actions finding category"},
  "finding:shell": {color: "0550ae", description: "Shell finding category"},
  "finding:vulnerability": {color: "cf222e", description: "Dependency vulnerability finding category"},
  "finding:secret": {color: "a40e26", description: "Secret exposure finding category"},
  "finding:misconfiguration": {color: "9a6700", description: "Configuration finding category"},
});

function marker(body, pattern, fallback = "none") {
  return String(body || "").match(pattern)?.[1] || fallback;
}

function repositoryId(issue) {
  const value = marker(issue?.body, REPOSITORY_ID, "");
  const parsed = Number.parseInt(value, 10);
  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : null;
}

function currentStatus(issue) {
  return marker(issue?.body, OVERALL_STATUS, "none");
}

function lastScanTimestamp(issue) {
  const value = marker(issue?.body, SCAN_TIMESTAMP, "");
  const timestamp = Date.parse(value);
  return Number.isFinite(timestamp) ? timestamp : null;
}

function parseBoundedInteger(value, name, minimum, maximum) {
  if (!/^[0-9]+$/.test(String(value || ""))) {
    throw new Error(`${name} must be an integer from ${minimum} to ${maximum}`);
  }
  const parsed = Number.parseInt(value, 10);
  if (!Number.isSafeInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new Error(`${name} must be an integer from ${minimum} to ${maximum}`);
  }
  return parsed;
}

function validateSelectionEntry(entry) {
  if (!entry || typeof entry !== "object" || !Number.isSafeInteger(entry.id) || entry.id <= 0) {
    throw new Error("selection snapshot contains an invalid repository id");
  }
  for (const field of ["full_name", "owner", "name", "visibility", "default_branch", "disposition", "reason"]) {
    if (typeof entry[field] !== "string" || entry[field].length === 0) {
      throw new Error(`selection snapshot contains an invalid ${field}`);
    }
  }
  if (entry.full_name !== `${entry.owner}/${entry.name}` || entry.owner.includes("/") || entry.name.includes("/")) {
    throw new Error("selection snapshot contains inconsistent repository identity");
  }
  if (!["public", "private", "internal"].includes(entry.visibility) || typeof entry.fork !== "boolean" ||
      typeof entry.archived !== "boolean" || typeof entry.disabled !== "boolean") {
    throw new Error("selection snapshot contains invalid repository metadata");
  }
  if (!["active", "retired"].includes(entry.disposition) || entry.reason.length > 120) {
    throw new Error("selection snapshot contains an invalid disposition");
  }
  if (entry.disposition === "retired" && !entry.archived && !entry.disabled) {
    throw new Error("selection snapshot retires an active repository");
  }
  if (entry.disposition === "active" && (entry.archived || entry.disabled)) {
    throw new Error("selection snapshot activates an archived or disabled repository");
  }
}

function loadSelection(file) {
  const value = JSON.parse(fs.readFileSync(file, "utf8"));
  if (!value || typeof value !== "object" || !Array.isArray(value.repositories) || value.repositories.length > 100) {
    throw new Error("selection snapshot must contain at most 100 repositories");
  }
  const ids = new Set();
  for (const entry of value.repositories) {
    validateSelectionEntry(entry);
    if (ids.has(entry.id)) throw new Error(`selection snapshot contains duplicate repository id ${entry.id}`);
    ids.add(entry.id);
  }
  return [...value.repositories].sort((a, b) => a.id - b.id);
}

function loadPlan(file) {
  const value = JSON.parse(fs.readFileSync(file, "utf8"));
  if (!value || typeof value !== "object" || !Array.isArray(value.include) || value.include.length > 100) {
    throw new Error("scan plan must contain an include array with at most 100 repositories");
  }
  if (value.include.length === 0) return [];
  return dashboard.loadPlan(file);
}

function planMatchesSelection(target, selected) {
  return target.id === selected.id && target.full_name === selected.full_name &&
    target.visibility === selected.visibility && target.default_branch === selected.default_branch;
}

async function listBounded(method, params) {
  const items = [];
  for (let page = 1; page <= 10; page += 1) {
    const response = await dashboard.requestWithRetry(() => method({...params, per_page: 100, page}));
    if (!Array.isArray(response?.data)) throw new Error("GitHub list API returned a malformed response");
    items.push(...response.data);
    if (response.data.length < 100) return items;
  }
  throw new Error("GitHub list API exceeded the 1000 item bound");
}

async function listManagedIssues(github, owner, repo) {
  const issues = await listBounded(github.rest.issues.listForRepo, {owner, repo, state: "all"});
  return issues.filter((issue) => !issue.pull_request && MANAGED.test(String(issue.body || "")));
}

async function ensureLabels(github, owner, repo) {
  const labels = await listBounded(github.rest.issues.listLabelsForRepo, {owner, repo});
  const names = new Set(labels.map((label) => String(label.name || "").toLowerCase()));
  for (const [name, definition] of Object.entries(LABEL_DEFINITIONS)) {
    if (names.has(name)) continue;
    await dashboard.requestWithRetry(() => github.rest.issues.createLabel({owner, repo, name, ...definition}));
  }
}

function previousStatus(issue, desiredStatus) {
  if (!issue) return "none";
  const oldCurrent = currentStatus(issue);
  const oldPrevious = marker(issue.body, PREVIOUS_STATUS, "none");
  return oldCurrent === desiredStatus ? oldPrevious : oldCurrent;
}

function safeReason(reason) {
  return String(reason || "organization reconciliation is incomplete").replace(/[\r\n]+/g, " ").slice(0, 160);
}

function renderSelectionError(selected, issue, context, reason) {
  const status = "error";
  const previous = previousStatus(issue, status);
  const normalizedReason = safeReason(reason);
  const fingerprint = dashboard.sha256(`organization-reconciliation:${selected.id}:${normalizedReason}`);
  const title = `[Security dashboard] ${selected.full_name}`;
  const state = "open";
  const labels = ["scan:error"];
  const workflowUrl = `https://github.com/${context.repo.owner}/${context.repo.repo}/actions/runs/${context.runId}`;
  const bodyWithoutDigest = [
    "<!-- segh-dashboard: v1 -->",
    `<!-- segh-repository-id: ${selected.id} -->`,
    "<!-- segh-overall-status: error -->",
    `<!-- segh-previous-status: ${previous} -->`,
    `<!-- segh-finding-fingerprint: ${fingerprint} -->`,
    "",
    `# Security dashboard: ${selected.full_name}`,
    "",
    "## Current state",
    "",
    "- **Overall status:** error",
    `- **Previous status:** ${previous}`,
    `- **Repository ID:** ${selected.id}`,
    `- **Visibility:** ${selected.visibility}`,
    `- **Default branch:** ${selected.default_branch}`,
    "- **Scanned commit:** unavailable",
    `- **Reconciliation run:** ${workflowUrl}`,
    "",
    `The current organization run could not produce complete immutable scan evidence for this repository: ${normalizedReason}.`,
    "",
    "Review the private workflow run and restore complete scan coverage. No repository source excerpt, path, secret value, or scanner log is published here.",
    "",
  ].join("\n");
  const digest = dashboard.sha256(dashboard.canonicalJson({
    title,
    state,
    labels,
    repository_id: selected.id,
    full_name: selected.full_name,
    visibility: selected.visibility,
    default_branch: selected.default_branch,
    status,
    previous_status: previous,
    reason: normalizedReason,
  }));
  return {title, state, labels, body: `${bodyWithoutDigest}<!-- segh-result-digest: ${digest} -->\n`, digest, status, previousStatus: previous, fingerprint};
}

function renderRetiredSelection(selected, issue) {
  const status = "retired";
  const previous = previousStatus(issue, status);
  const fingerprint = issue ? marker(issue.body, FINDING_FINGERPRINT, dashboard.sha256(`retired:${selected.id}`)) : dashboard.sha256(`retired:${selected.id}`);
  const title = `[Security dashboard] ${selected.full_name}`;
  const state = "closed";
  const labels = ["scan:retired"];
  const reason = safeReason(selected.reason);
  const bodyWithoutDigest = [
    "<!-- segh-dashboard: v1 -->",
    `<!-- segh-repository-id: ${selected.id} -->`,
    "<!-- segh-overall-status: retired -->",
    `<!-- segh-previous-status: ${previous} -->`,
    `<!-- segh-finding-fingerprint: ${fingerprint} -->`,
    "",
    `# Security dashboard: ${selected.full_name}`,
    "",
    "## Current state",
    "",
    "- **Overall status:** retired",
    `- **Previous status:** ${previous}`,
    `- **Repository ID:** ${selected.id}`,
    `- **Visibility:** ${selected.visibility}`,
    `- **Default branch:** ${selected.default_branch}`,
    "",
    `This repository is excluded from active scanning because ${reason}.`,
    "",
  ].join("\n");
  const digest = dashboard.sha256(dashboard.canonicalJson({
    title,
    state,
    labels,
    repository_id: selected.id,
    full_name: selected.full_name,
    status,
    previous_status: previous,
    reason,
  }));
  return {title, state, labels, body: `${bodyWithoutDigest}<!-- segh-result-digest: ${digest} -->\n`, digest, status, previousStatus: previous, fingerprint};
}

function selectionFromIssue(issue) {
  const id = repositoryId(issue);
  if (!id) throw new Error(`managed issue #${issue.number} lacks a valid repository id marker`);
  const fullName = String(issue.title || "").replace(/^\[Security dashboard\]\s*/, "").slice(0, 200) || `repository-${id}`;
  const [owner = "unknown", name = `repository-${id}`] = fullName.split("/", 2);
  const visibility = String(issue.body || "").match(/^- \*\*Visibility:\*\* (public|private|internal)$/m)?.[1] || "private";
  const defaultBranch = String(issue.body || "").match(/^- \*\*Default branch:\*\* ([^\n]+)$/m)?.[1] || "unknown";
  return {id, full_name: fullName, owner, name, visibility, fork: false, archived: false, disabled: false, default_branch: defaultBranch, disposition: "active", reason: "organization reconciliation is incomplete"};
}

function isStale(issue, now, staleAfterHours) {
  const timestamp = lastScanTimestamp(issue);
  return timestamp === null || now.getTime() - timestamp > staleAfterHours * 60 * 60 * 1000;
}

async function applyDecision(github, owner, repo, issue, desired, results, core) {
  try {
    const result = await dashboard.applyDesired(github, owner, repo, issue, desired);
    results.push({repository_id: repositoryId(result.issue) || repositoryId(issue) || null, status: desired.status, action: result.action});
  } catch (error) {
    const id = repositoryId(issue) || Number.parseInt(String(desired.body).match(REPOSITORY_ID)?.[1] || "0", 10) || null;
    results.push({repository_id: id, status: desired.status, action: "failed"});
    core.warning(`dashboard publication failed for repository id ${id || "unknown"}: ${safeReason(error.message)}`);
  }
}

function countBy(results, field, values) {
  const counts = Object.fromEntries(values.map((value) => [value, 0]));
  for (const result of results) {
    if (Object.hasOwn(counts, result[field])) counts[result[field]] += 1;
  }
  return counts;
}

async function writeOrganizationSummary(core, results, completeness) {
  const statuses = countBy(results, "status", ["pass", "findings", "incomplete", "error", "retired"]);
  const actions = countBy(results, "action", ["created", "updated", "unchanged", "retired-untracked", "deferred", "failed"]);
  const rows = [
    ["Status", "Count"],
    ...Object.entries(statuses).map(([name, count]) => [name, String(count)]),
    ["", ""],
    ["Publication action", "Count"],
    ...Object.entries(actions).map(([name, count]) => [name, String(count)]),
  ];
  if (core.summary?.addHeading) {
    await core.summary
      .addHeading("Organization dashboard reconciliation")
      .addRaw(`Completeness: ${completeness}\n\n`)
      .addTable(rows)
      .write();
  } else {
    core.info(`organization reconciliation summary: completeness=${completeness} statuses=${JSON.stringify(statuses)} actions=${JSON.stringify(actions)}`);
  }
  return {statuses, actions};
}

async function reconcile(options) {
  if (options.repositoryPrivate !== true && options.repositoryPrivate !== "true") {
    throw new Error("dashboard reconciliation requires a private control repository");
  }
  const staleAfterHours = parseBoundedInteger(options.staleAfterHours || "192", "stale_after_hours", 24, 720);
  const scanResult = String(options.scanResult || "unknown");
  if (!new Set(["success", "failure", "cancelled", "skipped", "unknown"]).has(scanResult)) {
    throw new Error("scan_result has an unsupported value");
  }

  const github = idempotentGitHub(options.github);
  const {owner, repo} = options.context.repo;
  await ensureLabels(github, owner, repo);
  const managed = await listManagedIssues(github, owner, repo);
  const issueById = dashboard.indexManagedIssues(managed);
  const now = new Date();
  const results = [];
  let completeness = "complete";
  let selection = null;
  let selectionError = null;
  let targets = null;
  let planError = null;

  if (options.selectionAvailable && fs.existsSync(options.selectionPath)) {
    try {
      selection = loadSelection(options.selectionPath);
    } catch (error) {
      selectionError = error;
      completeness = "selection-error";
    }
  } else {
    completeness = "selection-missing";
  }

  if (options.planAvailable && fs.existsSync(options.planPath)) {
    try {
      targets = loadPlan(options.planPath);
    } catch (error) {
      planError = error;
      completeness = completeness === "complete" ? "plan-error" : completeness;
    }
  } else {
    completeness = completeness === "complete" ? "plan-missing" : completeness;
  }

  let summariesRoot = options.summariesPath;
  let hardened = null;
  if (targets && targets.length > 0) {
    hardened = hardenedSummaryCopy(options.summariesPath);
    summariesRoot = hardened;
  }

  try {
    const targetById = new Map((targets || []).map((target) => [target.id, target]));
    const summaries = targets ? dashboard.loadSummaries(summariesRoot, targets, options.context) : new Map();
    const decided = new Set();

    if (selection) {
      const selectionById = new Map(selection.map((entry) => [entry.id, entry]));
      for (const selected of selection) {
        const issue = issueById.get(selected.id)?.[0] || null;
        if (selected.disposition === "retired") {
          if (!issue) {
            results.push({repository_id: selected.id, status: "retired", action: "retired-untracked"});
          } else {
            await applyDecision(github, owner, repo, issue, renderRetiredSelection(selected, issue), results, options.core);
          }
          decided.add(selected.id);
          continue;
        }

        const target = targetById.get(selected.id);
        let desired;
        if (!target) {
          desired = renderSelectionError(selected, issue, options.context,
            planError ? `immutable scan plan is invalid: ${safeReason(planError.message)}` : "immutable scan target is missing from the current run");
        } else if (!planMatchesSelection(target, selected)) {
          desired = renderSelectionError(selected, issue, options.context, "selection identity does not match the immutable scan plan");
        } else {
          desired = dashboard.renderIssue(summaries.get(selected.id), issue);
        }
        await applyDecision(github, owner, repo, issue, desired, results, options.core);
        decided.add(selected.id);
      }

      for (const target of targets || []) {
        if (selectionById.has(target.id)) continue;
        const issue = issueById.get(target.id)?.[0] || null;
        const selected = {
          id: target.id,
          full_name: target.full_name,
          owner: target.owner,
          name: target.name,
          visibility: target.visibility,
          fork: target.fork,
          archived: false,
          disabled: false,
          default_branch: target.default_branch,
          disposition: "active",
          reason: "scan plan target is absent from the authoritative App selection",
        };
        await applyDecision(github, owner, repo, issue,
          renderSelectionError(selected, issue, options.context, selected.reason), results, options.core);
        decided.add(target.id);
        completeness = "identity-mismatch";
      }

      for (const [id, entries] of [...issueById.entries()].sort((a, b) => a[0] - b[0])) {
        if (decided.has(id)) continue;
        const desired = dashboard.renderRetiredIssue(entries[0]);
        await applyDecision(github, owner, repo, entries[0], desired, results, options.core);
      }
    } else if (targets) {
      const activeIds = new Set();
      for (const target of targets) {
        const issue = issueById.get(target.id)?.[0] || null;
        await applyDecision(github, owner, repo, issue, dashboard.renderIssue(summaries.get(target.id), issue), results, options.core);
        activeIds.add(target.id);
      }
      for (const [id, entries] of [...issueById.entries()].sort((a, b) => a[0] - b[0])) {
        if (activeIds.has(id)) continue;
        const issue = entries[0];
        if (currentStatus(issue) === "retired") {
          results.push({repository_id: id, status: "retired", action: "deferred"});
          continue;
        }
        if (scanResult !== "success" || isStale(issue, now, staleAfterHours)) {
          const selected = selectionFromIssue(issue);
          await applyDecision(github, owner, repo, issue,
            renderSelectionError(selected, issue, options.context, "complete GitHub App selection evidence is unavailable for this run"), results, options.core);
        } else {
          results.push({repository_id: id, status: currentStatus(issue), action: "deferred"});
        }
      }
    } else {
      for (const [id, entries] of [...issueById.entries()].sort((a, b) => a[0] - b[0])) {
        const issue = entries[0];
        if (currentStatus(issue) === "retired") {
          results.push({repository_id: id, status: "retired", action: "deferred"});
          continue;
        }
        const selected = selectionFromIssue(issue);
        const shouldError = scanResult !== "success" || isStale(issue, now, staleAfterHours);
        if (shouldError) {
          await applyDecision(github, owner, repo, issue,
            renderSelectionError(selected, issue, options.context, "the current run produced neither a complete selection snapshot nor an immutable scan plan"), results, options.core);
        } else {
          results.push({repository_id: id, status: currentStatus(issue), action: "deferred"});
        }
      }
    }
  } finally {
    if (hardened) fs.rmSync(hardened, {recursive: true, force: true});
  }

  const summary = await writeOrganizationSummary(options.core, results, completeness);
  const failed = summary.actions.failed;
  const incompleteInputs = Boolean(selectionError || planError || !selection || !targets);
  if (failed > 0 || incompleteInputs || completeness === "identity-mismatch") {
    const reasons = [];
    if (failed > 0) reasons.push(`${failed} publication operation(s) failed`);
    if (selectionError) reasons.push(`selection snapshot is invalid: ${safeReason(selectionError.message)}`);
    else if (!selection) reasons.push("selection snapshot is unavailable");
    if (planError) reasons.push(`scan plan is invalid: ${safeReason(planError.message)}`);
    else if (!targets) reasons.push("scan plan is unavailable");
    if (completeness === "identity-mismatch") reasons.push("selection and scan plan identities disagree");
    throw new Error(reasons.join("; "));
  }

  return results;
}

module.exports = reconcile;
module.exports._internal = {
  currentStatus,
  isStale,
  loadPlan,
  loadSelection,
  planMatchesSelection,
  renderRetiredSelection,
  renderSelectionError,
  repositoryId,
  selectionFromIssue,
  writeOrganizationSummary,
};
