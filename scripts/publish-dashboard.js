"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const PRIMARY_LABELS = Object.freeze({
  pass: "scan:pass",
  findings: "scan:findings",
  incomplete: "scan:incomplete",
  error: "scan:error",
  retired: "scan:retired",
});

const FINDING_LABELS = Object.freeze({
  scorecard: "finding:scorecard",
  actions: "finding:actions",
  shell: "finding:shell",
  vulnerability: "finding:vulnerability",
  secret: "finding:secret",
  misconfiguration: "finding:misconfiguration",
});

const MANAGED_LABELS = new Set([...Object.values(PRIMARY_LABELS), ...Object.values(FINDING_LABELS)]);
const SCANNER_NAMES = new Set([
  "scorecard",
  "zizmor",
  "actionlint",
  "shellcheck",
  "trivy-vulnerability",
  "trivy-secret",
  "trivy-misconfiguration",
]);
const SCORECARD_CHECKS = new Set([
  "Branch-Protection",
  "Code-Review",
  "Dangerous-Workflow",
  "Pinned-Dependencies",
  "Token-Permissions",
  "Vulnerabilities",
]);
const REMEDIATION_CATEGORIES = new Set([
  "Harden GitHub Actions workflows and pin trusted dependencies.",
  "Correct shell diagnostics and unsafe scripting patterns.",
  "Update vulnerable dependencies or base components.",
  "Revoke exposed credentials and remove secret material from history.",
  "Harden infrastructure and deployment configuration.",
]);
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

const MARKERS = Object.freeze({
  managed: /<!-- segh-dashboard: v1 -->/,
  repositoryId: /<!-- segh-repository-id: ([0-9]+) -->/,
  resultDigest: /<!-- segh-result-digest: (sha256:[0-9a-f]{64}) -->/,
  overallStatus: /<!-- segh-overall-status: (pass|findings|incomplete|error|retired) -->/,
  previousStatus: /<!-- segh-previous-status: (none|pass|findings|incomplete|error|retired) -->/,
  findingFingerprint: /<!-- segh-finding-fingerprint: (sha256:[0-9a-f]{64}) -->/,
});

function sha256(value) {
  return `sha256:${crypto.createHash("sha256").update(value).digest("hex")}`;
}

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function sleep(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function retryDelay(error, attempt) {
  const headers = error?.response?.headers || {};
  const retryAfter = Number.parseInt(headers["retry-after"] || headers["Retry-After"] || "", 10);
  if (Number.isSafeInteger(retryAfter) && retryAfter >= 0) return Math.min(retryAfter * 1000, 30_000);
  return Math.min(1000 * (2 ** attempt), 8000);
}

function isRetryable(error) {
  const status = error?.status || error?.response?.status;
  if (status === 429 || (Number.isInteger(status) && status >= 500 && status <= 599)) return true;
  return status === 403 && /secondary rate limit|rate limit/i.test(String(error?.message || ""));
}

async function requestWithRetry(operation, attempts = 4) {
  let lastError;
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    try {
      return await operation();
    } catch (error) {
      lastError = error;
      if (!isRetryable(error) || attempt === attempts - 1) throw error;
      await sleep(retryDelay(error, attempt));
    }
  }
  throw lastError;
}

async function listBounded(method, params, maxPages = 10) {
  const items = [];
  const perPage = 100;
  for (let page = 1; page <= maxPages; page += 1) {
    const response = await requestWithRetry(() => method({...params, per_page: perPage, page}));
    if (!Array.isArray(response?.data)) throw new Error("GitHub list API returned a malformed response");
    items.push(...response.data);
    if (response.data.length < perPage) return items;
  }
  throw new Error(`GitHub list API exceeded the ${maxPages * perPage} item bound`);
}

function parseMarker(body, pattern, fallback = null) {
  const match = String(body || "").match(pattern);
  return match ? match[1] : fallback;
}

function parseRepositoryId(body) {
  const value = parseMarker(body, MARKERS.repositoryId);
  if (!value) return null;
  const parsed = Number.parseInt(value, 10);
  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : null;
}

function managedLabels(labels) {
  return labels
    .map((label) => typeof label === "string" ? label : label.name)
    .filter((name) => MANAGED_LABELS.has(name))
    .sort();
}

function allLabelNames(labels) {
  return labels.map((label) => typeof label === "string" ? label : label.name).filter(Boolean);
}

function validateTarget(target) {
  if (!target || typeof target !== "object") throw new Error("target plan entry must be an object");
  if (!Number.isSafeInteger(target.id) || target.id <= 0) throw new Error("target plan contains an invalid repository id");
  for (const field of ["full_name", "visibility", "default_branch", "commit_sha"]) {
    if (typeof target[field] !== "string" || target[field].length === 0) {
      throw new Error(`target plan contains an invalid ${field}`);
    }
  }
  if (!/^[0-9a-f]{40}$/.test(target.commit_sha)) throw new Error("target plan contains an invalid commit_sha");
  if (!["public", "private", "internal"].includes(target.visibility)) throw new Error("target plan contains an invalid visibility");
}

function loadPlan(planPath) {
  const plan = JSON.parse(fs.readFileSync(planPath, "utf8"));
  if (!plan || typeof plan !== "object" || !Array.isArray(plan.include) || plan.include.length === 0) {
    throw new Error("scan plan must contain a non-empty include array");
  }
  if (plan.include.length > 100) throw new Error("scan plan exceeds the 100 repository publication bound");
  const ids = new Set();
  for (const target of plan.include) {
    validateTarget(target);
    if (ids.has(target.id)) throw new Error(`scan plan contains duplicate repository id ${target.id}`);
    ids.add(target.id);
  }
  return [...plan.include].sort((a, b) => a.id - b.id);
}

function validateSummary(summary, target) {
  if (!summary || typeof summary !== "object" || summary.schema_version !== 1) {
    throw new Error("summary has an unsupported schema");
  }
  const repository = summary.repository;
  if (!repository || repository.id !== target.id || repository.full_name !== target.full_name ||
      repository.visibility !== target.visibility || repository.default_branch !== target.default_branch ||
      repository.commit_sha !== target.commit_sha) {
    throw new Error("summary identity does not match the immutable scan plan");
  }
  if (!["pass", "findings", "incomplete", "error"].includes(summary.overall_status)) {
    throw new Error("summary has an invalid overall status");
  }
  if (!Array.isArray(summary.scanners) || summary.scanners.length > 16) {
    throw new Error("summary has an invalid scanner list");
  }
  const scannerNames = new Set();
  for (const scanner of summary.scanners) {
    if (!scanner || typeof scanner.name !== "string" || !SCANNER_NAMES.has(scanner.name) || scannerNames.has(scanner.name) ||
        !["pass", "findings", "incomplete", "error", "skipped"].includes(scanner.status) ||
        !Number.isSafeInteger(scanner.findings) || scanner.findings < 0 || scanner.findings > 100000 ||
        (scanner.category !== undefined && !Object.hasOwn(FINDING_LABELS, scanner.category))) {
      throw new Error("summary contains an invalid scanner result");
    }
    scannerNames.add(scanner.name);
    if (scanner.selected_checks !== undefined &&
        (!Array.isArray(scanner.selected_checks) || scanner.selected_checks.length > 8 ||
         scanner.selected_checks.some((check) => !check || !SCORECARD_CHECKS.has(check.name) ||
           typeof check.score !== "number" || !Number.isFinite(check.score) || check.score < 0 || check.score > 10))) {
      throw new Error("summary contains invalid Scorecard checks");
    }
  }
  if (!summary.findings || !Number.isSafeInteger(summary.findings.total) || summary.findings.total < 0 ||
      !Array.isArray(summary.findings.categories) || summary.findings.categories.length > 8 ||
      typeof summary.findings.fingerprint !== "string" || !/^sha256:[0-9a-f]{64}$/.test(summary.findings.fingerprint)) {
    throw new Error("summary contains invalid bounded finding metadata");
  }
  const allowedCategories = new Set(Object.keys(FINDING_LABELS));
  if (summary.findings.categories.some((item) => typeof item !== "string" || !allowedCategories.has(item)) ||
      new Set(summary.findings.categories).size !== summary.findings.categories.length) {
    throw new Error("summary contains invalid finding categories");
  }
  if (!Array.isArray(summary.remediation_categories) || summary.remediation_categories.length > 8 ||
      summary.remediation_categories.some((item) => typeof item !== "string" || !REMEDIATION_CATEGORIES.has(item))) {
    throw new Error("summary contains invalid remediation categories");
  }
  if (!summary.scan || typeof summary.scan !== "object" ||
      typeof summary.scan.timestamp !== "string" || !Number.isFinite(Date.parse(summary.scan.timestamp)) ||
      !Number.isSafeInteger(summary.scan.workflow_run_id) || summary.scan.workflow_run_id <= 0 ||
      !Number.isSafeInteger(summary.scan.workflow_run_attempt) || summary.scan.workflow_run_attempt <= 0 ||
      typeof summary.scan.workflow_url !== "string" || !/^https:\/\/github\.com\/[^/]+\/[^/]+\/actions\/runs\/[0-9]+$/.test(summary.scan.workflow_url) ||
      summary.scan.evidence_artifact !== `repository-scan-${target.id}`) {
    throw new Error("summary contains invalid scan provenance");
  }
  const scannerTotal = summary.scanners.reduce((sum, scanner) => sum + scanner.findings, 0);
  if (scannerTotal !== summary.findings.total) throw new Error("summary finding count is inconsistent");
  if (summary.overall_status === "pass" &&
      (summary.findings.total !== 0 || summary.scanners.some((scanner) => ["findings", "error", "incomplete"].includes(scanner.status)))) {
    throw new Error("passing summary contains non-passing scanner state");
  }
  if (summary.overall_status === "findings" && summary.findings.total === 0) {
    throw new Error("findings summary contains no findings");
  }
  const serialized = JSON.stringify(summary);
  if (Buffer.byteLength(serialized, "utf8") > 32 * 1024) throw new Error("summary exceeds 32 KiB");
  return summary;
}

function syntheticErrorSummary(target, context, reason) {
  const safeReason = String(reason).replace(/[\r\n]+/g, " ").slice(0, 160);
  const fingerprint = sha256(`publication-input-error:${target.id}:${safeReason}`);
  return {
    schema_version: 1,
    repository: {
      id: target.id,
      full_name: target.full_name,
      visibility: target.visibility,
      default_branch: target.default_branch,
      commit_sha: target.commit_sha,
    },
    scan: {
      timestamp: new Date().toISOString(),
      workflow_run_id: context.runId,
      workflow_run_attempt: context.runAttempt,
      workflow_repository: `${context.repo.owner}/${context.repo.repo}`,
      workflow_url: `https://github.com/${context.repo.owner}/${context.repo.repo}/actions/runs/${context.runId}`,
      evidence_artifact: `repository-scan-${target.id}`,
    },
    overall_status: "error",
    scanners: [{name: "summary-publication-input", status: "error", findings: 0}],
    findings: {total: 0, categories: [], fingerprint},
    remediation_categories: ["Review the private workflow run and restore complete normalized scan evidence."],
  };
}

function findSummaryFiles(root) {
  const files = [];
  if (!fs.existsSync(root)) return files;
  for (const entry of fs.readdirSync(root, {withFileTypes: true})) {
    const candidate = path.join(root, entry.name);
    if (entry.isDirectory()) files.push(...findSummaryFiles(candidate));
    else if (entry.isFile() && entry.name === "summary.json") files.push(candidate);
  }
  return files.sort();
}

function loadSummaries(root, targets, context) {
  const byId = new Map();
  const targetById = new Map(targets.map((target) => [target.id, target]));
  for (const file of findSummaryFiles(root)) {
    const artifactMatch = file.match(/(?:^|[\/])repository-summary-([0-9]+)(?:[\/]|$)/);
    const artifactId = artifactMatch ? Number.parseInt(artifactMatch[1], 10) : null;
    let parsed = null;
    let parseError = null;
    try {
      parsed = JSON.parse(fs.readFileSync(file, "utf8"));
    } catch (error) {
      parseError = error;
    }
    const parsedId = parsed?.repository?.id;
    const id = Number.isSafeInteger(artifactId) && targetById.has(artifactId) ? artifactId : parsedId;
    if (!Number.isSafeInteger(id) || !targetById.has(id)) continue;
    const entries = byId.get(id) || [];
    entries.push({file, parsed, parseError});
    byId.set(id, entries);
  }

  const summaries = new Map();
  for (const target of targets) {
    const entries = byId.get(target.id) || [];
    if (entries.length !== 1) {
      const reason = entries.length === 0 ? "normalized summary artifact is missing" : "multiple normalized summary artifacts were found";
      summaries.set(target.id, syntheticErrorSummary(target, context, reason));
      continue;
    }
    try {
      if (entries[0].parseError) throw new Error("normalized summary artifact is malformed JSON");
      summaries.set(target.id, validateSummary(entries[0].parsed, target));
    } catch (error) {
      summaries.set(target.id, syntheticErrorSummary(target, context, error.message));
    }
  }
  return summaries;
}

function desiredManagedLabels(summary) {
  const labels = new Set([PRIMARY_LABELS[summary.overall_status]]);
  for (const category of summary.findings.categories) {
    const label = FINDING_LABELS[category];
    if (label) labels.add(label);
  }
  return [...labels].sort();
}

function renderScannerRows(scanners) {
  return scanners
    .slice(0, 16)
    .map((item) => `| ${item.name} | ${item.status} | ${item.findings} |`)
    .join("\n");
}

function renderScorecard(scanners) {
  const scorecard = scanners.find((item) => item.name === "scorecard");
  const checks = Array.isArray(scorecard?.selected_checks) ? scorecard.selected_checks.slice(0, 8) : [];
  if (checks.length === 0) return "No bounded Scorecard check scores were available.";
  return checks.map((check) => `- ${check.name}: ${check.score}/10`).join("\n");
}

function normalizePreviousStatus(issue, currentStatus) {
  if (!issue) return "none";
  const oldCurrent = parseMarker(issue.body, MARKERS.overallStatus, "none");
  const oldPrevious = parseMarker(issue.body, MARKERS.previousStatus, "none");
  return oldCurrent === currentStatus ? oldPrevious : oldCurrent;
}

function renderIssue(summary, issue = null) {
  const status = summary.overall_status;
  const previousStatus = normalizePreviousStatus(issue, status);
  const title = `[Security dashboard] ${summary.repository.full_name}`;
  const state = status === "pass" ? "closed" : "open";
  const labels = desiredManagedLabels(summary);
  const remediation = summary.remediation_categories.length > 0
    ? summary.remediation_categories.map((item) => `- ${item}`).join("\n")
    : "- No operator remediation is currently required.";
  const bodyWithoutDigest = [
    "<!-- segh-dashboard: v1 -->",
    `<!-- segh-repository-id: ${summary.repository.id} -->`,
    `<!-- segh-overall-status: ${status} -->`,
    `<!-- segh-previous-status: ${previousStatus} -->`,
    `<!-- segh-finding-fingerprint: ${summary.findings.fingerprint} -->`,
    "",
    `# Security dashboard: ${summary.repository.full_name}`,
    "",
    "## Current state",
    "",
    `- **Overall status:** ${status}`,
    `- **Previous status:** ${previousStatus}`,
    `- **Repository ID:** ${summary.repository.id}`,
    `- **Visibility:** ${summary.repository.visibility}`,
    `- **Default branch:** ${summary.repository.default_branch}`,
    `- **Scanned commit:** \`${summary.repository.commit_sha}\``,
    `- **Scan timestamp:** ${summary.scan.timestamp}`,
    `- **Workflow run:** ${summary.scan.workflow_url}`,
    `- **Private evidence artifact:** \`${summary.scan.evidence_artifact}\``,
    "",
    "## Scanner summary",
    "",
    "| Scanner | Status | Findings |",
    "| --- | --- | ---: |",
    renderScannerRows(summary.scanners),
    "",
    `**Total bounded finding count:** ${summary.findings.total}`,
    "",
    "## Selected OpenSSF Scorecard checks",
    "",
    renderScorecard(summary.scanners),
    "",
    "## Remediation categories",
    "",
    remediation,
    "",
    "Raw scanner output, file paths, source excerpts, secret values, and stack traces are intentionally excluded. Use the private workflow run and artifact for evidence review.",
    "",
  ].join("\n");
  const digest = sha256(canonicalJson({
    title,
    state,
    labels,
    previous_status: previousStatus,
    repository: summary.repository,
    overall_status: summary.overall_status,
    scanners: summary.scanners,
    findings: summary.findings,
    remediation_categories: summary.remediation_categories,
  }));
  const body = `${bodyWithoutDigest}<!-- segh-result-digest: ${digest} -->\n`;
  if (Buffer.byteLength(body, "utf8") > 48 * 1024) throw new Error("rendered issue body exceeds 48 KiB");
  return {title, state, labels, body, digest, status, previousStatus, fingerprint: summary.findings.fingerprint};
}

function renderRetiredIssue(issue) {
  const repositoryId = parseRepositoryId(issue.body);
  if (!repositoryId) throw new Error(`managed issue #${issue.number} lacks a valid repository id marker`);
  const oldCurrent = parseMarker(issue.body, MARKERS.overallStatus, "none");
  const oldFingerprint = parseMarker(issue.body, MARKERS.findingFingerprint, sha256("retired"));
  const fullName = issue.title.replace(/^\[Security dashboard\]\s*/, "").slice(0, 200) || `repository-${repositoryId}`;
  const summary = {
    schema_version: 1,
    repository: {id: repositoryId, full_name: fullName, visibility: "unknown", default_branch: "unknown", commit_sha: "0000000000000000000000000000000000000000"},
    scan: {timestamp: new Date().toISOString(), workflow_url: "Not scanned in the current selection.", evidence_artifact: "none"},
    overall_status: "retired",
    scanners: [{name: "selection", status: "skipped", findings: 0}],
    findings: {total: 0, categories: [], fingerprint: oldFingerprint},
    remediation_categories: ["Confirm that retirement from the GitHub App installation or scan selection was intentional."],
  };
  const previousStatus = oldCurrent === "retired" ? parseMarker(issue.body, MARKERS.previousStatus, "none") : oldCurrent;
  const title = `[Security dashboard] ${fullName}`;
  const state = "closed";
  const labels = [PRIMARY_LABELS.retired];
  const bodyWithoutDigest = [
    "<!-- segh-dashboard: v1 -->",
    `<!-- segh-repository-id: ${repositoryId} -->`,
    "<!-- segh-overall-status: retired -->",
    `<!-- segh-previous-status: ${previousStatus} -->`,
    `<!-- segh-finding-fingerprint: ${oldFingerprint} -->`,
    "",
    `# Security dashboard: ${fullName}`,
    "",
    "## Current state",
    "",
    "- **Overall status:** retired",
    `- **Previous status:** ${previousStatus}`,
    `- **Repository ID:** ${repositoryId}`,
    "",
    "This repository is no longer present in the active GitHub App installation selection. Confirm that retirement was intentional before deleting private evidence.",
    "",
  ].join("\n");
  const digest = sha256(canonicalJson({title, state, labels, previous_status: previousStatus, repository_id: repositoryId, status: "retired"}));
  return {title, state, labels, body: `${bodyWithoutDigest}<!-- segh-result-digest: ${digest} -->\n`, digest, status: "retired", previousStatus, fingerprint: oldFingerprint};
}

function issueMatchesDesired(issue, desired) {
  return issue.title === desired.title &&
    issue.state === desired.state &&
    parseMarker(issue.body, MARKERS.resultDigest, "none") === desired.digest &&
    parseMarker(issue.body, MARKERS.overallStatus, "none") === desired.status &&
    parseMarker(issue.body, MARKERS.findingFingerprint, "none") === desired.fingerprint &&
    JSON.stringify(managedLabels(issue.labels || [])) === JSON.stringify(desired.labels);
}

function historyChanged(issue, desired) {
  if (!issue) return false;
  const oldStatus = parseMarker(issue.body, MARKERS.overallStatus, "none");
  const oldFingerprint = parseMarker(issue.body, MARKERS.findingFingerprint, "none");
  return oldStatus !== desired.status || oldFingerprint !== desired.fingerprint;
}

function historyComment(issue, desired) {
  const oldStatus = parseMarker(issue.body, MARKERS.overallStatus, "none");
  const oldFingerprint = parseMarker(issue.body, MARKERS.findingFingerprint, "none");
  const lines = [
    "Security dashboard state changed.",
    "",
    `- Status: ${oldStatus} → ${desired.status}`,
  ];
  if (oldFingerprint !== desired.fingerprint) lines.push("- Finding fingerprint changed.");
  lines.push("- The issue body now represents the current bounded state; private evidence remains in the workflow artifact.");
  return lines.join("\n").slice(0, 1200);
}

async function ensureLabels(github, owner, repo) {
  const existing = await listBounded(github.rest.issues.listLabelsForRepo, {owner, repo}, 10);
  const names = new Set(existing.map((label) => label.name));
  for (const name of [...MANAGED_LABELS].sort()) {
    if (names.has(name)) continue;
    const definition = LABEL_DEFINITIONS[name];
    await requestWithRetry(() => github.rest.issues.createLabel({owner, repo, name, ...definition}));
  }
}

async function listManagedIssues(github, owner, repo) {
  const all = await listBounded(github.rest.issues.listForRepo, {owner, repo, state: "all"}, 10);
  return all.filter((issue) => !issue.pull_request && MARKERS.managed.test(String(issue.body || "")));
}

function indexManagedIssues(issues) {
  const byId = new Map();
  for (const issue of issues) {
    const id = parseRepositoryId(issue.body);
    if (!id) throw new Error(`managed issue #${issue.number} has no valid repository id marker`);
    const entries = byId.get(id) || [];
    entries.push(issue);
    byId.set(id, entries);
  }
  for (const [id, entries] of byId) {
    if (entries.length !== 1) throw new Error(`repository id ${id} has ${entries.length} managed dashboard issues`);
  }
  return byId;
}

async function applyDesired(github, owner, repo, issue, desired) {
  if (issue && issueMatchesDesired(issue, desired)) return {action: "unchanged", issue};

  const unmanaged = issue ? allLabelNames(issue.labels || []).filter((name) => !MANAGED_LABELS.has(name)) : [];
  const labels = [...new Set([...unmanaged, ...desired.labels])].sort();
  if (!issue) {
    const created = await requestWithRetry(() => github.rest.issues.create({owner, repo, title: desired.title, body: desired.body, labels}));
    if (desired.state === "closed") {
      const closed = await requestWithRetry(() => github.rest.issues.update({owner, repo, issue_number: created.data.number, state: "closed"}));
      return {action: "created", issue: closed.data};
    }
    return {action: "created", issue: created.data};
  }

  const addHistory = historyChanged(issue, desired);
  const updated = await requestWithRetry(() => github.rest.issues.update({
    owner,
    repo,
    issue_number: issue.number,
    title: desired.title,
    body: desired.body,
    state: desired.state,
    labels,
  }));
  if (addHistory) {
    await requestWithRetry(() => github.rest.issues.createComment({owner, repo, issue_number: issue.number, body: historyComment(issue, desired)}));
  }
  return {action: "updated", issue: updated.data};
}

async function publish({github, context, core, planPath, summariesPath, repositoryPrivate}) {
  if (repositoryPrivate !== true && repositoryPrivate !== "true") {
    throw new Error("dashboard publication requires a private control repository");
  }
  const owner = context.repo.owner;
  const repo = context.repo.repo;
  const targets = loadPlan(planPath);
  if (targets.some((target) => target.visibility !== "public") && repositoryPrivate !== true && repositoryPrivate !== "true") {
    throw new Error("private target results cannot be published to a public dashboard repository");
  }
  const summaries = loadSummaries(summariesPath, targets, context);
  const managed = await listManagedIssues(github, owner, repo);
  const issueById = indexManagedIssues(managed);
  await ensureLabels(github, owner, repo);
  const activeIds = new Set(targets.map((target) => target.id));
  const results = [];

  for (const target of targets) {
    const issue = issueById.get(target.id)?.[0] || null;
    const desired = renderIssue(summaries.get(target.id), issue);
    const result = await applyDesired(github, owner, repo, issue, desired);
    results.push({repository_id: target.id, action: result.action});
  }

  for (const [id, entries] of [...issueById.entries()].sort((a, b) => a[0] - b[0])) {
    if (activeIds.has(id)) continue;
    const issue = entries[0];
    const desired = renderRetiredIssue(issue);
    const result = await applyDesired(github, owner, repo, issue, desired);
    results.push({repository_id: id, action: result.action});
  }

  const counts = results.reduce((acc, result) => {
    acc[result.action] = (acc[result.action] || 0) + 1;
    return acc;
  }, {});
  core.info(`dashboard publication complete: ${JSON.stringify(counts)}`);
  return results;
}

module.exports = publish;
module.exports._internal = {
  MANAGED_LABELS,
  applyDesired,
  canonicalJson,
  desiredManagedLabels,
  historyChanged,
  indexManagedIssues,
  issueMatchesDesired,
  loadPlan,
  loadSummaries,
  parseRepositoryId,
  requestWithRetry,
  renderIssue,
  renderRetiredIssue,
  sha256,
  syntheticErrorSummary,
  validateSummary,
};
