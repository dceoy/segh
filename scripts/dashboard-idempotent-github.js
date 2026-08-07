"use strict";

const crypto = require("node:crypto");
const {list, managedDashboard, repositoryId, retryable} = require("./dashboard-github-common.js");
const {idempotentCreate} = require("./dashboard-idempotent-issue.js");
const {idempotentComment} = require("./dashboard-idempotent-comment.js");

const RENDERER_VERSION = 1;
const OVERALL_STATUS = /<!-- segh-overall-status: (pass|findings|incomplete|error|retired) -->/;
const FINDING_FINGERPRINT = /<!-- segh-finding-fingerprint: (sha256:[0-9a-f]{64}) -->/;
const RESULT_DIGEST = /<!-- segh-result-digest: (sha256:[0-9a-f]{64}) -->/;
const RENDERER_VERSION_MARKER = /<!-- segh-renderer-version: ([0-9]+) -->/;
const RENDERER_DIGEST = /<!-- segh-renderer-digest: (sha256:[0-9a-f]{64}) -->/;
const RENDERER_MARKERS = /<!-- segh-renderer-(?:version|digest): [^\n]+ -->\n?/g;
const BODY_INTEGRITY = /<!-- segh-body-integrity: sha256:([0-9a-f]{64}) -->\n?$/;
const MANAGED_LABELS = new Set([
  "scan:pass", "scan:findings", "scan:incomplete", "scan:error", "scan:retired",
  "finding:scorecard", "finding:actions", "finding:shell", "finding:vulnerability",
  "finding:secret", "finding:misconfiguration",
]);

function marker(body, pattern) { return String(body || "").match(pattern)?.[1] || "none"; }
function sha256(value) { return crypto.createHash("sha256").update(value).digest("hex"); }
function withoutBodyIntegrity(body) { return String(body || "").replace(BODY_INTEGRITY, ""); }
function withoutRendererContract(body) { return String(body || "").replace(RENDERER_MARKERS, ""); }
function expectedRendererDigest(body) {
  const resultDigest = marker(body, RESULT_DIGEST);
  return resultDigest === "none" ? null : `sha256:${sha256(`renderer:${RENDERER_VERSION}\0${resultDigest}`)}`;
}
function withRendererContract(body) {
  const canonical = withoutRendererContract(withoutBodyIntegrity(body));
  const resultDigest = marker(canonical, RESULT_DIGEST);
  if (resultDigest === "none") throw new Error("managed dashboard body lacks a result digest");
  const contract = `<!-- segh-renderer-version: ${RENDERER_VERSION} -->\n<!-- segh-renderer-digest: ${expectedRendererDigest(canonical)} -->\n`;
  return canonical.replace(RESULT_DIGEST, `${contract}$&`);
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
function hasCurrentRendererContract(body) {
  return Number.parseInt(marker(body, RENDERER_VERSION_MARKER), 10) === RENDERER_VERSION &&
    marker(body, RENDERER_DIGEST) === expectedRendererDigest(body);
}
function invalidateUntrustedDigest(issue) {
  if (!managedDashboard(issue.body) || (hasValidBodyIntegrity(issue.body) && hasCurrentRendererContract(issue.body))) return issue;
  return {...issue, body: String(issue.body || "").replace(RESULT_DIGEST, "<!-- segh-result-digest: invalid -->")};
}
function canonicalManagedLabel(name) { const canonical=String(name||"").toLowerCase(); return MANAGED_LABELS.has(canonical)?canonical:null; }
function normalizeManagedLabels(issue) {
  if (!Array.isArray(issue?.labels)) return issue;
  return {...issue, labels: issue.labels.map((label)=>{const name=typeof label==="string"?label:label?.name; const canonical=canonicalManagedLabel(name); if(!canonical)return label; return typeof label==="string"?canonical:{...label,name:canonical};})};
}
function withManagedBodyIntegrity(params) {
  if (typeof params.body !== "string" || !managedDashboard(params.body)) return params;
  return {...params, body: withBodyIntegrity(withRendererContract(params.body))};
}
function disableOctokitRetries(github) {
  const source=github.rest.issues; const issues={};
  for(const [name,value] of Object.entries(source)){issues[name]=typeof value==="function"?(params={})=>value.call(source,{...params,request:{...(params.request||{}),retries:0}}):value;}
  const listForRepo=issues.listForRepo;
  issues.listForRepo=async(params)=>{const response=await listForRepo(params); if(!Array.isArray(response?.data))return response; return {...response,data:response.data.map(normalizeManagedLabels).map(invalidateUntrustedDigest)};};
  return {...github,rest:{...github.rest,issues}};
}
function historyChanged(before,after){return managedDashboard(after)&&(marker(before,OVERALL_STATUS)!==marker(after,OVERALL_STATUS)||marker(before,FINDING_FINGERPRINT)!==marker(after,FINDING_FINGERPRINT));}
function transitionIdentity(before,after){
  const integrity=String(before||"").match(BODY_INTEGRITY)?.[1];
  const source=integrity?`source-integrity:sha256:${integrity}`:`source-body:sha256:${sha256(String(before||""))}`;
  return [
    source,
    `desired-result:${marker(after,RESULT_DIGEST)}`,
    `desired-status:${marker(after,OVERALL_STATUS)}`,
    `desired-fingerprint:${marker(after,FINDING_FINGERPRINT)}`,
  ].join("\n");
}
function issueKey(params){return `${params.owner}/${params.repo}#${params.issue_number}`;}
async function findIssue(github,params){const issues=await list(github.rest.issues.listForRepo,{owner:params.owner,repo:params.repo,state:"all"}); return issues.find((issue)=>!issue.pull_request&&issue.number===params.issue_number)||null;}
function sameLabel(left,right){return String(left||"").toLowerCase()===String(right||"").toLowerCase();}
async function findLabel(github,params){const labels=await list(github.rest.issues.listLabelsForRepo,{owner:params.owner,repo:params.repo}); return labels.find((label)=>sameLabel(label.name,params.name))||null;}
function labelAlreadyExists(error){const status=error?.status||error?.response?.status; if(status!==422)return false; const errors=error?.response?.data?.errors; return /already.?exists/i.test(String(error?.message||""))||(Array.isArray(errors)&&errors.some((item)=>item?.code==="already_exists"||/already.?exists/i.test(String(item?.message||""))));}
function idempotentLabel(github){const create=github.rest.issues.createLabel.bind(github.rest.issues); return async(params)=>{const existing=await findLabel(github,params); if(existing)return{data:existing}; try{return await create(params);}catch(error){if(!retryable(error)&&!labelAlreadyExists(error))throw error; const reconciled=await findLabel(github,params); if(reconciled)return{data:reconciled}; throw error;}};}
function idempotentGitHub(github) {
  const hardened=disableOctokitRetries(github); const issues={...hardened.rest.issues}; const create=hardened.rest.issues.create; const update=hardened.rest.issues.update;
  hardened.rest.issues.create=(params)=>create(withManagedBodyIntegrity(params));
  hardened.rest.issues.update=(params)=>update(withManagedBodyIntegrity(params));
  const persistUpdate=hardened.rest.issues.update; const createComment=idempotentComment(hardened); const pendingUpdates=new Map();
  issues.createLabel=idempotentLabel(hardened); issues.create=idempotentCreate(hardened);
  issues.update=async(params)=>{if(typeof params.body!=="string"||!managedDashboard(params.body))return persistUpdate(params); const current=await findIssue(hardened,params); if(!current||!historyChanged(current.body,params.body))return persistUpdate(params); pendingUpdates.set(issueKey(params),{params,eventIdentity:transitionIdentity(current.body,params.body)}); return{data:current};};
  issues.createComment=async(params)=>{const key=issueKey(params); const pending=pendingUpdates.get(key); const result=await createComment({...params,event_identity:pending?.eventIdentity||""}); if(pending){await persistUpdate(pending.params); pendingUpdates.delete(key);} return result;};
  return {...hardened,rest:{...hardened.rest,issues}};
}
module.exports={RENDERER_VERSION,hasCurrentRendererContract,hasValidBodyIntegrity,idempotentGitHub,repositoryId,withBodyIntegrity,withRendererContract};
