"use strict";

const crypto = require("node:crypto");
const {list, retryable} = require("./dashboard-github-common.js");

async function hasComment(github, params, marker) {
  if (typeof github.rest.issues.listComments !== "function") return false;
  return (await list(github.rest.issues.listComments, params))
    .some((comment) => String(comment.body || "").includes(marker));
}

function idempotentComment(github) {
  const create = github.rest.issues.createComment.bind(github.rest.issues);
  return async (params) => {
    const {event_identity: eventIdentity = "", ...request} = params;
    const hash = crypto.createHash("sha256")
      .update(`${request.issue_number}\n${eventIdentity}\n${request.body}`)
      .digest("hex");
    const marker = `<!-- segh-history-event: sha256:${hash} -->`;
    const query = {owner: request.owner, repo: request.repo, issue_number: request.issue_number};
    const body = `${marker}\n${request.body}`;
    if (await hasComment(github, query, marker)) return {data: {body}};
    try {
      return await create({...request, body});
    } catch (error) {
      if (!retryable(error)) throw error;
      if (await hasComment(github, query, marker)) return {data: {body}};
      throw error;
    }
  };
}

module.exports = {idempotentComment};
