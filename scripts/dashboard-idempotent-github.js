"use strict";

const {repositoryId} = require("./dashboard-github-common.js");
const {idempotentCreate} = require("./dashboard-idempotent-issue.js");
const {idempotentComment} = require("./dashboard-idempotent-comment.js");

function idempotentGitHub(github) {
  const issues = {...github.rest.issues};
  issues.create = idempotentCreate(github);
  issues.createComment = idempotentComment(github);
  return {...github, rest: {...github.rest, issues}};
}

module.exports = {idempotentGitHub, repositoryId};
