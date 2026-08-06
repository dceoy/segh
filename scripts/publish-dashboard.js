"use strict";

const fs = require("node:fs");
const core = require("./core/publish-dashboard.js");
const {hardenedSummaryCopy, completeScannerSet} = require("./dashboard-summary-contract.js");
const {idempotentGitHub, repositoryId} = require("./dashboard-idempotent-github.js");

async function publish(options) {
  const summariesPath = hardenedSummaryCopy(options.summariesPath);
  try {
    return await core({...options, github: idempotentGitHub(options.github), summariesPath});
  } finally {
    fs.rmSync(summariesPath, {recursive: true, force: true});
  }
}

module.exports = publish;
module.exports._internal = {...core._internal, completeScannerSet, idempotentGitHub, repositoryId};
