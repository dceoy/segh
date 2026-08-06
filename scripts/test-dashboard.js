#!/usr/bin/env node

"use strict";

const {execFileSync} = require("node:child_process");
const path = require("node:path");

for (const file of ["core/test-dashboard.js", "test-dashboard-fingerprint.js", "test-dashboard-publisher.js"]) {
  execFileSync(process.execPath, [path.join(__dirname, file)], {stdio: "inherit"});
}
