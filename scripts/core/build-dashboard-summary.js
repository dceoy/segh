#!/usr/bin/env node

"use strict";

// Keep one normalization contract. Core tests import the production implementation
// through this shim so scanner parsing and policy semantics cannot drift.
module.exports = require("../build-dashboard-summary.js");
