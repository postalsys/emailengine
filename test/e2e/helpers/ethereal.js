'use strict';

// Shared helpers for the EmailEngine happy-path e2e suite (test/e2e). The implementations live in the
// cross-tier module test/helpers/ethereal.js; this file only re-exports them under the names the specs
// use. waitForCondition's own defaults (interval 1000ms, timeout 90000ms) already match the e2e tier, so
// waitFor is a direct alias - no wrapper needed. (The integration tier's helpers.js genuinely overrides
// these with testConfig values, so that one keeps its wrapper.)

const { createUsableTestAccount, waitForCondition, etherealAccountPayload } = require('../../helpers/ethereal');

module.exports = { createUsableTestAccount, waitFor: waitForCondition, etherealAccountPayload };
