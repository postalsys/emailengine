'use strict';

// Shared helpers for the live-server integration tier (test/integration/*-test.js). Kept in one
// place so the tracking / unsubscribe-events specs do not each re-declare them. api-test.js and
// sendonly-test.js predate this module and keep their own inline copies on purpose (they run as
// standalone files and are left untouched). The Ethereal/polling implementations live in the
// cross-tier module test/helpers/ethereal.js (shared with test/e2e); this wrapper only bakes in
// the integration-tier polling defaults.

const crypto = require('node:crypto');
const testConfig = require('./test-config');
const { createUsableTestAccount, waitForCondition: waitForConditionBase, etherealAccountPayload } = require('../helpers/ethereal');

// The prepared serviceSecret from config/test.toml. Tracking / unsubscribe URLs are signed with an
// HMAC-SHA256 of the JSON payload keyed by this secret, so tests can forge valid signed blobs
// without a lib/db handle (same approach as tracking-signature-test.js).
const SERVICE_SECRET = 'a cat';

// The prepared "*"-scope access token from config/test.toml - authenticates REST API calls that
// verify/clean up accounts the integration tests create.
const ACCESS_TOKEN = '2aa97ad0456d6624a55d30780aa2ff61bfb7edc6fa00935b40814b271e718660';

// Poll `checkFn` until it returns a truthy value (then return it) or the timeout elapses.
async function waitForCondition(checkFn, options = {}) {
    const { interval = testConfig.POLL_INTERVAL, timeout = testConfig.DEFAULT_TIMEOUT, message } = options;
    return waitForConditionBase(checkFn, { interval, timeout, message });
}

// Sign a payload object the way EmailEngine signs tracking / unsubscribe blobs: base64url(JSON) as
// `data` and base64url(HMAC-SHA256(JSON)) as `sig`. Mirrors lib/tools.js getSignedFormDataSync.
function signBlob(obj) {
    const data = Buffer.from(JSON.stringify(obj));
    const sig = crypto.createHmac('sha256', SERVICE_SECRET).update(data).digest('base64url');
    return { data: data.toString('base64url'), sig };
}

// Find the crumb (CSRF token) value in a response's set-cookie headers, so a scripted POST can pass
// the crumb plugin the same way a browser would.
function extractCrumb(setCookie) {
    for (const cookie of setCookie || []) {
        const match = /(?:^|;\s*)crumb=([^;]+)/.exec(cookie);
        if (match) {
            return decodeURIComponent(match[1]);
        }
    }
    return null;
}

module.exports = { createUsableTestAccount, waitForCondition, etherealAccountPayload, signBlob, extractCrumb, SERVICE_SECRET, ACCESS_TOKEN };
