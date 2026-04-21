#!/usr/bin/env node
'use strict';

// Standalone smoke test for a Gmail service-account's ability to mint an
// OAuth2 access token via domain-wide delegation (DWD). Useful for catching
// stale keys or revoked DWD before running the full integration suite.
//
// Reads these env vars (typically from .env):
//   GMAIL_SERVICE_POSTALSYS_CLIENT        - numeric service account unique ID
//   GMAIL_SERVICE_POSTALSYS_KEY           - PEM private key (\n-escaped)
//   GMAIL_SERVICE_POSTALSYS_ACCOUNT_EMAIL - impersonation target (e.g. testuser@postalsys.com)

require('dotenv').config({ quiet: true });

const { GmailOauth } = require('../lib/oauth/gmail');

const serviceClient = process.env.GMAIL_SERVICE_POSTALSYS_CLIENT;
const serviceKey = process.env.GMAIL_SERVICE_POSTALSYS_KEY;
const user = process.env.GMAIL_SERVICE_POSTALSYS_ACCOUNT_EMAIL;

if (!serviceClient || !serviceKey || !user) {
    console.error('Missing env vars. Need GMAIL_SERVICE_POSTALSYS_{CLIENT,KEY,ACCOUNT_EMAIL}.');
    process.exit(2);
}

const oauth = new GmailOauth({
    serviceClient,
    serviceKey,
    scopes: ['https://mail.google.com/'],
    setFlag: async () => {}
});

(async () => {
    try {
        const result = await oauth.refreshToken({ user });
        console.log(`OK - minted token for ${user} (expires_in=${result.expires_in}s, scope="${result.scope || '(unspecified)'}")`);
    } catch (err) {
        console.error(`FAIL - ${err.message}`);
        if (err.tokenRequest && err.tokenRequest.response) {
            console.error('Google response:', JSON.stringify(err.tokenRequest.response, null, 2));
        }
        process.exit(1);
    }
})();
