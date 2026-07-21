'use strict';

// Covers lib/email-client/oauth-errors.js: RFC 6750 `invalid_token` is the status that actually
// means the access token is stale or revoked. It was not handled at all, so a genuinely stale token
// was never proactively cleared.

const test = require('node:test');
const assert = require('node:assert').strict;

const { shouldInvalidateAccessToken } = require('../lib/email-client/oauth-errors');

test('shouldInvalidateAccessToken', async t => {
    await t.test('invalid_token invalidates the cached access token', () => {
        // RFC 6750: the status that actually means expired, revoked or malformed.
        assert.strictEqual(shouldInvalidateAccessToken({ status: 'invalid_token' }), true);
    });

    await t.test('invalid_request still invalidates', () => {
        // Kept for compatibility - providers do send it for stale credentials in practice.
        assert.strictEqual(shouldInvalidateAccessToken({ status: 'invalid_request' }), true);
    });

    await t.test('an unrelated status does not invalidate', () => {
        assert.strictEqual(shouldInvalidateAccessToken({ status: 'insufficient_scope' }), false);
    });

    await t.test('a numeric XOAUTH2 status does not invalidate', () => {
        // Documents a known gap rather than desired behaviour: XOAUTH2 servers (Microsoft 365) put
        // the HTTP status here instead of a symbolic code, so stale tokens go uncleared there.
        assert.strictEqual(shouldInvalidateAccessToken({ status: '401', schemes: 'Bearer' }), false);
    });

    await t.test('a missing or empty payload does not invalidate', () => {
        assert.strictEqual(shouldInvalidateAccessToken(undefined), false);
        assert.strictEqual(shouldInvalidateAccessToken({}), false);
    });
});
