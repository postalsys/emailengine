'use strict';

// Covers lib/email-client/oauth-errors.js, the shared classification behind two behaviours on the
// OAuth2 connection path:
//
// 1. A token endpoint answering 429 or 5xx is rate limiting or broken, not rejecting credentials.
//    The shared fetch agent deliberately does not retry 5xx, so those arrive as ETokenRefresh and
//    used to be tagged authenticationFailed - parking a healthy account over a provider blip.
// 2. RFC 6750 `invalid_token` is the status that actually means the access token is stale or
//    revoked. It was not handled at all, so a genuinely stale token was never proactively cleared.

const test = require('node:test');
const assert = require('node:assert').strict;

const { isTransientTokenRefreshError, shouldInvalidateAccessToken } = require('../lib/email-client/oauth-errors');

function tokenError(statusCode) {
    return Object.assign(new Error('Token request failed'), { code: 'ETokenRefresh', statusCode });
}

test('isTransientTokenRefreshError', async t => {
    await t.test('treats 429 and 5xx from the token endpoint as transient', () => {
        // 500 and 599 are the range boundaries; the values between them take the same branch.
        for (let statusCode of [429, 500, 599]) {
            assert.strictEqual(isTransientTokenRefreshError(tokenError(statusCode)), true, `HTTP ${statusCode} must be transient`);
        }
    });

    await t.test('keeps other 4xx rejections as authentication failures', () => {
        // invalid_grant (revoked refresh token) surfaces as a 400 and is a genuine credential
        // problem - the transient carve-out must not swallow it.
        assert.strictEqual(isTransientTokenRefreshError(tokenError(400)), false);
    });

    await t.test('treats socket and DNS failures as transient', () => {
        // One errno and one undici code - enough to prove both shapes reach the shared set without
        // restating TRANSIENT_NETWORK_CODES, which would only assert the constant against a copy.
        for (let code of ['ENOTFOUND', 'UND_ERR_SOCKET']) {
            assert.strictEqual(isTransientTokenRefreshError(Object.assign(new Error('boom'), { code })), true, `${code} must be transient`);
        }
    });

    await t.test('does not widen on statusCode alone', () => {
        // Guards the carve-out: a 5xx without the ETokenRefresh code must not become transient.
        assert.strictEqual(isTransientTokenRefreshError(Object.assign(new Error('nope'), { code: 'ESOMETHINGELSE', statusCode: 503 })), false);
    });

    await t.test('an unrecognised or missing error is an auth failure', () => {
        assert.strictEqual(isTransientTokenRefreshError(new Error('no code')), false);
        assert.strictEqual(isTransientTokenRefreshError(undefined), false);
    });

    await t.test('an ETokenRefresh with no statusCode is an auth failure', () => {
        assert.strictEqual(isTransientTokenRefreshError(Object.assign(new Error('x'), { code: 'ETokenRefresh' })), false);
    });
});

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

    await t.test('a missing or empty payload does not invalidate', () => {
        assert.strictEqual(shouldInvalidateAccessToken(undefined), false);
        assert.strictEqual(shouldInvalidateAccessToken({}), false);
    });
});
