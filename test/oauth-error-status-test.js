'use strict';

const test = require('node:test');
const assert = require('node:assert').strict;

const { resolveOAuthErrorStatus } = require('../lib/tools');

test('resolveOAuthErrorStatus tests', async t => {
    await t.test('returns numeric error code when it is a valid HTTP status', async () => {
        assert.strictEqual(resolveOAuthErrorStatus({ code: 400 }, {}), 400);
        assert.strictEqual(resolveOAuthErrorStatus({ code: 403 }, {}), 403);
        assert.strictEqual(resolveOAuthErrorStatus({ code: 404 }, {}), 404);
        assert.strictEqual(resolveOAuthErrorStatus({ code: 429 }, {}), 429);
        assert.strictEqual(resolveOAuthErrorStatus({ code: 500 }, {}), 500);
        assert.strictEqual(resolveOAuthErrorStatus({ code: 503 }, {}), 503);
    });

    await t.test('falls back to err.statusCode when error code is a string', async () => {
        let err = { statusCode: 429 };
        assert.strictEqual(resolveOAuthErrorStatus({ code: 'TooManyPendingRequests' }, err), 429);
        assert.strictEqual(resolveOAuthErrorStatus({ code: 'TooManyRequests' }, err), 429);

        err = { statusCode: 400 };
        assert.strictEqual(resolveOAuthErrorStatus({ code: 'BadRequest' }, err), 400);
    });

    await t.test('falls back to err.oauthRequest.status when err.statusCode is missing', async () => {
        let err = { oauthRequest: { status: 429 } };
        assert.strictEqual(resolveOAuthErrorStatus({ code: 'TooManyPendingRequests' }, err), 429);

        err = { oauthRequest: { status: 503 } };
        assert.strictEqual(resolveOAuthErrorStatus({ code: 'ServiceUnavailable' }, err), 503);
    });

    await t.test('returns 500 when no fallback status is available', async () => {
        assert.strictEqual(resolveOAuthErrorStatus({ code: 'UnknownError' }, {}), 500);
        assert.strictEqual(resolveOAuthErrorStatus({ code: 'TooManyPendingRequests' }, {}), 500);
    });

    await t.test('rejects numeric codes below 400', async () => {
        let err = { statusCode: 429 };
        assert.strictEqual(resolveOAuthErrorStatus({ code: 200 }, err), 429);
        assert.strictEqual(resolveOAuthErrorStatus({ code: 301 }, err), 429);
        assert.strictEqual(resolveOAuthErrorStatus({ code: 0 }, err), 429);
    });

    await t.test('handles undefined and null error codes', async () => {
        let err = { statusCode: 502 };
        assert.strictEqual(resolveOAuthErrorStatus({ code: undefined }, err), 502);
        assert.strictEqual(resolveOAuthErrorStatus({ code: null }, err), 502);
        assert.strictEqual(resolveOAuthErrorStatus({}, err), 502);
    });

    await t.test('handles missing err parameter', async () => {
        assert.strictEqual(resolveOAuthErrorStatus({ code: 403 }, null), 403);
        assert.strictEqual(resolveOAuthErrorStatus({ code: 'BadRequest' }, null), 500);
        assert.strictEqual(resolveOAuthErrorStatus({ code: 'BadRequest' }, undefined), 500);
    });
});
