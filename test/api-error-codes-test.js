'use strict';

// lib/api-error-codes.js: a 404 from any API route carries `code: 'NotFound'`, whether or not the
// throw site set one. The exports, outbox, blocklist and account-log routes, and every lookup of an
// account that does not exist (lib/account.js throws a bare Boom 404), used to answer without one.

const test = require('node:test');
const assert = require('node:assert').strict;
const fs = require('node:fs');
const path = require('node:path');
const Boom = require('@hapi/boom');

const { addDefaultErrorCode, errorCodeExt } = require('../lib/api-error-codes');

test('addDefaultErrorCode', async t => {
    await t.test('a 404 without a code gets NotFound', () => {
        const payload = Boom.notFound('Export was not found').output.payload;
        assert.equal(addDefaultErrorCode(payload).code, 'NotFound');
        assert.equal(payload.message, 'Export was not found', 'the rest of the payload is untouched');
    });

    await t.test('a code set by the throw site is kept', () => {
        assert.equal(addDefaultErrorCode({ statusCode: 404, code: 'AccountNotFound' }).code, 'AccountNotFound');
    });

    await t.test('other statuses are left alone', () => {
        for (const statusCode of [400, 401, 403, 409, 500, 503]) {
            assert.ok(!('code' in addDefaultErrorCode({ statusCode })), String(statusCode));
        }
    });

    await t.test('tolerates a missing payload', () => {
        assert.equal(addDefaultErrorCode(null), null);
        assert.equal(addDefaultErrorCode(undefined), undefined);
    });
});

test('errorCodeExt fills in the code of an error response and leaves others alone', () => {
    const h = { continue: Symbol('continue') };
    const boom = { isBoom: true, output: { payload: { statusCode: 404, message: 'Not Found' } } };
    assert.equal(errorCodeExt({ response: boom }, h), h.continue);
    assert.equal(boom.output.payload.code, 'NotFound');

    const plain = { source: { ok: true } };
    assert.equal(errorCodeExt({ response: plain }, h), h.continue);
    assert.deepEqual(plain, { source: { ok: true } });
});

test('the API worker registers it ahead of the error response handler', () => {
    // workers/api.js boots a server on require, so the wiring is checked in its source: the step
    // has to run before preResponse copies the payload into the JSON error body
    const source = fs.readFileSync(path.join(__dirname, '..', 'workers', 'api.js'), 'utf8');
    const ext = source.indexOf("server.ext('onPreResponse', errorCodeExt);");
    const pre = source.indexOf("server.ext('onPreResponse', preResponse);");
    assert.ok(ext > 0 && pre > ext, 'errorCodeExt is registered before preResponse');
});
