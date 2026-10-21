'use strict';

// lib/api-error-codes.js: a 404 from any API route carries `code: 'NotFound'`, whether or not the
// throw site set one. The exports, outbox, blocklist and account-log routes, and every lookup of an
// account that does not exist (lib/account.js throws a bare Boom 404), used to answer without one.

const test = require('node:test');
const assert = require('node:assert').strict;
const fs = require('node:fs');
const path = require('node:path');
const Boom = require('@hapi/boom');

const { addDefaultErrorCode } = require('../lib/api-error-codes');

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

test('the API worker fills it in where the JSON error body is built', () => {
    // workers/api.js boots a server on require, so the wiring is checked in its source: the JSON
    // error branch of the onPreResponse handler has to pass its payload through the helper before
    // building the response
    const source = fs.readFileSync(path.join(__dirname, '..', 'workers', 'api.js'), 'utf8');
    const branch = source.indexOf('if (request.errorInfo && wantsJsonError) {');
    assert.ok(branch > 0, 'the JSON error branch exists');
    const respond = source.indexOf('h.response(request.errorInfo)', branch);
    const call = source.indexOf('addDefaultErrorCode(request.errorInfo)', branch);
    assert.ok(call > branch && call < respond, 'addDefaultErrorCode() runs before the JSON error response is built');
});
