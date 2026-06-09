'use strict';

// Hermetic unit tests for lib/api-routes/route-helpers.js. Pure functions, no DB or network.

const test = require('node:test');
const assert = require('node:assert').strict;
const Boom = require('@hapi/boom');

const { handleError } = require('../lib/api-routes/route-helpers');

// Minimal request stub - handleError only uses request.logger.error
const fakeRequest = { logger: { error() {} } };

test('handleError status mapping', async t => {
    await t.test('preserves an explicit statusCode', () => {
        let err = new Error('bad input');
        err.statusCode = 400;
        err.code = 'UnsupportedSearchTerm';
        try {
            handleError(fakeRequest, err);
            assert.fail('should have thrown');
        } catch (boomErr) {
            assert.equal(boomErr.output.statusCode, 400);
            assert.equal(boomErr.output.payload.code, 'UnsupportedSearchTerm');
        }
    });

    await t.test('maps MissingServerExtension (no statusCode) to 422', () => {
        let err = new Error('Server does not support X-GM-EXT-1 extension required for label search');
        err.code = 'MissingServerExtension';
        try {
            handleError(fakeRequest, err);
            assert.fail('should have thrown');
        } catch (boomErr) {
            assert.equal(boomErr.output.statusCode, 422);
            assert.equal(boomErr.output.payload.code, 'MissingServerExtension');
            // 4xx errors keep the original message (unlike 5xx, which Boom masks)
            assert.match(boomErr.output.payload.message, /label search/);
        }
    });

    await t.test('defaults an unknown error to 500', () => {
        let err = new Error('boom');
        try {
            handleError(fakeRequest, err);
            assert.fail('should have thrown');
        } catch (boomErr) {
            assert.equal(boomErr.output.statusCode, 500);
        }
    });

    await t.test('passes Boom errors through unchanged', () => {
        let boom = Boom.notFound('nope');
        try {
            handleError(fakeRequest, boom);
            assert.fail('should have thrown');
        } catch (caught) {
            assert.equal(caught, boom);
            assert.equal(caught.output.statusCode, 404);
        }
    });
});
