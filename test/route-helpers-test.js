'use strict';

// Hermetic unit tests for lib/api-routes/route-helpers.js. Pure functions, no DB or network.

const test = require('node:test');
const assert = require('node:assert').strict;
const Boom = require('@hapi/boom');

const { handleError } = require('../lib/api-routes/route-helpers');

// Minimal request stub - handleError logs at warn (4xx) or error (5xx)
const fakeRequest = { logger: { warn() {}, error() {} } };

// Request stub that records the level handleError logged at, so tests can assert severity
function recordingRequest() {
    const logged = [];
    return {
        logged,
        logger: {
            warn(data) {
                logged.push({ level: 'warn', data });
            },
            error(data) {
                logged.push({ level: 'error', data });
            }
        }
    };
}

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

test('handleError log level', async t => {
    await t.test('logs an expected 4xx (Boom 404 existence probe) at warn', () => {
        let request = recordingRequest();
        try {
            handleError(request, Boom.notFound('Account record was not found for requested ID'));
            assert.fail('should have thrown');
        } catch {
            // expected
        }
        assert.equal(request.logged.length, 1);
        assert.equal(request.logged[0].level, 'warn');
        assert.equal(request.logged[0].data.statusCode, 404);
    });

    await t.test('logs a plain 4xx (explicit statusCode) at warn', () => {
        let request = recordingRequest();
        let err = new Error('bad input');
        err.statusCode = 400;
        try {
            handleError(request, err);
            assert.fail('should have thrown');
        } catch {
            // expected
        }
        assert.equal(request.logged[0].level, 'warn');
        assert.equal(request.logged[0].data.statusCode, 400);
    });

    await t.test('logs a plain 5xx server fault at error', () => {
        let request = recordingRequest();
        try {
            handleError(request, new Error('boom'));
            assert.fail('should have thrown');
        } catch {
            // expected
        }
        assert.equal(request.logged[0].level, 'error');
        assert.equal(request.logged[0].data.statusCode, 500);
    });

    await t.test('logs a Boom 5xx server fault at error', () => {
        let request = recordingRequest();
        try {
            handleError(request, Boom.badImplementation('upstream blew up'));
            assert.fail('should have thrown');
        } catch {
            // expected
        }
        assert.equal(request.logged[0].level, 'error');
        assert.equal(request.logged[0].data.statusCode, 500);
    });
});
