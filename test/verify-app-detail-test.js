'use strict';

// describeResponse() lifts error text out of a remote endpoint's response and puts it into the
// /v1/oauth2/{app}/verify report. That is reflected content, so it has to be bounded.

const test = require('node:test');
const assert = require('node:assert').strict;

const { __test__ } = require('../lib/oauth/verify-app');
const registerRedisTeardown = require('./helpers/redis-teardown');

const { describeResponse, MAX_REMOTE_DETAIL_LENGTH } = __test__;

// verify-app pulls in lib/db transitively, whose Redis and BullMQ handles keep the event loop
// alive after the tests pass. See the helper for why this is a force-exit.
registerRedisTeardown();

const withResponse = response => ({ response });

test('describeResponse', async t => {
    await t.test('surfaces a Google API nested error message', () => {
        assert.strictEqual(describeResponse(withResponse({ error: { message: 'Permission denied' } })), 'Permission denied');
    });

    await t.test('joins the OAuth/STS error and description', () => {
        assert.strictEqual(describeResponse(withResponse({ error: 'invalid_grant', error_description: 'Bad audience' })), 'invalid_grant: Bad audience');
    });

    await t.test('reads through the tokenRequest envelope', () => {
        assert.strictEqual(describeResponse({ tokenRequest: { response: { error: 'invalid_request' } } }), 'invalid_request');
    });

    await t.test('returns null when there is nothing to describe', () => {
        for (let err of [null, undefined, {}, withResponse(null), withResponse({}), withResponse('a string')]) {
            assert.strictEqual(describeResponse(err), null);
        }
    });

    await t.test('bounds a long nested error message', () => {
        const detail = describeResponse(withResponse({ error: { message: 'x'.repeat(50000) } }));
        assert.ok(detail.length <= MAX_REMOTE_DETAIL_LENGTH + 3, `expected a bounded string, got ${detail.length}`);
        assert.ok(detail.endsWith('...'));
    });

    await t.test('bounds a long error_description', () => {
        // The shape that mattered: a remote token endpoint echoing an arbitrarily long body back
        // through error_description and into the API response.
        const detail = describeResponse(withResponse({ error: 'invalid_grant', error_description: 'y'.repeat(50000) }));
        assert.ok(detail.length <= MAX_REMOTE_DETAIL_LENGTH + 3);
        assert.ok(detail.endsWith('...'));
    });

    await t.test('leaves a short detail untouched', () => {
        const short = 'invalid_grant: Bad audience';
        assert.strictEqual(describeResponse(withResponse({ error: 'invalid_grant', error_description: 'Bad audience' })), short);
        assert.ok(!short.endsWith('...'));
    });

    await t.test('ignores non-string error fields rather than stringifying them', () => {
        assert.strictEqual(describeResponse(withResponse({ error: { code: 500 }, error_description: null })), null);
    });
});
