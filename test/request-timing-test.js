'use strict';

// The duration the api_call_duration_seconds histogram observes, read off Hapi's request.info.

const test = require('node:test');
const assert = require('node:assert').strict;

const { apiCallDuration } = require('../lib/request-timing');

test('apiCallDuration()', async t => {
    await t.test('measures from receiving the request to completing the response, in seconds', () => {
        assert.equal(apiCallDuration({ received: 1000, responded: 1200, completed: 1250 }), 0.25);
    });

    await t.test('falls back to the response time when the request never completed', () => {
        // a client that hung up before the response was fully written
        assert.equal(apiCallDuration({ received: 1000, responded: 1400, completed: 0 }), 0.4);
    });

    await t.test('reports nothing it cannot measure', () => {
        assert.equal(apiCallDuration(null), null);
        assert.equal(apiCallDuration({}), null);
        assert.equal(apiCallDuration({ received: 1000 }), null);
        assert.equal(apiCallDuration({ received: 0, completed: 1000 }), null);
        // a clock step backwards must not become a negative observation, which prom-client refuses
        assert.equal(apiCallDuration({ received: 2000, completed: 1000 }), null);
    });

    await t.test('a request answered within the same millisecond is a zero observation', () => {
        assert.equal(apiCallDuration({ received: 1000, completed: 1000 }), 0);
    });
});
