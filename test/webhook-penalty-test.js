'use strict';

// The per-target delivery penalty of the webhook worker (lib/webhook-penalty.js): which failures
// earn one, for how long, and which key it lives under.

const test = require('node:test');
const assert = require('node:assert').strict;

const { penaltyKey, penaltyFor, MAX_PENALTY_MS } = require('../lib/webhook-penalty');
const { REDIS_PREFIX } = require('../lib/consts');

test('penaltyKey() identifies a target by its origin', () => {
    const key = penaltyKey('https://hooks.example.com/path/one?x=1');
    assert.ok(key.startsWith(`${REDIS_PREFIX}webhook:penalty:`));
    // the same receiver, whatever path, credentials or query the URL carries
    assert.equal(penaltyKey('https://user:pass@hooks.example.com/other'), key);
    assert.equal(penaltyKey('https://hooks.example.com:443/'), key);
    // another port, scheme or host is another target
    assert.notEqual(penaltyKey('http://hooks.example.com/path/one'), key);
    assert.notEqual(penaltyKey('https://hooks.example.com:8443/path/one'), key);
    assert.notEqual(penaltyKey('https://other.example.com/path/one'), key);
    // the key never carries the credentials or the host in the clear
    assert.doesNotMatch(key, /example\.com|pass/);
    // a URL that does not parse gets no key, and so no penalty
    assert.equal(penaltyKey('not a url'), null);
    assert.equal(penaltyKey(''), null);
});

test('penaltyFor() penalises the failures that hold the queue', () => {
    const timeout = 30 * 1000;
    // a timed-out attempt and a connection that was never made: twice the attempt cap
    assert.equal(penaltyFor(Object.assign(new Error('timeout'), { code: 'ETIMEDOUT' }), timeout), 60 * 1000);
    assert.equal(penaltyFor(Object.assign(new Error('refused'), { code: 'ECONNREFUSED' }), timeout), 60 * 1000);
    assert.equal(penaltyFor(Object.assign(new Error('fetch failed'), { cause: { code: 'ENOTFOUND' } }), timeout), 60 * 1000);
    // capped, whatever the attempt cap is set to
    assert.equal(penaltyFor(Object.assign(new Error('timeout'), { code: 'ETIMEDOUT' }), 60 * 60 * 1000), MAX_PENALTY_MS);
    // and never zero for a penalised failure
    assert.ok(penaltyFor(Object.assign(new Error('timeout'), { code: 'ETIMEDOUT' }), 0) >= 1000);

    // a receiver that answered, with any status, is not holding the queue; the retry schedule
    // spaces those out already. Nor is a refusal that fails the job for good
    assert.equal(penaltyFor(Object.assign(new Error('HTTP 503'), { statusCode: 503 }), timeout), 0);
    assert.equal(penaltyFor(Object.assign(new Error('blocked'), { code: 'EEGRESSBLOCKED' }), timeout), 0);
    assert.equal(penaltyFor(Object.assign(new Error('redirect'), { code: 'EREDIRECTNOTFOLLOWED' }), timeout), 0);
    assert.equal(penaltyFor(new Error('plain'), timeout), 0);
    assert.equal(penaltyFor(null, timeout), 0);
});
