'use strict';

// An account id may contain ":", and the per-account keys are `iam:<account>:<suffix>`, so the
// glob of one account also matches the keys of an account whose id begins with it and a colon.
// lib/account/own-account-key.js tells the two apart by the suffix vocabulary, and
// redisScanDelete() applies it as a filter so a delete or a flush of one account never takes
// another tenant's index with it.

const test = require('node:test');
const assert = require('node:assert').strict;
const crypto = require('crypto');

const { isOwnAccountKey, ownAccountKeyFilter } = require('../lib/account/own-account-key');
const redisScanDelete = require('../lib/redis-scan-delete');
const { redis } = require('../lib/db');
const registerRedisTeardown = require('./helpers/redis-teardown');

const NS = `oak-test:${crypto.randomBytes(8).toString('hex')}:`;
const logger = { trace() {}, debug() {}, info() {}, warn() {}, error() {} };

registerRedisTeardown(redis, async () => {
    const leftover = await redis.keys(`${NS}*`);
    if (leftover.length) {
        await redis.del(...leftover);
    }
});

test('isOwnAccountKey() admits the shapes the account writes and nothing else', () => {
    const own = ['g', 'announced-in', 'h:1a2b3c', 'l:z9', 'n:0'].map(suffix => `pfx:iam:tenant:${suffix}`);
    for (const key of own) {
        assert.equal(isOwnAccountKey('pfx:', 'tenant', key), true, key);
    }

    // the keys of an account whose id begins with this one and a colon, which the glob matches too
    const other = ['g', 'announced-in', 'h:1a2b3c', 'l:z9'].map(suffix => `pfx:iam:tenant:x:${suffix}`);
    for (const key of other) {
        assert.equal(isOwnAccountKey('pfx:', 'tenant', key), false, key);
    }
    // and the id being the suffix of another account's key does not make it this account's
    assert.equal(isOwnAccountKey('pfx:', 'tenant', 'pfx:iam:other:tenant:g'), false);
    assert.equal(isOwnAccountKey('pfx:', 'tenant', 'pfx:iam:tenant:g:g'), false);
    assert.equal(isOwnAccountKey('pfx:', 'tenant', 'pfx:iam:tenant:'), false);
    assert.equal(isOwnAccountKey('pfx:', 'tenant', null), false);

    // an account id carrying a colon itself is matched whole
    assert.equal(isOwnAccountKey('pfx:', 'tenant:x', 'pfx:iam:tenant:x:g'), true);
    assert.equal(isOwnAccountKey('pfx:', 'tenant:x', 'pfx:iam:tenant:g'), false);

    // the predicate a scan is filtered with is the same rule
    const mine = ownAccountKeyFilter('pfx:', 'tenant');
    assert.deepEqual(['pfx:iam:tenant:g', 'pfx:iam:tenant:x:g', 'pfx:iam:tenant:l:z9', 'pfx:iam:other:g'].filter(mine), [
        'pfx:iam:tenant:g',
        'pfx:iam:tenant:l:z9'
    ]);
});

test('redisScanDelete() leaves the keys its filter refuses', async () => {
    const keys = {
        own: [`${NS}iam:tenant:g`, `${NS}iam:tenant:announced-in`, `${NS}iam:tenant:h:1a2b`],
        other: [`${NS}iam:tenant:x:g`, `${NS}iam:tenant:x:h:1a2b`, `${NS}iam:tenant:x:announced-in`]
    };
    const pipeline = redis.pipeline();
    for (const key of keys.own.concat(keys.other)) {
        pipeline.set(key, '1');
    }
    await pipeline.exec();

    const removed = await redisScanDelete(redis, logger, `${NS}iam:tenant:*`, key => isOwnAccountKey(NS, 'tenant', key));
    assert.equal(removed, keys.own.length);

    for (const key of keys.own) {
        assert.equal(await redis.exists(key), 0, `${key} is removed`);
    }
    for (const key of keys.other) {
        assert.equal(await redis.exists(key), 1, `${key} belongs to another account and stays`);
    }

    // without a filter the glob decides, as before
    assert.equal(await redisScanDelete(redis, logger, `${NS}iam:tenant:x:*`), keys.other.length);
});
