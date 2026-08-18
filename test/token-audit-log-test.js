'use strict';

// Tests for the per-token audit trail (lib/token-audit-log.js).
//
// Needs Redis, so it force-exits like the rest of the suite: requiring lib/db opens a Redis client
// and a BullMQ connection, and the unit runner has no --test-force-exit.

const test = require('node:test');
const assert = require('node:assert').strict;

const auditLog = require('../lib/token-audit-log');
const tokens = require('../lib/tokens');
const settings = require('../lib/settings');
const { redis } = require('../lib/db');
const registerRedisTeardown = require('./helpers/redis-teardown');
const { REDIS_PREFIX } = require('../lib/consts');

const TOKEN_ID = 'f'.repeat(64);
const logKey = `${REDIS_PREFIX}tokens:log:${TOKEN_ID}`;

let prevSetting;
const provisioned = [];

// record() is deliberately fire-and-forget, so a test has to wait for the write rather than await
// the call. Polling the key beats a fixed sleep: it fails fast when the write never happens.
async function waitForEntries(count, timeoutMs = 2000) {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
        const len = await redis.llen(logKey);
        if (len >= count) {
            return len;
        }
        if (Date.now() > deadline) {
            return len;
        }
        await new Promise(resolve => setTimeout(resolve, 20));
    }
}

const entry = (overrides = {}) =>
    Object.assign(
        {
            tokenId: TOKEN_ID,
            ip: '127.0.0.1',
            method: 'get',
            path: '/v1/account/{account}/messages',
            action: 'read',
            group: 'message',
            account: 'acct',
            status: 'allowed'
        },
        overrides
    );

test.before(async () => {
    prevSetting = await settings.get('tokenAuditLog');
});

registerRedisTeardown(redis, async () => {
    await redis.del(logKey);
    for (const token of provisioned) {
        try {
            await tokens.delete(token);
        } catch (err) {
            // ignore
        }
    }
    try {
        await settings.set('tokenAuditLog', prevSetting === null ? false : prevSetting);
    } catch (err) {
        // ignore
    }
});

test('token audit log', async t => {
    await t.test('writes nothing while the setting is off', async () => {
        // Off by default is the whole reason the setting exists: this runs on the hot path of every
        // authenticated request, and most instances will never read the result.
        await settings.set('tokenAuditLog', false);
        auditLog.resetFlagCache();
        await redis.del(logKey);

        auditLog.record(entry());
        assert.equal(await waitForEntries(1, 300), 0, 'an entry was written with the setting off');
    });

    await t.test('records a request once enabled', async () => {
        await settings.set('tokenAuditLog', true);
        auditLog.resetFlagCache();
        await redis.del(logKey);

        auditLog.record(entry());
        assert.equal(await waitForEntries(1), 1);

        const { total, entries } = await auditLog.list(TOKEN_ID);
        assert.equal(total, 1);
        assert.equal(entries[0].status, 'allowed');
        assert.equal(entries[0].path, '/v1/account/{account}/messages');
        assert.equal(entries[0].action, 'read');
        assert.equal(entries[0].group, 'message');
        assert.ok(entries[0].time instanceof Date, 'the stored time should come back as a Date');
    });

    await t.test('records a denial with its reason', async () => {
        // A refused call is the interesting record - it is what "this agent tried to do X" looks like
        await redis.del(logKey);
        auditLog.record(entry({ status: 'denied', reason: 'group', group: 'admin' }));
        await waitForEntries(1);

        const { entries } = await auditLog.list(TOKEN_ID);
        assert.equal(entries[0].status, 'denied');
        assert.equal(entries[0].reason, 'group');
    });

    await t.test('returns newest first', async () => {
        await redis.del(logKey);
        for (const path of ['/first', '/second', '/third']) {
            auditLog.record(entry({ path }));
        }
        await waitForEntries(3);

        const { entries } = await auditLog.list(TOKEN_ID);
        assert.deepEqual(
            entries.map(e => e.path),
            ['/third', '/second', '/first']
        );
    });

    await t.test('trims to the retention cap', async () => {
        await redis.del(logKey);
        const over = auditLog.LOG_ENTRIES + 10;
        for (let i = 0; i < over; i++) {
            auditLog.record(entry({ path: `/p${i}` }));
        }
        await waitForEntries(auditLog.LOG_ENTRIES);

        // A log of who read whose mail carries the sensitivity of the mail, so the cap is a hard
        // trim rather than a target it may drift past
        const len = await redis.llen(logKey);
        assert.equal(len, auditLog.LOG_ENTRIES, `expected the list capped at ${auditLog.LOG_ENTRIES}, got ${len}`);
    });

    await t.test('bounds how long a log survives its last use', async () => {
        await redis.del(logKey);
        auditLog.record(entry());
        await waitForEntries(1);

        // The bound itself is whatever EXPIRE was given; what matters is that one was set at all, so
        // a log cannot outlive the credential's activity indefinitely.
        const ttl = await redis.ttl(logKey);
        assert.ok(ttl > 0, 'the log key should carry a TTL');
    });

    await t.test('pages through the entries', async () => {
        await redis.del(logKey);
        for (let i = 0; i < 5; i++) {
            auditLog.record(entry({ path: `/page${i}` }));
        }
        await waitForEntries(5);

        const first = await auditLog.list(TOKEN_ID, { page: 0, pageSize: 2 });
        assert.equal(first.total, 5);
        assert.equal(first.pages, 3);
        assert.equal(first.entries.length, 2);

        // Pinned rather than merely "different from page 0": notDeepEqual also passes on an empty
        // page or on garbage
        const second = await auditLog.list(TOKEN_ID, { page: 1, pageSize: 2 });
        assert.deepEqual(
            second.entries.map(e => e.path),
            ['/page2', '/page1']
        );
    });

    await t.test('an empty log reads as empty rather than failing', async () => {
        // The normal state on an instance that just enabled the setting
        const result = await auditLog.list('0'.repeat(64));
        assert.deepEqual(result, { total: 0, page: 0, pages: 0, entries: [] });
    });

    await t.test('ignores an entry with no token id', async () => {
        await redis.del(logKey);
        auditLog.record({ status: 'allowed' });
        auditLog.record(undefined);
        assert.equal(await waitForEntries(1, 300), 0);
    });

    await t.test('records the denials that matter most, not just the permission one', async () => {
        // A leaked token used against the wrong account, or from an unlisted address, is the
        // strongest signal of credential misuse there is - a trail that held only the calls that
        // succeeded would be silent about exactly the ones worth looking at.
        await redis.del(logKey);
        for (const reason of ['scope', 'account', 'address', 'referrer', 'rateLimit']) {
            auditLog.record(entry({ status: 'denied', reason }));
        }
        await waitForEntries(5);

        const { entries } = await auditLog.list(TOKEN_ID);
        assert.deepEqual(entries.map(e => e.reason).sort(), ['account', 'address', 'rateLimit', 'referrer', 'scope']);
        assert.ok(entries.every(e => e.status === 'denied'));
    });

    await t.test('deleting a token removes its log', async () => {
        // The trail describes a credential that no longer exists, and the key is named after the
        // token id, so nothing else would ever collect it
        await settings.set('tokenAuditLog', true);
        auditLog.resetFlagCache();

        const token = await tokens.provision({ scopes: ['api'], description: 'audit log cleanup', nolog: true });
        provisioned.push(token);
        const tokenData = await tokens.getRawData(token);

        auditLog.record(entry({ tokenId: tokenData.id }));

        const key = `${REDIS_PREFIX}tokens:log:${tokenData.id}`;
        const deadline = Date.now() + 2000;
        while ((await redis.llen(key)) === 0 && Date.now() < deadline) {
            await new Promise(resolve => setTimeout(resolve, 20));
        }
        assert.equal(await redis.llen(key), 1, 'expected the entry to be written before deleting the token');

        await tokens.delete(token);
        assert.equal(await redis.exists(key), 0, 'the audit log outlived the token it describes');
    });
});
