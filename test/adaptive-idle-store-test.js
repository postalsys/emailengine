'use strict';

// lib/email-client/imap/adaptive-idle-store.js against the test Redis, and the IMAP client's close
// handler step that feeds it: a host whose idle sessions keep being dropped gets an interval every
// account connecting to it picks up.

const test = require('node:test');
const assert = require('node:assert').strict;
const crypto = require('crypto');

const { redis } = require('../lib/db');
const { learnedInterval, recordClose, LEARNED_KEY } = require('../lib/email-client/imap/adaptive-idle-store');
const { IMAPClient } = require('../lib/email-client/imap-client');
const { createMockLogger } = require('./helpers/mock-logger');
const registerRedisTeardown = require('./helpers/redis-teardown');

const hosts = [];
const newHost = () => {
    const host = `imap-${crypto.randomBytes(4).toString('hex')}.example.com`;
    hosts.push(host);
    return host;
};
test.after(async () => {
    if (hosts.length) {
        await redis.hdel(LEARNED_KEY, ...hosts);
    }
});
// after the cleanup above, which still needs the connection
registerRedisTeardown(redis);

const droppedIdle = now => ({ connectedAt: now - 45 * 1000, lastClientWrite: now - 30 * 1000, idlingAtClose: true, context: {} });

test('adaptive IDLE store', async t => {
    await t.test('two dropped idle sessions teach the host an interval, case-insensitively', async () => {
        const host = newHost();
        const now = Date.now();
        assert.strictEqual(await learnedInterval(redis, host), null);
        await recordClose(redis, host, droppedIdle(now), now);
        const second = await recordClose(redis, host.toUpperCase(), droppedIdle(now + 60000), now + 60000);
        assert.deepStrictEqual([second.before, second.after], [null, 18000]);
        assert.strictEqual(await learnedInterval(redis, host), 18000);
    });

    await t.test('a close that says nothing is not stored', async () => {
        const host = newHost();
        assert.strictEqual(await recordClose(redis, host, { connectedAt: null, context: {} }), null);
        assert.strictEqual(await redis.hexists(LEARNED_KEY, host), 0);
    });

    await t.test('a broken stored value reads as nothing learned', async () => {
        const host = newHost();
        await redis.hset(LEARNED_KEY, host, '{broken');
        assert.strictEqual(await learnedInterval(redis, host), null);
    });

    await t.test('IMAPClient.recordIdleClose() records and logs a change, and never throws', async () => {
        const host = newHost();
        const logger = createMockLogger();
        const client = Object.assign(Object.create(IMAPClient.prototype), { redis, logger, account: 'acc', imapConfig: { host } });
        await client.recordIdleClose(Object.assign(droppedIdle(Date.now()), { options: { host } }));
        await client.recordIdleClose(Object.assign(droppedIdle(Date.now()), { options: { host } }));
        assert.strictEqual(await learnedInterval(redis, host), 18000);
        assert.ok(logger.entries.some(entry => entry.msg === 'Learned an IDLE restart interval for the server'));

        const broken = Object.assign(Object.create(IMAPClient.prototype), {
            redis: {
                hget: async () => {
                    throw new Error('down');
                }
            },
            logger,
            account: 'acc'
        });
        await assert.doesNotReject(broken.recordIdleClose(Object.assign(droppedIdle(Date.now()), { options: { host } })));
    });
});
