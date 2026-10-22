'use strict';

// lib/email-client/imap/adaptive-idle-store.js against the test Redis, and the IMAP client's close
// handler step that feeds it: a host whose idle sessions keep being dropped gets an interval every
// account connecting to it picks up.

const test = require('node:test');
const assert = require('node:assert').strict;
const crypto = require('crypto');

const { redis } = require('../lib/db');
const { learnedInterval, recordClose, LEARNED_KEY } = require('../lib/email-client/imap/adaptive-idle-store');
const { initialState, STABLE_SESSION } = require('../lib/email-client/imap/adaptive-idle');
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

    await t.test('a long session on a host with nothing learned writes nothing', async () => {
        const host = newHost();
        const now = Date.now();
        assert.strictEqual(await recordClose(redis, host, { connectedAt: now - 3600 * 1000, lastClientWrite: now, context: {} }, now), null);
        assert.strictEqual(await redis.hexists(LEARNED_KEY, host), 0);
    });

    await t.test('a host back to nothing learned gives up its field', async () => {
        const host = newHost();
        const now = Date.now();
        // a drop starts a run, a long session then ends it with nothing learned
        await recordClose(redis, host, droppedIdle(now), now);
        assert.strictEqual(await redis.hexists(LEARNED_KEY, host), 1);
        await recordClose(redis, host, { connectedAt: now - 3600 * 1000, lastClientWrite: now, context: {} }, now + 60000);
        assert.strictEqual(await redis.hexists(LEARNED_KEY, host), 0);
    });

    await t.test('a host whose cooldown is over gives up its field on the next long session', async () => {
        const host = newHost();
        const now = Date.now();
        await redis.hset(LEARNED_KEY, host, JSON.stringify(Object.assign(initialState(), { cappedUntil: now - 1 })));
        await recordClose(redis, host, { connectedAt: now - STABLE_SESSION, lastClientWrite: now, context: {} }, now);
        assert.strictEqual(await redis.hexists(LEARNED_KEY, host), 0);
    });

    await t.test('IMAPClient.close() marks the connection as closed on purpose, so nothing is learned from it', async () => {
        // Regression: a pause, a worker shutdown, a move to another worker or a requested reconnect
        // closed the primary connection without marking it, and the close handler took it for a
        // server drop (an idling session an operator paused was enough to cap a host for a day)
        const primary = Object.assign(droppedIdle(Date.now()), { close() {} });
        const client = Object.assign(Object.create(IMAPClient.prototype), {
            imapClient: primary,
            commandClient: null,
            closeSubconnections() {}
        });
        client.close();
        assert.strictEqual(primary.context.disabled, true);
        assert.strictEqual(await recordClose(redis, newHost(), primary), null, 'no observation');
    });

    await t.test('IMAPClient.recordIdleClose() measures from when the connection closed', async () => {
        const host = newHost();
        const client = Object.assign(Object.create(IMAPClient.prototype), { redis, account: 'a', logger: createMockLogger() });
        const closedAt = Date.now() - 5000;
        // lastClientWrite 30 s before the close: two of them teach 18 s, whatever the handler awaited
        await client.recordIdleClose(
            { options: { host }, connectedAt: closedAt - 45000, lastClientWrite: closedAt - 30000, idlingAtClose: true, context: {} },
            closedAt
        );
        await client.recordIdleClose(
            { options: { host }, connectedAt: closedAt + 15000, lastClientWrite: closedAt + 30000, idlingAtClose: true, context: {} },
            closedAt + 60000
        );
        assert.strictEqual(await learnedInterval(redis, host), 18000);
    });

    await t.test('a changed state is written once, and the result reports the interval before it', async () => {
        // pinned by mutation testing
        const host = newHost();
        const now = Date.now();
        const stored = JSON.stringify(Object.assign(initialState(), { interval: 18000, stable: 1 }));
        await redis.hset(LEARNED_KEY, host, stored);
        const writes = [];
        const spy = {
            hget: (...a) => redis.hget(...a),
            hset: (...a) => {
                writes.push(a);
                return redis.hset(...a);
            },
            hdel: (...a) => {
                writes.push(a);
                return redis.hdel(...a);
            }
        };
        // a long session that is not yet enough to relax: stable 1 -> 2 is a change, written once
        const longSession = { connectedAt: now - STABLE_SESSION, lastClientWrite: now, maxIdleTime: 18000, context: {} };
        const recorded = await recordClose(spy, host, longSession, now);
        assert.deepStrictEqual([recorded.before, recorded.after], [18000, 18000]);
        assert.strictEqual(writes.length, 1);
    });

    await t.test('an observation that changes nothing writes nothing', async () => {
        // pinned by mutation testing: a drop inside the cooldown leaves the state as it is
        const host = newHost();
        const now = Date.now();
        await redis.hset(LEARNED_KEY, host, JSON.stringify(Object.assign(initialState(), { cappedUntil: now + 3600000 })));
        const writes = [];
        const spy = {
            hget: (...a) => redis.hget(...a),
            hset: (...a) => writes.push(a),
            hdel: (...a) => writes.push(a)
        };
        await recordClose(spy, host, droppedIdle(now), now);
        assert.deepStrictEqual(writes, []);
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

    await t.test('IMAPClient.getLearnedIdleInterval() reads once for the connections an account opens together', async () => {
        const host = newHost();
        let reads = 0;
        const client = Object.assign(Object.create(IMAPClient.prototype), {
            logger: createMockLogger(),
            redis: {
                hget: async () => {
                    reads++;
                    return JSON.stringify({ interval: 18000 });
                }
            }
        });
        assert.strictEqual(await client.getLearnedIdleInterval(host), 18000);
        assert.strictEqual(await client.getLearnedIdleInterval(host), 18000);
        assert.strictEqual(reads, 1);
    });

    await t.test('IMAPClient.recordIdleClose() records and logs a change, and never throws', async t => {
        const host = newHost();
        const logger = createMockLogger();
        const client = Object.assign(Object.create(IMAPClient.prototype), { redis, logger, account: 'acc', imapConfig: { host } });
        await client.recordIdleClose(Object.assign(droppedIdle(Date.now()), { options: { host } }));
        // a second drop a minute later, not the same event seen twice
        t.mock.timers.enable({ apis: ['Date'], now: Date.now() + 60 * 1000 });
        try {
            await client.recordIdleClose(Object.assign(droppedIdle(Date.now()), { options: { host } }));
        } finally {
            t.mock.timers.reset();
        }
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
