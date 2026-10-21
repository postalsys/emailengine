'use strict';

// SyncOperations.runFullSync() and runFastSync() end to end against the test Redis: what a sync
// pass leaves in the message index, what it queues as new, and which messages it reports deleted or
// changed. The property tests compare a run with a reference copy of the original one-message-at-a-
// time full sync loop, over random mailbox states with gaps, flag changes and partial FETCH rows, so
// the batched Redis access can not change what a pass reports.

const test = require('node:test');
const assert = require('node:assert').strict;

const { redis } = require('../lib/db');
const { createSyncHarness, countingRedis } = require('./helpers/sync-harness');
const { forAll, gen } = require('./helpers/property');
const registerRedisTeardown = require('./helpers/redis-teardown');

registerRedisTeardown(redis);

const uids = (...list) => list.map(uid => ({ uid }));

async function fullSync(state) {
    const harness = await createSyncHarness(state);
    try {
        await harness.sync.runFullSync();
        return {
            indexed: await harness.indexedUids(),
            queued: await harness.queuedUids(),
            deleted: harness.events.deleted.slice().sort((a, b) => a - b),
            changed: harness.events.changed.map(change => change.uid)
        };
    } finally {
        await harness.cleanup();
    }
}

test('runFullSync', async t => {
    await t.test('first sync indexes and queues every message', async () => {
        const result = await fullSync({ server: uids(1, 2, 3, 7, 9) });
        assert.deepStrictEqual(result, { indexed: [1, 2, 3, 7, 9], queued: [1, 2, 3, 7, 9], deleted: [], changed: [] });
    });

    await t.test('an unchanged folder reports nothing', async () => {
        const result = await fullSync({ server: uids(1, 2, 3), stored: uids(1, 2, 3) });
        assert.deepStrictEqual(result, { indexed: [1, 2, 3], queued: [], deleted: [], changed: [] });
    });

    await t.test('a flag change is reported for that message only', async () => {
        const result = await fullSync({
            server: [{ uid: 1 }, { uid: 2, flags: ['\\Seen'] }, { uid: 3 }],
            stored: uids(1, 2, 3)
        });
        assert.deepStrictEqual(result.changed, [2]);
        assert.deepStrictEqual(result.queued, []);
    });

    await t.test('messages gone from the middle are found by the sequence gap', async () => {
        const result = await fullSync({ server: uids(1, 4, 5), stored: uids(1, 2, 3, 4, 5) });
        assert.deepStrictEqual(result, { indexed: [1, 4, 5], queued: [], deleted: [2, 3], changed: [] });
    });

    await t.test('messages gone from the end are found after the last batch', async () => {
        const result = await fullSync({ server: uids(1, 2), stored: uids(1, 2, 3, 4) });
        assert.deepStrictEqual(result, { indexed: [1, 2], queued: [], deleted: [3, 4], changed: [] });
    });

    await t.test('new and deleted messages in the same pass', async () => {
        const result = await fullSync({ server: uids(2, 3, 8, 9), stored: uids(1, 2, 5, 8) });
        assert.deepStrictEqual(result, { indexed: [2, 3, 8, 9], queued: [3, 9], deleted: [1, 5], changed: [] });
    });

    await t.test('an empty folder expunges everything indexed', async () => {
        const result = await fullSync({ server: [], stored: uids(1, 2) });
        assert.deepStrictEqual(result, { indexed: [], queued: [], deleted: [1, 2], changed: [] });
    });

    // Regression: deletions were worked out from how far an entry's index position had moved from
    // its sequence number, so a message missing from the index among them was reported deleted
    // right after being announced, and the one actually gone stayed indexed for good
    await t.test('a message missing from the index next to a deleted one', async () => {
        const result = await fullSync({ server: uids(3, 6, 12, 14), stored: uids(3, 6, 9, 14) });
        assert.deepStrictEqual(result, { indexed: [3, 6, 12, 14], queued: [12], deleted: [9], changed: [] });
    });

    // A partial row is a message the server answered without UID or FLAGS: what it stands for is
    // unknown, so the index entries next to it are neither compared nor taken for gone
    await t.test('a partial row in the middle leaves its message indexed', async () => {
        const result = await fullSync({ server: [{ uid: 1 }, { uid: 2, partial: true }, { uid: 3 }], stored: uids(1, 2, 3) });
        assert.deepStrictEqual(result, { indexed: [1, 2, 3], queued: [], deleted: [], changed: [] });
    });

    // Regression: the trailing pass took the sequence number of a partial row at the end for a
    // deleted message, and the next pass announced it as new again
    await t.test('a partial row at the end leaves its message indexed', async () => {
        const result = await fullSync({ server: [{ uid: 1 }, { uid: 2 }, { uid: 3, partial: true }], stored: uids(1, 2, 3) });
        assert.deepStrictEqual(result, { indexed: [1, 2, 3], queued: [], deleted: [], changed: [] });
    });

    await t.test('a partial row next to a deleted message keeps both until a pass can tell them apart', async () => {
        const result = await fullSync({ server: [{ uid: 1 }, { uid: 3, partial: true }, { uid: 5 }], stored: uids(1, 2, 3, 5) });
        assert.deepStrictEqual(result, { indexed: [1, 2, 3, 5], queued: [], deleted: [], changed: [] });
    });

    const FLAGS = ['\\Seen', '\\Flagged', '\\Answered', '$Label1'];
    const mailboxState = random => {
        const stored = [];
        const server = [];
        let uid = 0;
        const count = 1 + Math.floor(random() * 40);
        for (let i = 0; i < count; i++) {
            uid += 1 + Math.floor(random() * 3);
            const flags = FLAGS.filter(() => random() < 0.3);
            const where = random();
            if (where < 0.7) {
                stored.push({ uid, flags });
                server.push({ uid, flags: random() < 0.15 ? FLAGS.filter(() => random() < 0.3) : flags, partial: random() < 0.05 });
            } else if (where < 0.85) {
                stored.push({ uid, flags });
            } else {
                server.push({ uid, flags, partial: random() < 0.05 });
            }
        }
        return { stored, server };
    };

    await t.test('property: with partial rows, nothing on the server is reported deleted and gaps with no partial row are', async () => {
        await forAll(
            mailboxState,
            async state => {
                const result = await fullSync(state);
                const full = state.server.filter(message => !message.partial).map(message => message.uid);
                const partial = state.server.filter(message => message.partial).map(message => message.uid);
                const serverUids = state.server.map(message => message.uid);
                const gone = state.stored.map(message => message.uid).filter(uid => !serverUids.includes(uid));

                for (const uid of result.deleted) {
                    assert.ok(gone.includes(uid), `uid ${uid} is on the server but was reported deleted`);
                }
                for (const uid of gone) {
                    const before = Math.max(0, ...full.filter(other => other < uid));
                    const after = Math.min(Infinity, ...full.filter(other => other > uid));
                    if (!partial.some(other => other > before && other < after)) {
                        assert.ok(result.deleted.includes(uid), `uid ${uid} is gone with no partial row next to it`);
                    }
                }
                for (const uid of full) {
                    assert.ok(result.indexed.includes(uid), `uid ${uid} was fetched in full but is not indexed`);
                }
            },
            { runs: 200 }
        );
    });

    await t.test('property: with no partial rows, the index ends up equal to the server', async () => {
        await forAll(
            random => {
                const state = mailboxState(random);
                state.server.forEach(message => delete message.partial);
                return state;
            },
            async state => {
                const result = await fullSync(state);
                const serverUids = state.server.map(message => message.uid);
                const storedUids = state.stored.map(message => message.uid);
                assert.deepStrictEqual(result.indexed, serverUids);
                assert.deepStrictEqual(
                    result.queued,
                    serverUids.filter(uid => !storedUids.includes(uid))
                );
                assert.deepStrictEqual(
                    result.deleted,
                    storedUids.filter(uid => !serverUids.includes(uid))
                );
            },
            { runs: 150 }
        );
    });

    await t.test('an unchanged folder does not cost a Redis round trip per message', async () => {
        const counting = countingRedis(redis);
        const list = Array.from({ length: 300 }, (v, i) => ({ uid: i + 1 }));
        const harness = await createSyncHarness({ server: list, stored: list, redisClient: counting.client });
        try {
            counting.reset();
            await harness.sync.runFullSync();
            assert.deepStrictEqual(harness.events, { deleted: [], changed: [] });
            assert.ok(counting.roundTrips() < 30, `${counting.roundTrips()} round trips for 300 unchanged messages`);
        } finally {
            await harness.cleanup();
        }
    });
});

test('runFastSync', async t => {
    async function fastSync(state) {
        const harness = await createSyncHarness(state);
        try {
            if (state.storedUidNext) {
                await redis.hset(harness.keys.mailbox, 'uidNext', String(state.storedUidNext));
            }
            await harness.sync.runFastSync();
            return { queued: await harness.queuedUids(), uidNext: Number(await redis.hget(harness.keys.mailbox, 'uidNext')) };
        } finally {
            await harness.cleanup();
        }
    }

    await t.test('queues only messages above the stored UIDNEXT and moves it on', async () => {
        assert.deepStrictEqual(await fastSync({ server: uids(3, 5, 6, 9), storedStatus: { uidNext: 5 }, storedUidNext: 5 }), {
            queued: [5, 6, 9],
            uidNext: 10
        });
    });

    await t.test('nothing new, nothing queued', async () => {
        assert.deepStrictEqual(await fastSync({ server: uids(3, 4), storedStatus: { uidNext: 5 }, storedUidNext: 5 }), { queued: [], uidNext: 5 });
    });

    await t.test('partial rows are skipped', async () => {
        assert.deepStrictEqual(
            await fastSync({ server: [{ uid: 5 }, { uid: 6, partial: true }, { uid: 7 }], storedStatus: { uidNext: 5 }, storedUidNext: 5 }),
            {
                queued: [5, 7],
                uidNext: 8
            }
        );
    });

    await t.test('property: queues exactly the full rows at or above the stored UIDNEXT', async () => {
        await forAll(
            gen.record({
                server: gen.array(gen.integer(1, 60), 0, 25),
                partial: gen.array(gen.boolean(), 25, 25),
                uidNext: gen.integer(1, 60)
            }),
            async ({ server, partial, uidNext }) => {
                const list = [...new Set(server)].sort((a, b) => a - b).map((uid, i) => ({ uid, partial: partial[i] && i % 3 === 0 }));
                const result = await fastSync({ server: list, storedStatus: { uidNext }, storedUidNext: uidNext });
                const expected = list.filter(message => !message.partial && message.uid >= uidNext).map(message => message.uid);
                assert.deepStrictEqual(result.queued, expected);
                assert.strictEqual(result.uidNext, Math.max(uidNext, ...expected.map(uid => uid + 1)));
            },
            { runs: 150 }
        );
    });

    await t.test('a missing or broken stored UIDNEXT queues everything fetched', async () => {
        assert.deepStrictEqual(await fastSync({ server: uids(2, 3), storedStatus: { uidNext: 1 } }), { queued: [2, 3], uidNext: 4 });
        assert.deepStrictEqual(await fastSync({ server: uids(2, 3), storedStatus: { uidNext: 1 }, storedUidNext: 'x' }), { queued: [2, 3], uidNext: 4 });
    });

    await t.test('new messages cost a fixed number of round trips, not two each', async () => {
        const counting = countingRedis(redis);
        const list = Array.from({ length: 200 }, (v, i) => ({ uid: i + 10 }));
        const harness = await createSyncHarness({ server: list, storedStatus: { uidNext: 10 }, redisClient: counting.client });
        try {
            await redis.hset(harness.keys.mailbox, 'uidNext', '10');
            counting.reset();
            await harness.sync.runFastSync();
            assert.strictEqual((await harness.queuedUids()).length, 200);
            assert.ok(counting.roundTrips() < 10, `${counting.roundTrips()} round trips for 200 new messages`);
        } finally {
            await harness.cleanup();
        }
    });

    // The queue and UIDNEXT move together: UIDNEXT moved past a message that was never queued means
    // that message is never announced
    await t.test('a failed queue write leaves UIDNEXT where it was', async () => {
        const failing = new Proxy(redis, {
            get(target, name) {
                if (name === 'multi') {
                    return () => {
                        const multi = target.multi();
                        multi.zadd = () => {
                            multi.call('NOSUCHCOMMAND');
                            return multi;
                        };
                        return multi;
                    };
                }
                const value = target[name];
                return typeof value === 'function' ? value.bind(target) : value;
            }
        });
        const harness = await createSyncHarness({ server: uids(10, 11), storedStatus: { uidNext: 10 }, redisClient: failing });
        try {
            await redis.hset(harness.keys.mailbox, 'uidNext', '10');
            // the transaction is refused as a whole, so neither write lands
            await harness.sync
                .queueNewMessages([
                    { uid: 10, flags: new Set() },
                    { uid: 11, flags: new Set() }
                ])
                .catch(() => {});
            assert.strictEqual(await redis.hget(harness.keys.mailbox, 'uidNext'), '10');
            assert.deepStrictEqual(await harness.queuedUids(), []);
        } finally {
            await harness.cleanup();
        }
    });
});

test('a FETCH that finds no mailbox selected ends the pass', async () => {
    // ImapFlow 2.6.0 throws NoMailboxSelected where it used to yield nothing. Taken for an empty
    // folder, nothing had been fetched, so the trailing pass expunged every indexed message and
    // sent a messageDeleted for each. The pass now stops without touching the index
    const harness = await createSyncHarness({ server: uids(1, 2, 3), stored: uids(1, 2, 3) });
    try {
        let fetches = 0;
        // what ImapFlow's fetch() iterator does once no mailbox is selected: reject on the first read
        harness.server.fetch = () => ({
            [Symbol.asyncIterator]: () => ({
                next: async () => {
                    fetches++;
                    const err = new Error('No mailbox is currently selected');
                    err.code = 'NoMailboxSelected';
                    throw err;
                }
            })
        });

        await assert.rejects(harness.sync.runFullSync(), err => err.code === 'IMAPConnectionClosing' && err.cause?.code === 'NoMailboxSelected');
        assert.strictEqual(fetches, 1, 'not retried');
        assert.deepStrictEqual(harness.events.deleted, []);
        assert.deepStrictEqual(await harness.indexedUids(), [1, 2, 3]);
    } finally {
        await harness.cleanup();
    }
});
