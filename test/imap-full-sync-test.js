'use strict';

// SyncOperations.runFullSync() and runFastSync() end to end against the test Redis: what a sync
// pass leaves in the message index, what it queues as new, and which messages it reports deleted or
// changed. The property tests compare a run with a reference copy of the original one-message-at-a-
// time full sync loop, over random mailbox states with gaps, flag changes and partial FETCH rows, so
// the batched Redis access can not change what a pass reports.

const test = require('node:test');
const assert = require('node:assert').strict;

const { redis } = require('../lib/db');
const { compareExisting } = require('../lib/tools');
const { getFetchRange } = require('../lib/email-client/imap/sync-operations');
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

/**
 * The full sync loop as it was before its Redis access was batched: every fetched message read its
 * index entry on its own. Kept only as the oracle the batched implementation is compared with
 */
async function referenceFullSync(harness) {
    const { mailbox } = harness;
    const fields = { uid: true, flags: true };
    const status = mailbox.getMailboxStatus();
    let seqMax = 0;
    let lastHighestUid = 0;
    let range = false;
    while ((range = getFetchRange(status.messages, range))) {
        for await (let messageData of mailbox.connection.imapClient.fetch(range, fields, {})) {
            if (!messageData || !messageData.uid || !messageData.flags || messageData.uid <= lastHighestUid) {
                continue;
            }
            lastHighestUid = messageData.uid;
            messageData.flags.delete('\\Recent');
            if (messageData.seq > seqMax) {
                seqMax = messageData.seq;
            }
            let storedMessage = await mailbox.entryListGet(messageData.uid, { uid: true });
            if (!storedMessage) {
                let seq = await mailbox.entryListSet(messageData);
                if (seq) {
                    await redis.zadd(mailbox.getNotificationsKey(), messageData.uid, JSON.stringify({ uid: messageData.uid }));
                }
            } else {
                let diff = storedMessage.seq - messageData.seq;
                for (let i = diff - 1; i >= 0; i--) {
                    let deletedEntry = await mailbox.entryListExpunge(messageData.seq + i);
                    if (deletedEntry) {
                        await mailbox.processDeleted(deletedEntry);
                    }
                }
                let changes = compareExisting(storedMessage.entry, messageData);
                if (changes && (await mailbox.entryListSet(messageData))) {
                    await mailbox.processChanges(messageData, changes);
                }
            }
        }
    }
    let diff = (await redis.zcard(mailbox.getMessagesKey())) - seqMax;
    for (let i = diff - 1; i >= 0; i--) {
        let deletedEntry = await mailbox.entryListExpunge(seqMax + i + 1);
        if (deletedEntry) {
            await mailbox.processDeleted(deletedEntry);
        }
    }
}

async function referenceRun(state) {
    const harness = await createSyncHarness(state);
    try {
        await referenceFullSync(harness);
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

    // Recorded behaviour, not a claim that it is right: a partial row is skipped, so the message it
    // stands for is neither seen nor counted, and when it is the last one the trailing pass takes
    // the sequence number it held for gone
    await t.test('a partial row in the middle leaves its message indexed', async () => {
        const result = await fullSync({ server: [{ uid: 1 }, { uid: 2, partial: true }, { uid: 3 }], stored: uids(1, 2, 3) });
        assert.deepStrictEqual(result, { indexed: [1, 2, 3], queued: [], deleted: [], changed: [] });
    });

    await t.test('a partial row at the end is reported deleted', async () => {
        const result = await fullSync({ server: [{ uid: 1 }, { uid: 2 }, { uid: 3, partial: true }], stored: uids(1, 2, 3) });
        assert.deepStrictEqual(result, { indexed: [1, 2], queued: [], deleted: [3], changed: [] });
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

    await t.test('property: reports what the one-message-at-a-time loop reports', async () => {
        await forAll(
            mailboxState,
            async state => {
                assert.deepStrictEqual(await fullSync(state), await referenceRun(state));
            },
            { runs: 150 }
        );
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
});
