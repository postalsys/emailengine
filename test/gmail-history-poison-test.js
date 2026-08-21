'use strict';

// Unit coverage for the Gmail poison history entry protection (gmail-client.js
// processHistory).
//
// The googleHistoryId cursor only advances after an entry is processed, so an
// entry whose processing kills the worker (heartbeat restart, OOM) used to be
// refetched by every restarted worker forever, taking the whole worker pool
// down with it. processHistory now records an in-flight marker
// (googleHistoryProcessing) before each entry; when the same entry has already
// started GMAIL_MAX_HISTORY_ENTRY_ATTEMPTS times without finishing, it is
// skipped with a logged error and the cursor advances past it.

const test = require('node:test');
const assert = require('node:assert').strict;

const { GmailClient } = require('../lib/email-client/gmail-client');
const { GMAIL_MAX_HISTORY_ENTRY_ATTEMPTS } = require('../lib/consts');
const { redis } = require('../lib/db');
const registerRedisTeardown = require('./helpers/redis-teardown');

// Requiring the client pulls in lib/db (persistent Redis + BullMQ handles); force a clean exit.
registerRedisTeardown(redis);

const historyEntry = id => ({
    id: `${id}`,
    messagesAdded: [{ message: { id: `gmsg-${id}`, threadId: 't1', labelIds: ['INBOX'] } }]
});

const usedAccounts = [];

// Build a GmailClient against the test Redis with history collaborators stubbed
function makeClient(account, historyPage) {
    const client = new GmailClient(account, { redis });
    usedAccounts.push(client);
    const logs = { error: [], warn: [], info: [] };
    client.logger = {
        error: entry => logs.error.push(entry),
        warn: entry => logs.warn.push(entry),
        info: entry => logs.info.push(entry),
        debug: () => {},
        trace: () => {}
    };
    const processed = [];
    const markersDuringProcessing = [];
    client.processHistoryEntry = async entry => {
        markersDuringProcessing.push(JSON.parse(await redis.hget(client.getAccountKey(), 'googleHistoryProcessing')));
        processed.push(entry.id);
    };
    client.request = async () => historyPage;
    return { client, logs, processed, markersDuringProcessing };
}

test('Gmail poison history entry protection', async t => {
    t.after(async () => {
        for (let client of usedAccounts) {
            await redis.del(client.getAccountKey());
        }
    });

    await t.test('marks the entry in flight while it is processed and clears the marker after the run', async () => {
        const { client, processed, markersDuringProcessing } = makeClient('poison-test-clean', {
            history: [historyEntry(1001)],
            historyId: '1001'
        });

        await client.processHistory(1000, 1001);

        assert.deepStrictEqual(processed, ['1001']);
        // the marker existed while the entry was in flight and named it
        assert.deepStrictEqual(markersDuringProcessing, [{ id: '1001', count: 1 }]);
        // and is gone after the run completed
        assert.strictEqual(await redis.hget(client.getAccountKey(), 'googleHistoryProcessing'), null);
        // the cursor advanced
        assert.strictEqual(await redis.hget(client.getAccountKey(), 'googleHistoryId'), '1001');
    });

    await t.test('a marker left by a died worker increments the attempt count on the retry', async () => {
        const { client, processed, markersDuringProcessing } = makeClient('poison-test-retry', {
            history: [historyEntry(1001)],
            historyId: '1001'
        });
        // a previous worker started this entry once and never finished
        await redis.hset(client.getAccountKey(), 'googleHistoryProcessing', JSON.stringify({ id: '1001', count: 1 }));

        await client.processHistory(1000, 1001);

        // still below the limit: the entry is processed again, as attempt two
        assert.deepStrictEqual(processed, ['1001']);
        assert.deepStrictEqual(markersDuringProcessing, [{ id: '1001', count: 2 }]);
        assert.strictEqual(await redis.hget(client.getAccountKey(), 'googleHistoryProcessing'), null);
    });

    await t.test('skips an entry that reached the attempt limit and advances the cursor past it', async () => {
        const { client, logs, processed } = makeClient('poison-test-skip', {
            history: [historyEntry(1001), historyEntry(1002)],
            historyId: '1002'
        });
        // every allowed attempt has already started and died
        await redis.hset(client.getAccountKey(), 'googleHistoryProcessing', JSON.stringify({ id: '1001', count: GMAIL_MAX_HISTORY_ENTRY_ATTEMPTS }));

        await client.processHistory(1000, 1002);

        // the poison entry was skipped, the next one still processed
        assert.deepStrictEqual(processed, ['1002']);
        // the skip is logged with the account, the entry and the lost messages
        const skipLog = logs.error.find(entry => entry.entryId === '1001');
        assert.ok(skipLog, 'skip must be logged');
        assert.strictEqual(skipLog.account, 'poison-test-skip');
        assert.deepStrictEqual(skipLog.messageIds, ['gmsg-1001']);
        // the cursor moved past the poison entry so the account makes progress
        assert.strictEqual(await redis.hget(client.getAccountKey(), 'googleHistoryId'), '1002');
        assert.strictEqual(await redis.hget(client.getAccountKey(), 'googleHistoryProcessing'), null);
    });

    await t.test('a marker for a different entry does not affect processing', async () => {
        const { client, processed, markersDuringProcessing } = makeClient('poison-test-other', {
            history: [historyEntry(1001)],
            historyId: '1001'
        });
        // marker names an entry that is no longer in the fetched range
        await redis.hset(client.getAccountKey(), 'googleHistoryProcessing', JSON.stringify({ id: '999', count: GMAIL_MAX_HISTORY_ENTRY_ATTEMPTS + 2 }));

        await client.processHistory(1000, 1001);

        assert.deepStrictEqual(processed, ['1001']);
        // the stale marker was replaced by this entry's own first attempt
        assert.deepStrictEqual(markersDuringProcessing, [{ id: '1001', count: 1 }]);
        assert.strictEqual(await redis.hget(client.getAccountKey(), 'googleHistoryProcessing'), null);
    });

    await t.test('an entry that throws is logged and does not loop', async () => {
        const { client, logs } = makeClient('poison-test-throw', {
            history: [historyEntry(1001)],
            historyId: '1001'
        });
        client.processHistoryEntry = async () => {
            throw new Error('processing failed');
        };

        await client.processHistory(1000, 1001);

        // thrown errors keep the pre-existing behavior: logged, cursor advances
        assert.ok(logs.error.find(entry => entry.msg === 'Failed to process history entry'));
        assert.strictEqual(await redis.hget(client.getAccountKey(), 'googleHistoryId'), '1001');
        assert.strictEqual(await redis.hget(client.getAccountKey(), 'googleHistoryProcessing'), null);
    });

    await t.test('a graceful close clears an in-flight marker so a deploy does not leave a strike', async () => {
        const { client } = makeClient('poison-test-close', { history: [], historyId: '1001' });
        // a worker was terminated mid-entry, but by a drain rather than by the entry
        await redis.hset(client.getAccountKey(), 'googleHistoryProcessing', JSON.stringify({ id: '1001', count: 1 }));

        await client.close();

        assert.strictEqual(await redis.hget(client.getAccountKey(), 'googleHistoryProcessing'), null);
    });
});
