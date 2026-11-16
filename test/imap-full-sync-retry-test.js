'use strict';

// The FETCH error branch of SyncOperations.runFullSync(): a failed batch is fetched again after a
// growing wait, with the failure recorded on the account (syncError) until a FETCH succeeds. While
// it waits the connection can go away, another task can select a different folder, and the folder
// itself can change, so after the wait the loop checks the connection, aborts when the folder is
// no longer selected, and reads the folder status again, which moves where the batches end. The
// whole retry is bounded in time. The waits are skipped (test/helpers/instant-timers.js), with the
// clock moved on by each, so the time bound is reached in no real time.

const test = require('node:test');
const assert = require('node:assert').strict;
const path = require('node:path');

const { redis } = require('../lib/db');
const { FETCH_BATCH_SIZE } = require('../lib/email-client/imap/sync-operations');
const { createSyncHarness } = require('./helpers/sync-harness');
const { withInstantSleeps } = require('./helpers/instant-timers');
const registerRedisTeardown = require('./helpers/redis-teardown');

registerRedisTeardown(redis);

const SYNC_FILE = path.join('imap', 'sync-operations.js');

const uids = count => Array.from({ length: count }, (value, i) => ({ uid: i + 1 }));

/**
 * Makes the harness server fail chosen FETCH attempts. `plan(attempt, range)` returns an error to
 * throw (after `after` rows of that attempt, default none), or nothing to answer normally
 */
function scriptFetch(harness, plan) {
    const realFetch = harness.server.fetch;
    const attempts = [];
    harness.server.fetch = async function* (range, fields, opts) {
        const attempt = attempts.length + 1;
        attempts.push(range);
        const failure = await plan(attempt, range);
        let rows = 0;
        for await (const row of realFetch.call(this, range, fields, opts)) {
            if (failure && rows >= (failure.after || 0)) {
                break;
            }
            rows++;
            yield row;
        }
        if (failure) {
            throw failure.error;
        }
    };
    return attempts;
}

const fetchError = () => Object.assign(new Error('Command failed'), { responseStatus: 'NO', responseText: 'Server busy' });

async function withHarness(state, fn) {
    const harness = await createSyncHarness(state);
    await redis.hset(harness.keys.account, 'account', 'test-account');
    try {
        return await fn(harness);
    } finally {
        await harness.cleanup();
    }
}

test('runFullSync FETCH retry', async t => {
    await t.test('a failed FETCH is retried after a wait, with the failure recorded until it succeeds', async () => {
        await withHarness({ server: uids(5) }, async harness => {
            let recorded;
            scriptFetch(harness, async attempt => {
                if (attempt === 2) {
                    recorded = JSON.parse(await redis.hget(harness.keys.account, 'syncError'));
                }
                return attempt === 1 ? { error: fetchError(), after: 2 } : null;
            });

            const { error, delays } = await withInstantSleeps(SYNC_FILE, () => harness.sync.runFullSync());

            assert.equal(error, undefined);
            assert.deepEqual(delays, [2000]);
            assert.equal(recorded.path, 'INBOX');
            assert.deepEqual(recorded.error, { error: 'Command failed', responseStatus: 'NO', responseText: 'Server busy' });
            assert.ok(!Number.isNaN(Date.parse(recorded.time)));
            assert.equal(await redis.hexists(harness.keys.account, 'syncError'), 0, 'cleared by the FETCH that succeeded');
            // the rows of the failed attempt were never compared, the retry fetched them again
            assert.deepEqual(await harness.indexedUids(), [1, 2, 3, 4, 5]);
            assert.deepEqual(await harness.queuedUids(), [1, 2, 3, 4, 5]);
            assert.deepEqual(harness.events.deleted, []);
        });
    });

    await t.test('the rows of a failed attempt are dropped, the retry decides what changed', async () => {
        await withHarness({ server: uids(3), stored: uids(3) }, async harness => {
            scriptFetch(harness, async attempt => (attempt === 1 ? { error: fetchError(), after: 2 } : null));

            const { error } = await withInstantSleeps(SYNC_FILE, () => harness.sync.runFullSync(), {
                onSleep: () => {
                    // flagged on the server while the loop waited
                    harness.server.messages[0].flags = ['\\Seen'];
                }
            });

            assert.equal(error, undefined);
            assert.deepEqual(
                harness.events.changed.map(change => change.uid),
                [1]
            );
        });
    });

    await t.test('the failure is not recorded for an account that is gone', async () => {
        await withHarness({ server: uids(3) }, async harness => {
            await redis.del(harness.keys.account);
            let recorded;
            scriptFetch(harness, async attempt => {
                if (attempt === 2) {
                    recorded = await redis.hget(harness.keys.account, 'syncError');
                }
                return attempt === 1 ? { error: fetchError() } : null;
            });

            const { error } = await withInstantSleeps(SYNC_FILE, () => harness.sync.runFullSync());

            assert.equal(error, undefined);
            assert.equal(recorded, null);
            assert.equal(await redis.exists(harness.keys.account), 0);
        });
    });

    await t.test('the wait grows per batch and starts over for the next one', async () => {
        await withHarness({ server: uids(FETCH_BATCH_SIZE + 5) }, async harness => {
            const attempts = scriptFetch(harness, async attempt => {
                const failures = { 1: true, 2: true, 4: true };
                return failures[attempt] ? { error: fetchError() } : null;
            });

            const { error, delays } = await withInstantSleeps(SYNC_FILE, () => harness.sync.runFullSync());

            assert.equal(error, undefined);
            assert.deepEqual(delays, [2000, 4000, 2000]);
            assert.deepEqual(attempts, [
                `1:${FETCH_BATCH_SIZE}`,
                `1:${FETCH_BATCH_SIZE}`,
                `1:${FETCH_BATCH_SIZE}`,
                `${FETCH_BATCH_SIZE + 1}:*`,
                `${FETCH_BATCH_SIZE + 1}:*`
            ]);
            assert.equal((await harness.indexedUids()).length, FETCH_BATCH_SIZE + 5);
        });
    });

    await t.test('the status read again after a failure decides where the batches end', async () => {
        await withHarness({ server: uids(FETCH_BATCH_SIZE + 5), stored: uids(FETCH_BATCH_SIZE + 5) }, async harness => {
            const attempts = scriptFetch(harness, async attempt => {
                if (attempt === 1) {
                    // the folder shrank while the batch failed
                    harness.server.messages = harness.server.messages.slice(0, 10);
                    return { error: fetchError() };
                }
                return null;
            });

            const { error } = await withInstantSleeps(SYNC_FILE, () => harness.sync.runFullSync());

            assert.equal(error, undefined);
            assert.deepEqual(attempts, [`1:${FETCH_BATCH_SIZE}`, `1:${FETCH_BATCH_SIZE}`], 'no second batch for messages that are gone');
            assert.deepEqual(
                await harness.indexedUids(),
                uids(10).map(entry => entry.uid)
            );
            assert.equal(harness.events.deleted.length, FETCH_BATCH_SIZE - 5);
        });
    });

    await t.test('a connection that became unusable during the wait ends the pass', async () => {
        await withHarness({ server: uids(3), stored: uids(3) }, async harness => {
            const err = fetchError();
            const attempts = scriptFetch(harness, async () => ({ error: err }));

            const { error, delays } = await withInstantSleeps(SYNC_FILE, () => harness.sync.runFullSync(), {
                onSleep: () => {
                    harness.server.usable = false;
                }
            });

            assert.equal(error?.code, 'IMAPConnectionClosing');
            assert.equal(error.message, 'IMAP connection closed during sync');
            assert.equal(error.cause, err);
            assert.deepEqual(delays, [2000]);
            assert.equal(attempts.length, 1);
            assert.deepEqual(harness.events.deleted, []);
        });
    });

    await t.test('a connection already unusable is not waited for and records nothing', async () => {
        await withHarness({ server: uids(3), stored: uids(3) }, async harness => {
            scriptFetch(harness, async () => {
                harness.server.usable = false;
                return { error: fetchError() };
            });

            const { error, delays } = await withInstantSleeps(SYNC_FILE, () => harness.sync.runFullSync());

            assert.equal(error?.code, 'IMAPConnectionClosing');
            assert.deepEqual(delays, []);
            assert.equal(await redis.hexists(harness.keys.account, 'syncError'), 0);
        });
    });

    await t.test('another folder selected during the wait aborts the pass', async () => {
        for (const replacement of [{ path: 'Archive' }, null]) {
            await withHarness({ server: uids(3), stored: uids(3) }, async harness => {
                const err = fetchError();
                const attempts = scriptFetch(harness, async () => ({ error: err }));

                const { error } = await withInstantSleeps(SYNC_FILE, () => harness.sync.runFullSync(), {
                    onSleep: () => {
                        harness.server.mailbox = replacement;
                    }
                });

                assert.equal(error?.message, 'Mailbox changed during sync operation');
                assert.equal(error.cause, err);
                assert.equal(error.code, undefined);
                assert.equal(attempts.length, 1);
                assert.deepEqual(harness.events.deleted, []);
                assert.deepEqual(await harness.indexedUids(), [1, 2, 3]);
            });
        }
    });

    await t.test('the retry runs on the connection current after the wait', async () => {
        await withHarness({ server: uids(3) }, async harness => {
            const original = harness.server;
            const realFetch = original.fetch;
            scriptFetch(harness, async () => ({ error: fetchError() }));
            const used = [];
            const replacement = {
                usable: true,
                mailbox: { path: 'INBOX' },
                async *fetch(...args) {
                    used.push('replacement');
                    yield* realFetch.apply(original, args);
                }
            };

            const { error } = await withInstantSleeps(SYNC_FILE, () => harness.sync.runFullSync(), {
                onSleep: () => {
                    harness.mailbox.connection.imapClient = replacement;
                }
            });

            assert.equal(error, undefined);
            assert.deepEqual(used, ['replacement']);
            assert.deepEqual(await harness.indexedUids(), [1, 2, 3]);
        });
    });

    await t.test('a replacement connection that is not usable yet ends the pass', async () => {
        await withHarness({ server: uids(3), stored: uids(3) }, async harness => {
            scriptFetch(harness, async () => ({ error: fetchError() }));

            const { error } = await withInstantSleeps(SYNC_FILE, () => harness.sync.runFullSync(), {
                onSleep: () => {
                    harness.mailbox.connection.imapClient = { usable: false, mailbox: { path: 'INBOX' } };
                }
            });

            assert.equal(error?.code, 'IMAPConnectionClosing');
            assert.equal(error.message, 'IMAP connection not available');
        });
    });

    await t.test('retrying stops once the time bound is spent', async () => {
        await withHarness({ server: uids(3), stored: uids(3) }, async harness => {
            // bounded here too, so a loop that never gives up fails the test instead of hanging it
            const attempts = scriptFetch(harness, async attempt => (attempt <= 20 ? { error: fetchError() } : null));

            const { error, delays } = await withInstantSleeps(SYNC_FILE, () => harness.sync.runFullSync());

            assert.equal(error?.code, 'FetchRetryTimeout');
            assert.equal(error.statusCode, 504);
            // 2+4+8+16+32 seconds, then 60 each: past five minutes on the ninth attempt
            assert.deepEqual(delays, [2000, 4000, 8000, 16000, 32000, 60000, 60000, 60000, 60000]);
            assert.equal(attempts.length, 9);
            assert.deepEqual(harness.events.deleted, []);
            assert.ok(await redis.hexists(harness.keys.account, 'syncError'), 'the failure stays recorded');
        });
    });
});
