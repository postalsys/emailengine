'use strict';

// lib/export-worker.js: the export job body moved out of workers/export.js. Driven with an in-memory
// export store, a scripted account and a collecting output stream, so every branch of indexing and
// exporting can be reached without a worker thread, a mail server or a file.

const test = require('node:test');
const assert = require('node:assert').strict;
const { PassThrough } = require('node:stream');

require('./helpers/mock-db').installDbMock();

const { createExportJobs, resolveFolders, LOCK_EXTENSION_INTERVAL, MESSAGE_FETCH_BATCH_SIZE, IMAP_MESSAGE_MAX_RETRIES } = require('../lib/export-worker');
const { createMockLogger } = require('./helpers/mock-logger');
const { forAll, gen } = require('./helpers/property');

require('./helpers/redis-teardown')();

const ACCOUNT = 'acc1';
const EXPORT_ID = 'exp_1';

function createStore() {
    const store = {
        queue: [],
        updates: [],
        counters: { messagesQueued: 0, messagesExported: 0, bytesWritten: 0, messagesSkipped: 0 },
        cancelled: false,
        extended: 0,
        queueCalls: 0,
        counterCalls: 0,
        async update(account, exportId, data) {
            store.updates.push(data);
        },
        async isCancelled() {
            return store.cancelled;
        },
        async extendExpiry() {
            store.extended++;
        },
        async queueMessage(account, exportId, info) {
            store.queueCalls++;
            if (store.queue.some(entry => entry.messageId === info.messageId)) {
                return false;
            }
            store.queue.push(info);
            store.counters.messagesQueued++;
            return true;
        },
        async queueMessages(account, exportId, infos) {
            store.queueCalls++;
            let added = 0;
            for (const info of infos) {
                if (!store.queue.some(entry => entry.messageId === info.messageId)) {
                    store.queue.push(info);
                    store.counters.messagesQueued++;
                    added++;
                }
            }
            return added;
        },
        async getNextBatch(account, exportId, limit) {
            return store.queue.splice(0, limit);
        },
        async incrementExported(account, exportId, bytes) {
            store.counterCalls++;
            store.counters.messagesExported++;
            store.counters.bytesWritten += bytes;
        },
        async incrementSkipped() {
            store.counterCalls++;
            store.counters.messagesSkipped++;
        },
        async incrementCounters(account, exportId, counts) {
            store.counterCalls++;
            store.counters.messagesExported += counts.exported || 0;
            store.counters.bytesWritten += counts.bytesWritten || 0;
            store.counters.messagesSkipped += counts.skipped || 0;
        }
    };
    return store;
}

function createOutput() {
    const input = new PassThrough();
    const output = new PassThrough();
    const lines = [];
    let buffered = '';
    input.on('data', chunk => {
        buffered += chunk.toString();
        let index;
        while ((index = buffered.indexOf('\n')) >= 0) {
            lines.push(JSON.parse(buffered.slice(0, index)));
            buffered = buffered.slice(index + 1);
        }
    });
    input.on('end', () => output.end());
    output.resume();
    return { input, output, lines, error: () => null, destroy() {} };
}

function createClock(start = 1_000_000) {
    let time = start;
    return { now: () => time, advance: ms => (time += ms) };
}

function createHarness({ account = {}, settingsValues = {}, clock = createClock() } = {}) {
    const store = createStore();
    const output = createOutput();
    const sleeps = [];
    const logger = createMockLogger();
    const job = {
        data: { account: ACCOUNT, exportId: EXPORT_ID },
        token: 't',
        locks: 0,
        async extendLock() {
            job.locks++;
        }
    };
    const accountObject = Object.assign(
        {
            async listMailboxes() {
                return [{ path: 'INBOX', specialUse: '\\Inbox' }];
            },
            async loadAccountData() {
                return {};
            },
            async isApiClient() {
                return false;
            }
        },
        account
    );
    const jobs = createExportJobs({
        redis: { hexists: async () => 1 },
        settings: {
            get: async key => settingsValues[key],
            getMulti: async (...keys) => Object.fromEntries(keys.map(key => [key, settingsValues[key]]))
        },
        getSecret: async () => 'secret',
        logger,
        Export: store,
        openExportOutput: async () => output,
        createAccount: async () => accountObject,
        sleep: async ms => {
            sleeps.push(ms);
        },
        now: clock.now
    });
    return { jobs, store, output, sleeps, logger, job, clock, accountObject };
}

const exportData = (extra = {}) => Object.assign({ exportId: EXPORT_ID, folders: '[]', startDate: '0', endDate: String(Date.now() + 3600 * 1000) }, extra);

test('resolveFolders', async t => {
    const mailboxes = [
        { path: 'INBOX', specialUse: '\\Inbox' },
        { path: 'Sent', specialUse: '\\Sent' },
        { path: 'Junk', specialUse: '\\Junk' },
        { path: 'Trash', specialUse: '\\Trash' },
        { path: 'Work' }
    ];

    await t.test('no folders requested: everything but Junk and Trash', () => {
        assert.deepStrictEqual(resolveFolders([], mailboxes), ['INBOX', 'Sent', 'Work']);
    });

    await t.test('no folders requested and an All folder: only that one', () => {
        assert.deepStrictEqual(resolveFolders(null, mailboxes.concat({ path: '[Gmail]/All Mail', specialUse: '\\All' })), ['[Gmail]/All Mail']);
    });

    await t.test('special-use names resolve, unknown ones drop out, paths pass through', () => {
        assert.deepStrictEqual(resolveFolders(['\\Sent', '\\Archive', 'Work'], mailboxes), ['Sent', 'Work']);
    });
});

test('indexMessages', async t => {
    function pagedAccount(pages) {
        return {
            calls: [],
            async listMessages(options) {
                this.calls.push(options);
                const index = options.cursor ? Number(options.cursor) : 0;
                return { messages: pages[index], nextPageCursor: index + 1 < pages.length ? String(index + 1) : null };
            }
        };
    }

    const page = (from, count) => Array.from({ length: count }, (v, i) => ({ id: `m${from + i}`, uid: from + i, size: 10, date: '2026-01-01T00:00:00Z' }));

    await t.test('queues every listed message across pages and reports progress', async () => {
        const account = pagedAccount([page(1, 3), page(4, 2)]);
        const { jobs, store, job } = createHarness({ account });
        await jobs.indexMessages(job, exportData());
        assert.deepStrictEqual(
            store.queue.map(entry => entry.messageId),
            ['m1', 'm2', 'm3', 'm4', 'm5']
        );
        assert.deepStrictEqual(store.queue[0], { folder: 'INBOX', messageId: 'm1', uid: 1, size: 10, date: Date.parse('2026-01-01T00:00:00Z') });
        assert.deepStrictEqual(store.updates, [{ foldersTotal: 1 }, { foldersScanned: 1 }]);
        assert.strictEqual(account.calls[0].metadataOnly, true);
    });

    await t.test('stops at the message limit and marks the export truncated', async () => {
        const { jobs, store, job } = createHarness({ account: pagedAccount([page(1, 5), page(6, 5)]), settingsValues: { exportMaxMessages: 7 } });
        await jobs.indexMessages(job, exportData());
        assert.strictEqual(store.queue.length, 7);
        assert.deepStrictEqual(store.updates.at(-1), { truncated: '1' });
    });

    await t.test('a folder deleted mid-export counts as empty', async () => {
        const err = new Error('Folder not found');
        err.code = 'FolderNotFound';
        const { jobs, store, job } = createHarness({
            account: {
                async listMessages() {
                    throw err;
                }
            }
        });
        await jobs.indexMessages(job, exportData());
        assert.strictEqual(store.queue.length, 0);
        assert.deepStrictEqual(store.updates.at(-1), { foldersScanned: 1 });
    });

    await t.test('retries a transient listing failure with backoff', async () => {
        let attempts = 0;
        const { jobs, store, job, sleeps } = createHarness({
            account: {
                async listMessages() {
                    if (++attempts < 3) {
                        const err = new Error('timeout');
                        err.code = 'ETIMEDOUT';
                        throw err;
                    }
                    return { messages: page(1, 1) };
                }
            }
        });
        await jobs.indexMessages(job, exportData());
        assert.strictEqual(store.queue.length, 1);
        assert.deepStrictEqual(sleeps, [1000, 2000]);
    });

    await t.test('a permanent failure fails the export naming the folder', async () => {
        const { jobs, job } = createHarness({
            account: {
                async listMessages() {
                    throw new Error('Authentication failed');
                }
            }
        });
        await assert.rejects(jobs.indexMessages(job, exportData()), /Failed to index folder "INBOX": Authentication failed/);
    });

    await t.test('a cancelled export stops before the next folder', async () => {
        const { jobs, store, job } = createHarness({ account: pagedAccount([page(1, 1)]) });
        store.cancelled = true;
        await assert.rejects(jobs.indexMessages(job, exportData()), err => err.code === 'ExportCancelled');
    });

    await t.test('property: queues min(listed, limit) messages for any page layout', async () => {
        await forAll(
            gen.record({ pages: gen.array(gen.integer(0, 30), 1, 5), limit: gen.integer(0, 80) }),
            async ({ pages, limit }) => {
                let from = 1;
                const layout = pages.map(count => {
                    const list = page(from, count);
                    from += count;
                    return list;
                });
                const { jobs, store, job } = createHarness({ account: pagedAccount(layout), settingsValues: { exportMaxMessages: limit } });
                await jobs.indexMessages(job, exportData());
                const total = from - 1;
                assert.strictEqual(store.queue.length, limit ? Math.min(total, limit) : total);
            },
            { runs: 200 }
        );
    });
});

test('exportMessages', async t => {
    const entries = count => Array.from({ length: count }, (v, i) => ({ folder: 'INBOX', messageId: `m${i + 1}`, uid: i + 1, size: 10 }));

    function imapAccount(behaviour = {}) {
        return {
            attempts: [],
            async getMessage(id) {
                this.attempts.push(id);
                if (behaviour[id]) {
                    return behaviour[id](this.attempts.filter(seen => seen === id).length);
                }
                return { id, subject: `Subject ${id}` };
            }
        };
    }

    await t.test('writes one line per message and counts it', async () => {
        const { jobs, store, job, output } = createHarness({ account: imapAccount() });
        store.queue.push(...entries(3));
        await jobs.exportMessages(job, exportData());
        assert.deepStrictEqual(
            output.lines.map(line => line.id),
            ['m1', 'm2', 'm3']
        );
        assert.strictEqual(output.lines[0].path, 'INBOX');
        assert.strictEqual(store.counters.messagesExported, 3);
        assert.strictEqual(
            store.counters.bytesWritten,
            output.lines.reduce((sum, line) => sum + Buffer.byteLength(JSON.stringify(line) + '\n'), 0)
        );
    });

    await t.test('skips a message that is gone and retries a transient failure', async () => {
        const gone = new Error('Not found');
        gone.statusCode = 404;
        const { jobs, store, job, output, sleeps } = createHarness({
            account: imapAccount({
                m1: () => {
                    throw gone;
                },
                m2: attempt => {
                    if (attempt < 2) {
                        const err = new Error('reset');
                        err.code = 'ECONNRESET';
                        throw err;
                    }
                    return { id: 'm2' };
                }
            })
        });
        store.queue.push(...entries(3));
        await jobs.exportMessages(job, exportData());
        assert.deepStrictEqual(
            output.lines.map(line => line.id),
            ['m2', 'm3']
        );
        assert.strictEqual(store.counters.messagesSkipped, 1);
        assert.strictEqual(store.counters.messagesExported, 2);
        assert.deepStrictEqual(sleeps, [2000]);
    });

    await t.test('a permanent fetch failure fails the export after closing the file', async () => {
        const { jobs, store, job, output } = createHarness({
            account: imapAccount({
                m2: () => {
                    throw new Error('Unexpected server response');
                }
            })
        });
        store.queue.push(...entries(3));
        await assert.rejects(jobs.exportMessages(job, exportData()), /Unexpected server response/);
        assert.strictEqual(output.input.writableEnded, true);
        assert.strictEqual(store.counters.messagesExported, 1);
    });

    await t.test('entries over the attachment size limit are skipped without a fetch', async () => {
        const account = imapAccount();
        const { jobs, store, job } = createHarness({ account, settingsValues: { exportMaxMessageSize: 100 } });
        store.queue.push({ folder: 'INBOX', messageId: 'big', uid: 1, size: 1000 }, ...entries(1));
        await jobs.exportMessages(job, exportData({ includeAttachments: '1' }));
        assert.deepStrictEqual(account.attempts, ['m1']);
        assert.strictEqual(store.counters.messagesSkipped, 1);
    });

    await t.test('stops at the size limit and marks the export truncated', async () => {
        const { jobs, store, job, output } = createHarness({ account: imapAccount(), settingsValues: { exportMaxSize: 60 } });
        store.queue.push(...entries(10));
        await jobs.exportMessages(job, exportData());
        assert.ok(output.lines.length < 10);
        assert.deepStrictEqual(store.updates.at(-1), { truncated: '1' });
    });

    function apiAccount(behaviour = {}) {
        const answer = (id, attempt) => (behaviour[id] ? behaviour[id](attempt) : { messageId: id, data: { id } });
        return {
            isApiClient: async () => true,
            batches: [],
            singles: [],
            async getMessages(ids) {
                this.batches.push(ids);
                return ids.map(id => answer(id, this.batches.filter(batch => batch.includes(id)).length));
            },
            // a batch of one entry is fetched on its own, as for IMAP
            async getMessage(id) {
                this.singles.push(id);
                const result = answer(id, 1);
                if (result.error) {
                    throw Object.assign(new Error(result.error.message), result.error);
                }
                return result.data || null;
            }
        };
    }

    await t.test('API accounts fetch in chunks and retry rate-limited messages', async () => {
        const account = apiAccount({
            m3: attempt => (attempt < 2 ? { messageId: 'm3', error: { statusCode: 429, message: 'slow down' } } : { messageId: 'm3', data: { id: 'm3' } }),
            m4: () => ({ messageId: 'm4', error: { statusCode: 404, message: 'gone' } }),
            m5: () => ({ messageId: 'm5' })
        });
        const { jobs, store, job, output, sleeps } = createHarness({ account });
        store.queue.push(...entries(MESSAGE_FETCH_BATCH_SIZE + 2));
        await jobs.exportMessages(job, exportData());
        assert.strictEqual(account.batches[0].length, MESSAGE_FETCH_BATCH_SIZE);
        assert.deepStrictEqual(account.batches[1], ['m3']);
        assert.strictEqual(output.lines.length, MESSAGE_FETCH_BATCH_SIZE + 2 - 2);
        assert.strictEqual(store.counters.messagesSkipped, 2);
        assert.strictEqual(sleeps.length, 1);
    });

    await t.test('an API error that is not retryable fails the export', async () => {
        const account = apiAccount({ m2: () => ({ messageId: 'm2', error: { statusCode: 400, code: 'BadRequest', message: 'bad' } }) });
        const { jobs, store, job } = createHarness({ account });
        store.queue.push(...entries(3));
        await assert.rejects(jobs.exportMessages(job, exportData()), err => err.code === 'BadRequest');
    });

    // Release 1 moved the lease extension into the per-message loops (commit f22b1d10): a batch can
    // run past the 10 minute job lock, and BullMQ then starts a second run of the same export
    await t.test('the job lock is extended per IMAP fetch attempt', async () => {
        const clock = createClock();
        const transient = new Error('timeout');
        transient.code = 'ETIMEDOUT';
        const { jobs, store, job } = createHarness({
            clock,
            account: {
                attempts: 0,
                async getMessage(id) {
                    // every attempt takes longer than the extension interval
                    clock.advance(LOCK_EXTENSION_INTERVAL + 1);
                    if (id === 'm1' && ++this.attempts < IMAP_MESSAGE_MAX_RETRIES) {
                        throw transient;
                    }
                    return { id };
                }
            }
        });
        store.queue.push(...entries(2));
        await jobs.exportMessages(job, exportData());
        // two attempts plus the success for m1, one fetch for m2: each extends the lease first
        assert.ok(job.locks >= IMAP_MESSAGE_MAX_RETRIES + 1, `${job.locks} extensions`);
        assert.strictEqual(job.locks, store.extended);
    });

    await t.test('the job lock is extended per API chunk', async () => {
        const clock = createClock();
        const account = apiAccount();
        const getMessages = account.getMessages.bind(account);
        account.getMessages = async ids => {
            clock.advance(LOCK_EXTENSION_INTERVAL + 1);
            return getMessages(ids);
        };
        const { jobs, store, job } = createHarness({ clock, account });
        store.queue.push(...entries(MESSAGE_FETCH_BATCH_SIZE * 3));
        await jobs.exportMessages(job, exportData());
        assert.strictEqual(account.batches.length, 3);
        assert.ok(job.locks >= 3, `${job.locks} extensions for 3 chunks`);
    });

    await t.test('progress is written once per batch, and a page is queued in one call', async () => {
        const { jobs, store, job } = createHarness({ account: imapAccount() });
        store.queue.push(...entries(250));
        await jobs.exportMessages(job, exportData());
        assert.strictEqual(store.counters.messagesExported, 250);
        // 250 entries are three batches of up to 100
        assert.strictEqual(store.counterCalls, 3);

        const indexing = createHarness({
            account: {
                async listMessages() {
                    return { messages: Array.from({ length: 700 }, (v, i) => ({ id: `m${i}`, uid: i + 1 })) };
                }
            }
        });
        await indexing.jobs.indexMessages(indexing.job, exportData());
        assert.strictEqual(indexing.store.queue.length, 700);
        assert.strictEqual(indexing.store.queueCalls, 1);
    });

    await t.test('progress made before a failure is still written', async () => {
        const { jobs, store, job } = createHarness({
            account: imapAccount({
                m5: () => {
                    throw new Error('Unexpected server response');
                }
            })
        });
        store.queue.push(...entries(10));
        await assert.rejects(jobs.exportMessages(job, exportData()));
        assert.strictEqual(store.counters.messagesExported, 4);
    });

    await t.test('property: exported + skipped always equals what was queued', async () => {
        await forAll(
            gen.record({ count: gen.integer(0, 250), missing: gen.array(gen.integer(1, 250), 0, 20), api: gen.boolean() }),
            async ({ count, missing, api }) => {
                const behaviour = {};
                for (const n of missing) {
                    behaviour[`m${n}`] = api
                        ? () => ({ messageId: `m${n}`, error: { statusCode: 404, message: 'gone' } })
                        : () => {
                              const err = new Error('gone');
                              err.statusCode = 404;
                              throw err;
                          };
                }
                const account = api ? apiAccount(behaviour) : imapAccount(behaviour);
                const { jobs, store, job, output } = createHarness({ account });
                store.queue.push(...entries(count));
                await jobs.exportMessages(job, exportData());
                const skipped = new Set(missing.filter(n => n <= count)).size;
                assert.strictEqual(store.counters.messagesExported + store.counters.messagesSkipped, count);
                assert.strictEqual(store.counters.messagesSkipped, skipped);
                assert.strictEqual(output.lines.length, store.counters.messagesExported);
            },
            { runs: 100 }
        );
    });
});
