'use strict';

// Mailbox.onHighestModseq(): ImapFlow 2.6.0 reports a HIGHESTMODSEQ change it finds while polling a
// server without IDLE. Such a server sends no FETCH when flags change, so this is the only sign of a
// change before the next resync; it runs the same debounced partial sync an EXISTS does.

const test = require('node:test');
const assert = require('node:assert').strict;

require('./helpers/mock-db').installDbMock();

const { Mailbox } = require('../lib/email-client/imap/mailbox');
const { createMockLogger } = require('./helpers/mock-logger');

require('./helpers/redis-teardown')();

function makeMailbox(extra) {
    const logger = createMockLogger();
    logger.child = () => logger;
    const syncs = [];
    const mailbox = Object.assign(Object.create(Mailbox.prototype), {
        path: 'INBOX',
        logger,
        syncDisabled: false,
        partialSync: async () => syncs.push(Date.now()),
        shouldRunPartialSyncAfterExists: async () => false,
        ...extra
    });
    return { mailbox, syncs };
}

const event = { path: 'INBOX', highestModseq: 12n, prevHighestModseq: 10n };

test('Mailbox.onHighestModseq()', async t => {
    await t.test('runs one partial sync for a burst of changes', async () => {
        t.mock.timers.enable({ apis: ['setTimeout'] });
        try {
            const { mailbox, syncs } = makeMailbox();
            await mailbox.onHighestModseq(event);
            await mailbox.onHighestModseq(Object.assign({}, event, { highestModseq: 13n }));
            t.mock.timers.tick(1000);
            await new Promise(resolve => setImmediate(resolve));
            assert.strictEqual(syncs.length, 1);
        } finally {
            t.mock.timers.reset();
        }
    });

    await t.test('does not ask whether the message count changed, as an EXISTS does', async () => {
        t.mock.timers.enable({ apis: ['setTimeout'] });
        try {
            // shouldRunPartialSyncAfterExists() answers false here: a flag change leaves the count
            const { mailbox, syncs } = makeMailbox();
            await mailbox.onHighestModseq(event);
            t.mock.timers.tick(1000);
            await new Promise(resolve => setImmediate(resolve));
            assert.strictEqual(syncs.length, 1);

            await mailbox.onExists({ path: 'INBOX', count: 5, prevCount: 5 });
            t.mock.timers.tick(1000);
            await new Promise(resolve => setImmediate(resolve));
            assert.strictEqual(syncs.length, 1, 'an EXISTS still checks first');
        } finally {
            t.mock.timers.reset();
        }
    });

    await t.test('a folder excluded from syncing is left alone', async () => {
        t.mock.timers.enable({ apis: ['setTimeout'] });
        try {
            const { mailbox, syncs } = makeMailbox({ syncDisabled: true });
            await mailbox.onHighestModseq(event);
            t.mock.timers.tick(1000);
            await new Promise(resolve => setImmediate(resolve));
            assert.strictEqual(syncs.length, 0);
        } finally {
            t.mock.timers.reset();
        }
    });
});
