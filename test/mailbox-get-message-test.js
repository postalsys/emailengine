'use strict';

const test = require('node:test');
const assert = require('node:assert').strict;

// Must run before the module under test is required: it pulls in lib/db, which
// opens real Redis connections at load time. The exercised getMessage() path
// never reaches Redis.
require('./helpers/mock-db').installDbMock();

const { Mailbox } = require('../lib/email-client/imap/mailbox');

// Regression tests for Mailbox.getMessage().
//
// markAsSeen mirrored the flag into messageData.flags without checking that the
// set exists, while the condition guarding the block explicitly allowed a
// missing set through. A FETCH response without FLAGS - a partial response, or a
// caller-provided field list that leaves flags out - therefore raised
// "Cannot read properties of undefined (reading 'add')". The STORE-failure
// catch swallowed it as a "Failed to mark message as Seen" debug entry, and the
// pino formatter in lib/logger.js forwards every logged TypeError to error
// tracking, so each such fetch turned into an error report (Sentry EMAILENGINE-5).
//
// The same block also ran before the partial-response guard, so a FETCH that
// matched nothing (fetchOne returns false) was dereferenced too.

function createMockContext({ fetchResult, flagsAddResult = true, flagsAddError } = {}) {
    const flagsAddCalls = [];
    const loggedErrors = [];

    // Anything logged with an `err` is what reaches error tracking
    const recordError = entry => {
        if (entry && entry.err) {
            loggedErrors.push(entry.err);
        }
    };

    const connectionClient = {
        fetchOne: async () => fetchResult,
        messageFlagsAdd: async (range, flags, opts) => {
            flagsAddCalls.push({ range, flags, opts });
            if (flagsAddError) {
                throw flagsAddError;
            }
            return flagsAddResult;
        }
    };

    const ctx = {
        path: 'INBOX',
        listingEntry: { path: 'INBOX' },
        logger: {
            trace() {},
            debug: recordError,
            info() {},
            warn: recordError,
            error: recordError
        },
        connection: {
            account: 'test-account',
            getImapConnection: async () => connectionClient,
            onTaskCompleted() {},
            packUid: async () => 'AAAAAAAAAAAA',
            isAutoreply: () => false,
            attachBounces: async () => {}
        },
        // Use the real implementations so the returned payload is built the same
        // way as in production
        getMessageInfo: Mailbox.prototype.getMessageInfo,
        getAttachmentList: Mailbox.prototype.getAttachmentList
    };

    return { ctx, flagsAddCalls, loggedErrors };
}

function messageFixture(extra) {
    return Object.assign(
        {
            uid: 42,
            size: 1024,
            envelope: { subject: 'Test message' },
            internalDate: new Date('2026-07-20T10:47:39.000Z')
        },
        extra
    );
}

// skipLock keeps the test on getMessage's own logic instead of the mailbox
// locking that belongs to the live connection
const OPTS = { skipLock: true, markAsSeen: true, headers: false };

test('Mailbox.getMessage() markAsSeen handling', async t => {
    await t.test('does not raise a TypeError when the FETCH response carries no flags', async () => {
        const { ctx, flagsAddCalls, loggedErrors } = createMockContext({ fetchResult: messageFixture() });

        const messageInfo = await Mailbox.prototype.getMessage.call(ctx, { uid: 42 }, OPTS);

        assert.equal(flagsAddCalls.length, 1, 'the message must still be marked as seen on the server');
        assert.deepEqual(flagsAddCalls[0].flags, ['\\Seen']);
        assert.deepEqual(loggedErrors, [], 'a missing flag set is not an error and must not be reported as one');
        assert.equal(messageInfo.uid, 42);
        assert.equal(messageInfo.flags, undefined, 'an unknown flag set must not be invented from the flag we just set');
        assert.equal(messageInfo.unseen, undefined);
    });

    await t.test('mirrors the flag when the FETCH response carries flags', async () => {
        const { ctx, flagsAddCalls } = createMockContext({ fetchResult: messageFixture({ flags: new Set(['\\Flagged']) }) });

        const messageInfo = await Mailbox.prototype.getMessage.call(ctx, { uid: 42 }, OPTS);

        assert.equal(flagsAddCalls.length, 1);
        assert.deepEqual(messageInfo.flags.sort(), ['\\Flagged', '\\Seen']);
        assert.equal(messageInfo.unseen, undefined, 'the message must no longer be reported as unseen');
        assert.equal(messageInfo.flagged, true, 'the flags reported by the server must be preserved');
    });

    await t.test('does not mirror the flag when the server rejects the STORE', async () => {
        const { ctx } = createMockContext({ fetchResult: messageFixture({ flags: new Set() }), flagsAddResult: false });

        const messageInfo = await Mailbox.prototype.getMessage.call(ctx, { uid: 42 }, OPTS);

        assert.deepEqual(messageInfo.flags, []);
        assert.equal(messageInfo.unseen, true);
    });

    await t.test('a failing STORE does not fail the fetch', async () => {
        const storeError = new Error('STORE failed');
        const { ctx, loggedErrors } = createMockContext({ fetchResult: messageFixture({ flags: new Set() }), flagsAddError: storeError });

        const messageInfo = await Mailbox.prototype.getMessage.call(ctx, { uid: 42 }, OPTS);

        assert.equal(messageInfo.uid, 42);
        assert.equal(messageInfo.unseen, true);
        assert.deepEqual(loggedErrors, [storeError], 'a real STORE failure must still be logged');
    });

    await t.test('skips the STORE when the message is already seen', async () => {
        const { ctx, flagsAddCalls } = createMockContext({ fetchResult: messageFixture({ flags: new Set(['\\Seen']) }) });

        const messageInfo = await Mailbox.prototype.getMessage.call(ctx, { uid: 42 }, OPTS);

        assert.equal(flagsAddCalls.length, 0, 'an already seen message must not be stored again');
        assert.deepEqual(messageInfo.flags, ['\\Seen']);
    });
});

test('Mailbox.getMessage() partial response handling', async t => {
    // ImapFlow resolves fetchOne() with false when the range matched nothing, and
    // returns a bare object when the server answered without the requested fields
    for (let [label, fetchResult] of [
        ['the message was not found', false],
        ['the FETCH response has no UID', { size: 1024 }]
    ]) {
        await t.test(`returns false when ${label}`, async () => {
            const { ctx, flagsAddCalls } = createMockContext({ fetchResult });

            const messageInfo = await Mailbox.prototype.getMessage.call(ctx, { uid: 42 }, OPTS);

            assert.equal(messageInfo, false);
            assert.equal(flagsAddCalls.length, 0, 'a message that was not fetched must not be marked as seen');
        });
    }
});
