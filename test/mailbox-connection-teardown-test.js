'use strict';

const test = require('node:test');
const assert = require('node:assert').strict;
const { Readable } = require('node:stream');

// Must run before the module under test is required: it pulls in lib/db, which opens real Redis
// connections at load time. The exercised paths never reach Redis.
// The last case runs the whole enrichment through to the notification, which reads a couple of
// account keys on the way. Nothing here asserts on Redis, so an empty answer is enough.
require('./helpers/mock-db').installDbMock({
    redis: { hget: async () => null, hgetall: async () => ({}), hset: async () => 1, pfadd: async () => 1, set: async () => 'OK', del: async () => 1 }
});

// The inline-image path is gated on the notifyWebSafeHtml setting, which mailbox.js reads through
// the shared settings module at call time - so the stub can go on the module object.
// Only the inline-image path is wanted here; everything else reads as unset, which is what an
// unconfigured instance would give back.
const settings = require('../lib/settings');
settings.get = async key => (key === 'notifyWebSafeHtml' ? true : undefined);

const { Mailbox } = require('../lib/email-client/imap/mailbox');

// A sync pass enriches each new message - inline images, bounce and ARF parsing, Gmail categories -
// by downloading more of it over the same connection. When the connection is torn down mid-pass,
// `connection.imapClient` is null, and every one of those calls used to dereference it directly.
//
// Two things went wrong, seen in production as
// "TypeError: Cannot read properties of null (reading 'downloadMany')":
//
//   1. The failure was reported as an error, so a routine reconnect paged Sentry.
//   2. A TypeError carries no `code`, so publishSyncedEvents() read it as a problem with the
//      MESSAGE rather than with the connection, dropped it from the notification queue and
//      announced it anyway - with its inline images still pointing at cid: references that were
//      never downloaded. The same held for an ImapFlow call that failed with NoConnection.
//
// requireImapClient() now fails the way the rest of the connection does, and the enrichment catches
// let a connection failure through so the message stays queued for the next pass.

const makeCtx = (imapClient = null) => ({
    path: 'INBOX',
    logger: { trace() {}, debug() {}, info() {}, warn() {}, error() {} },
    connection: { account: 'test-account', imapClient }
});

test('Mailbox.requireImapClient()', async t => {
    await t.test('returns the live client', () => {
        const client = { download: () => {} };
        assert.equal(Mailbox.prototype.requireImapClient.call(makeCtx(client)), client);
    });

    await t.test('fails as a connection error when the client is gone', () => {
        // The code is what publishSyncedEvents() reads to decide the message is still worth
        // keeping. A bare TypeError told it the opposite. It is the same code every other
        // "there is no connection to use" site raises, from lib/email-client/imap/connection-errors.
        assert.throws(
            () => Mailbox.prototype.requireImapClient.call(makeCtx(null)),
            err => {
                assert.equal(err.code, 'IMAPConnectionClosing');
                assert.ok(!(err instanceof TypeError), 'must not surface as a null dereference');
                return true;
            }
        );
    });

    await t.test('the thrown code is one publishSyncedEvents keeps the message for', async () => {
        // Pins the two halves together: the code connectionClient() throws has to be in the set the
        // queue-keeping branch tests, or the message is dropped exactly as before.
        const { CONNECTION_CLOSING_CODES } = require('../lib/consts');
        let thrown;
        try {
            Mailbox.prototype.requireImapClient.call(makeCtx(null));
        } catch (err) {
            thrown = err;
        }
        assert.ok(CONNECTION_CLOSING_CODES.has(thrown.code), `${thrown.code} must be a connection-closing code`);
    });
});

test('Mailbox.loadAttachmentContent()', async t => {
    // The three enrichment passes that need an attachment body (notifyAttachments, the inline
    // images, calendar parts) each carried their own copy of this. Only the calendar copy declined
    // to store a zero-length body; the extraction keeps that, because an empty string reaches the
    // webhook payload as a content field that is there but says nothing.
    const attachmentFor = () => ({ id: 'AAAAAQAAAAIx', contentType: 'image/png' });

    function makeCtx(download) {
        const logged = [];
        const ctx = Object.assign(Object.create(Mailbox.prototype), {
            path: 'INBOX',
            logger: {
                trace() {},
                debug() {},
                info() {},
                warn() {},
                error: entry => logged.push(entry)
            },
            connection: { account: 'test-account', imapClient: { download } }
        });
        return { ctx, logged };
    }

    await t.test('stores the downloaded body as base64', async () => {
        const { ctx } = makeCtx(async () => ({ content: Readable.from([Buffer.from('hello')]) }));
        const attachment = attachmentFor();

        await ctx.loadAttachmentContent({ uid: 42 }, attachment, {});

        assert.equal(attachment.content, Buffer.from('hello').toString('base64'));
    });

    await t.test('leaves a zero-length body unset rather than storing an empty string', async () => {
        const { ctx } = makeCtx(async () => ({ content: Readable.from([]) }));
        const attachment = attachmentFor();

        await ctx.loadAttachmentContent({ uid: 42 }, attachment, {});

        assert.equal('content' in attachment, false);
    });

    await t.test('logs a download failure and leaves the rest of the message alone', async () => {
        const { ctx, logged } = makeCtx(async () => {
            throw Object.assign(new Error('Server refused the part'), { serverResponseCode: 'CANNOT' });
        });
        const attachment = attachmentFor();

        await ctx.loadAttachmentContent({ uid: 42 }, attachment, {});

        assert.equal('content' in attachment, false);
        assert.equal(logged.length, 1);
        assert.equal(logged[0].msg, 'Failed to load attachment content');
    });

    await t.test('lets a gone connection through so the message is re-queued', async () => {
        const { ctx, logged } = makeCtx(async () => {
            throw Object.assign(new Error('Connection not available'), { code: 'NoConnection' });
        });

        await assert.rejects(() => ctx.loadAttachmentContent({ uid: 42 }, attachmentFor(), {}), /Connection not available/);
        assert.deepEqual(logged, [], 'a teardown is not this attachment failing');
    });
});

test('Mailbox.processNew() when the connection goes away mid-enrichment', async t => {
    // processNew() reaches its download paths only for a message that needs enriching, so each case
    // below supplies the smallest message shape that gets there.
    function makeProcessNewCtx({ imapClient, messageInfo }) {
        const notifications = [];
        const logged = [];

        // Inherits the prototype rather than listing the methods it needs: processNew() delegates to
        // several of them, and a receiver that enumerates today's set goes stale the moment one
        // more is extracted.
        const ctx = Object.assign(Object.create(Mailbox.prototype), {
            path: 'INBOX',
            listingEntry: { path: 'INBOX', specialUse: '\\Inbox' },
            logger: {
                trace() {},
                debug() {},
                info() {},
                warn(entry) {
                    logged.push(entry);
                },
                error(entry) {
                    logged.push(entry);
                }
            },
            connection: {
                account: 'test-account',
                imapClient,
                notifyFrom: false,
                syncFrom: false,
                // Only reached once the enrichment is done, which is the point of the last case
                redis: { pfadd: async () => 1, set: async () => 'OK', del: async () => 1 },
                async notify(mailbox, event, data) {
                    notifications.push({ event, data });
                }
            },
            // The fetch itself is not what is under test - the enrichment that follows it is
            getMessage: async () => messageInfo,
            mightBeDSNResponse: () => false,
            mightBeABounce: () => false,
            mightBeAComplaint: () => false,
            getSeenMessagesKey: () => 'seen:test-account:INBOX'
        });

        return { ctx, notifications, logged };
    }

    await t.test('a null client stops the message being announced without its inline images', async () => {
        // The whole point: the message stays unannounced so the next pass can send it complete.
        const messageInfo = {
            id: 'AAAAAQAAAAI',
            uid: 42,
            attachments: [{ id: 'AAAAAQAAAAIx', contentId: '<img1>', contentType: 'image/png' }],
            text: { html: '<img src="cid:img1">' },
            headers: {}
        };

        const { ctx } = makeProcessNewCtx({ imapClient: null, messageInfo });

        await assert.rejects(
            () => ctx.processNew({ uid: messageInfo.uid, flags: new Set() }, {}, false, {}),
            err => {
                assert.equal(err.code, 'IMAPConnectionClosing', 'the failure has to reach the caller as a connection error');
                return true;
            }
        );
    });

    await t.test('a client that reports NoConnection is passed on the same way', async () => {
        // Same window, one step later: the client object survives the teardown but every command
        // on it fails. This one already had a code and was still swallowed.
        const messageInfo = {
            id: 'AAAAAQAAAAI',
            uid: 42,
            attachments: [{ id: 'AAAAAQAAAAIx', contentId: '<img1>', contentType: 'image/png' }],
            text: { html: '<img src="cid:img1">' },
            headers: {}
        };

        // Both download entry points fail the same way, so the case does not depend on which one
        // this message's shape reaches first
        const failing = async () => {
            let err = new Error('Connection not available');
            err.code = 'NoConnection';
            throw err;
        };
        const imapClient = { download: failing, downloadMany: failing };
        const { ctx } = makeProcessNewCtx({ imapClient, messageInfo });

        await assert.rejects(
            () => ctx.processNew({ uid: messageInfo.uid, flags: new Set() }, {}, false, {}),
            err => {
                assert.equal(err.code, 'NoConnection', "ImapFlow's own code is passed on, not re-wrapped");
                return true;
            }
        );
    });

    await t.test('a download failure that is not the connection still delivers the message', async () => {
        // The tradeoff has a limit: a server refusing one part is the message's problem, and
        // holding the whole notification back for it would be worse than announcing it as-is.
        const messageInfo = {
            id: 'AAAAAQAAAAI',
            uid: 42,
            attachments: [{ id: 'AAAAAQAAAAIx', contentId: '<img1>', contentType: 'image/png' }],
            text: { html: '<img src="cid:img1">' },
            headers: {}
        };

        const failing = async () => {
            let err = new Error('Server refused the part');
            err.serverResponseCode = 'CANNOT';
            throw err;
        };
        const imapClient = { download: failing, downloadMany: failing };
        const { ctx, notifications, logged } = makeProcessNewCtx({ imapClient, messageInfo });

        await ctx.processNew({ uid: messageInfo.uid, flags: new Set() }, {}, false, {});

        assert.equal(notifications.length, 1, 'the message is still announced');
        assert.equal(notifications[0].event, 'messageNew');
        assert.ok(
            logged.some(entry => /Failed to (download attachments|load attachment content)/.test(entry.msg)),
            'and the failure is still reported'
        );
    });
});
