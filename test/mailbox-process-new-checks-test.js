'use strict';

// What processNew() has settled by the time it runs the complaint, delivery-report and bounce
// checks: the folder the message counts as, which the fetch decides (its own folder, or on Gmail
// the label, since every message lives in All Mail there), and the headers the checks see. The
// headers fetched for the checks (see notificationHeaderFields()) are narrowed down to the
// notifyHeaders list only afterwards; the narrowing used to run first, so a list that left out
// Auto-Submitted or Content-Type hid them.

//
// Then the delivery-report check itself: a message can be expunged between being detected and being
// downloaded (a server-side filter moving a DSN to Junk within a second does exactly that), and
// download() then resolves with no content. The check used to hand that to the parser, which threw
// and was logged as "Failed to process DSN" for a normal race.

const test = require('node:test');
const assert = require('node:assert').strict;
const fs = require('node:fs');
const path = require('node:path');
const { Readable } = require('node:stream');

// Must run before the module under test is required: it pulls in lib/db, which opens real Redis
// connections at load time. The run reaches the notification, which reads a couple of account
// keys on the way; an empty answer is enough
require('./helpers/mock-db').installDbMock({
    redis: { hget: async () => null, hgetall: async () => ({}), hset: async () => 1, pfadd: async () => 1, set: async () => 'OK', del: async () => 1 }
});

const settings = require('../lib/settings');
settings.get = async () => undefined;
settings.getMulti = async (...keys) => Object.fromEntries(await Promise.all(keys.map(async key => [key, await settings.get(key)])));

const { Mailbox } = require('../lib/email-client/imap/mailbox');
const { createMockLogger } = require('./helpers/mock-logger');

require('./helpers/redis-teardown')();

const snapshot = messageInfo => ({ headers: Object.keys(messageInfo.headers || {}), messageSpecialUse: messageInfo.messageSpecialUse });

function createContext({ specialUse = '\\Inbox', headers = {}, labels, dsn = false, bounce = false, download } = {}) {
    const seen = {};
    const notifications = [];
    const downloads = [];
    const logger = createMockLogger();
    logger.child = () => logger;

    const ctx = Object.assign(Object.create(Mailbox.prototype), {
        path: 'INBOX',
        listingEntry: { path: 'INBOX', specialUse },
        logger,
        connection: {
            account: 'test-account',
            imapClient: download
                ? {
                      async download(uid, part) {
                          downloads.push({ uid, part });
                          return download();
                      }
                  }
                : null,
            notifyFrom: false,
            redis: { pfadd: async () => 1 },
            getImapConnection: async () => ({ fetchOne: async () => ({ uid: 42, flags: new Set() }) }),
            // The arrival checks live on the connection; each records what it was shown
            mightBeAComplaint(messageInfo) {
                seen.complaint = snapshot(messageInfo);
                return false;
            },
            mightBeDSNResponse(messageInfo) {
                seen.dsn = snapshot(messageInfo);
                return dsn;
            },
            mightBeABounce(messageInfo) {
                seen.bounce = snapshot(messageInfo);
                return bounce;
            },
            async notify(mailbox, event, data) {
                notifications.push({ event, data });
            }
        },
        // The real fetch, since it is what decides the folder; only the server round trip and the
        // message assembly are stubbed
        getMessageInfo: async () => (seen.messageInfo = { id: 'AAAAAQAAAAI', uid: 42, headers: Object.assign({}, headers), labels }),
        getSeenMessagesKey: () => 'seen:test-account:INBOX'
    });

    const errors = () => logger.entries.filter(entry => entry.level === 'error').map(entry => entry.msg);

    return { ctx, seen, notifications, downloads, errors };
}

const processNew = (ctx, options = {}) => ctx.processNew({ uid: 42, flags: new Set() }, options, {});

test('Mailbox.processNew() before the arrival checks', async t => {
    await t.test('the folder is decided before the checks run', async () => {
        const { ctx, seen } = createContext({ specialUse: '\\Inbox' });

        await processNew(ctx);

        for (const check of ['complaint', 'dsn', 'bounce']) {
            assert.equal(seen[check].messageSpecialUse, '\\Inbox', `the ${check} check knows the folder`);
        }
    });

    await t.test('on Gmail the label decides, since every message lives in All Mail', async () => {
        const inbox = createContext({ specialUse: '\\All', labels: ['\\Inbox', '\\Important'] });
        await processNew(inbox.ctx);
        assert.equal(inbox.seen.bounce.messageSpecialUse, '\\Inbox');

        const elsewhere = createContext({ specialUse: '\\All', labels: ['\\Important'] });
        await processNew(elsewhere.ctx);
        assert.equal(elsewhere.seen.bounce.messageSpecialUse, undefined);

        // Junk, Sent and Trash outrank Inbox: a message carrying one of those labels as well is not an arrival
        const alsoSent = createContext({ specialUse: '\\All', labels: ['\\Sent', '\\Inbox'] });
        await processNew(alsoSent.ctx);
        assert.equal(alsoSent.seen.bounce.messageSpecialUse, '\\Sent');
    });

    await t.test('the checks see the fetched headers, the notification only the requested ones', async () => {
        // Only the keys matter here: the checks are stubs, and it is the plumbing under test
        const fetched = { subject: ['x'], 'auto-submitted': ['x'], 'content-type': ['x'] };
        const { ctx, seen, notifications } = createContext({ headers: fetched });

        // What publishSyncedEvents() passes for notifyHeaders = ['subject']
        await processNew(ctx, { headers: ['subject'], fetchHeaders: ['subject', 'auto-submitted', 'content-type'] });

        assert.deepEqual(seen.dsn.headers, Object.keys(fetched));
        assert.deepEqual(seen.bounce.headers, Object.keys(fetched));
        assert.equal(notifications.length, 1);
        assert.deepEqual(Object.keys(notifications[0].data.headers), ['subject'], 'the payload carries only what was asked for');
    });
});

test('Mailbox.processNew() delivery-report check', async t => {
    const DSN_SOURCE = fs.readFileSync(path.join(__dirname, 'fixtures', 'bounces', 'delayed.eml'));

    await t.test('a message expunged before the download is skipped without an error', async () => {
        // What download() answers for "* FETCH (... BODY[]<0> NIL)" + "OK [EXPUNGEISSUED]"
        const { ctx, seen, notifications, downloads, errors } = createContext({ dsn: true, download: async () => ({}) });

        await processNew(ctx);

        assert.equal(downloads.length, 1);
        assert.deepEqual(errors(), []);
        assert.equal(seen.messageInfo.deliveryReport, undefined);
        assert.equal(notifications.length, 1, 'the message is still announced');
    });

    await t.test('the bounce check does not download the expunged message again', async () => {
        const { ctx, notifications, downloads, errors } = createContext({ dsn: true, bounce: true, download: async () => ({}) });

        await processNew(ctx);

        assert.equal(downloads.length, 1);
        assert.deepEqual(errors(), []);
        assert.equal(notifications.length, 1);
    });

    await t.test('a downloaded delivery report is still parsed', async () => {
        const { ctx, seen, errors } = createContext({ dsn: true, download: async () => ({ content: Readable.from([DSN_SOURCE]) }) });

        await processNew(ctx);

        assert.deepEqual(errors(), []);
        assert.equal(seen.messageInfo.deliveryReport?.action, 'delayed');
    });

    await t.test('a failing download is still reported', async () => {
        const { ctx, notifications, errors } = createContext({
            dsn: true,
            download: async () => {
                throw new Error('Unexpected server answer');
            }
        });

        await processNew(ctx);

        assert.deepEqual(errors(), ['Failed to process DSN']);
        assert.equal(notifications.length, 1);
    });
});
