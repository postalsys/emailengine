'use strict';

// processNew() fetches the headers its own checks need (see notificationHeaderFields()) on top of
// the ones the notifyHeaders setting asks for, and narrows the published set back down. The
// narrowing has to come after the complaint, delivery-report and bounce checks: it used to run
// before them, so with a notifyHeaders list that left out Auto-Submitted or Content-Type the
// checks never saw the headers fetched for them.

const test = require('node:test');
const assert = require('node:assert').strict;

// Must run before the module under test is required: it pulls in lib/db, which opens real Redis
// connections at load time. The run reaches the notification, which reads a couple of account
// keys on the way; an empty answer is enough
require('./helpers/mock-db').installDbMock({
    redis: { hget: async () => null, hgetall: async () => ({}), hset: async () => 1, pfadd: async () => 1, set: async () => 'OK', del: async () => 1 }
});

const settings = require('../lib/settings');
settings.get = async () => undefined;

const { Mailbox } = require('../lib/email-client/imap/mailbox');
const { noopLogger } = require('./helpers/auth-failure');

require('./helpers/redis-teardown')();

test('Mailbox.processNew() header narrowing', async t => {
    await t.test('the bounce check sees the fetched headers, the notification only the requested ones', async () => {
        const fetched = { subject: ['Undeliverable: Quarterly report'], 'auto-submitted': ['auto-generated'], 'content-type': ['text/plain'] };
        const seenByChecks = {};
        const notifications = [];

        const ctx = Object.assign(Object.create(Mailbox.prototype), {
            path: 'INBOX',
            listingEntry: { path: 'INBOX', specialUse: '\\Inbox' },
            logger: noopLogger,
            connection: {
                account: 'test-account',
                imapClient: null,
                notifyFrom: false,
                syncFrom: false,
                redis: { pfadd: async () => 1 },
                async notify(mailbox, event, data) {
                    notifications.push({ event, data });
                }
            },
            getMessage: async () => ({ id: 'AAAAAQAAAAI', uid: 42, headers: Object.assign({}, fetched) }),
            mightBeDSNResponse(messageInfo) {
                seenByChecks.dsn = Object.keys(messageInfo.headers);
                return false;
            },
            mightBeABounce(messageInfo) {
                seenByChecks.bounce = Object.keys(messageInfo.headers);
                return false;
            },
            mightBeAComplaint: () => false,
            getSeenMessagesKey: () => 'seen:test-account:INBOX'
        });

        // What publishSyncedEvents() passes for notifyHeaders = ['subject']
        await ctx.processNew({ uid: 42, flags: new Set() }, { headers: ['subject'], fetchHeaders: ['subject', 'auto-submitted', 'content-type'] }, false, {});

        assert.deepEqual(seenByChecks.dsn, Object.keys(fetched));
        assert.deepEqual(seenByChecks.bounce, Object.keys(fetched));
        assert.equal(notifications.length, 1);
        assert.deepEqual(Object.keys(notifications[0].data.headers), ['subject'], 'the payload carries only what was asked for');
    });
});
