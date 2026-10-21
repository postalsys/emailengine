'use strict';

// Mailbox.processNew(): a potential bounce whose parsing fails must not leave the IMAP download
// half-read on the primary connection. The delivery-report branch destroyed its stream on a parser
// failure; the bounce branch next to it did not. The parser is replaced here so it fails while the
// download is still open, which a real broken message can not be relied on to do.

const test = require('node:test');
const assert = require('node:assert').strict;
const { PassThrough } = require('node:stream');

require('./helpers/mock-db').installDbMock({
    redis: { hget: async () => null, hgetall: async () => ({}), hset: async () => 1, pfadd: async () => 1, set: async () => 'OK', del: async () => 1 }
});

const bounceDetectModule = require('../lib/bounce-detect');
bounceDetectModule.bounceDetect = async () => {
    throw new Error('Unexpected DSN structure');
};

const settings = require('../lib/settings');
settings.get = async () => undefined;
settings.getMulti = async (...keys) => Object.fromEntries(await Promise.all(keys.map(async key => [key, await settings.get(key)])));

const { Mailbox } = require('../lib/email-client/imap/mailbox');
const { createMockLogger } = require('./helpers/mock-logger');

require('./helpers/redis-teardown')();

test('a bounce that fails to parse leaves no half-read download behind', async () => {
    const stream = new PassThrough();
    stream.write('Received: by mx.example.com\r\n');
    const notifications = [];
    const logger = createMockLogger();
    logger.child = () => logger;

    const ctx = Object.assign(Object.create(Mailbox.prototype), {
        path: 'INBOX',
        listingEntry: { path: 'INBOX', specialUse: '\\Inbox' },
        logger,
        connection: {
            account: 'test-account',
            imapClient: { download: async () => ({ content: stream }) },
            notifyFrom: false,
            redis: { pfadd: async () => 1 },
            getImapConnection: async () => ({ fetchOne: async () => ({ uid: 42, flags: new Set() }) }),
            mightBeAComplaint: () => false,
            mightBeDSNResponse: () => false,
            mightBeABounce: () => true,
            async notify(mailbox, event, data) {
                notifications.push({ event, data });
            }
        },
        getMessageInfo: async () => ({ id: 'AAAAAQAAAAI', uid: 42, headers: {} }),
        getSeenMessagesKey: () => 'seen:test-account:INBOX'
    });

    await ctx.processNew({ uid: 42, flags: new Set() }, {}, {});

    assert.deepEqual(
        logger.entries.filter(entry => entry.level === 'error').map(entry => entry.msg),
        ['Failed to process potential bounce']
    );
    assert.ok(stream.destroyed, 'the download stream is destroyed');
    assert.equal(notifications.length, 1, 'the message is still announced');
});
