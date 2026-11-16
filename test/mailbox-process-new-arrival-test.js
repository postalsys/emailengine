'use strict';

// Mailbox.processNew() from the fetch to the notification, for the parts no other suite pins:
//
// - A message a server lists before it can be fetched (replication lag) is fetched again three
//   times with a growing wait, and reported as messageMissing when it never shows up.
// - A message older than notifyFrom, or one in a non-Inbox folder that was there before a
//   reconnect, is not announced at all, and leaves the seen-messages HyperLogLog alone.
// - On Gmail, an Inbox message in All Mail gets its category.
// - seemsLikeNew is the HyperLogLog's answer, and false for a message the account sent itself.
// - Every arrival check rethrows a gone connection, so the message stays queued instead of being
//   announced half processed; any other failure is logged and the message is still announced.

const test = require('node:test');
const assert = require('node:assert').strict;
const fs = require('node:fs');
const path = require('node:path');
const { Readable } = require('node:stream');
const mailparser = require('mailparser');
const { simpleParser } = mailparser;

// Patched before the module under test destructures it at load, so one test can make it fail
let parserFailure = null;
mailparser.simpleParser = async (input, options) => {
    if (parserFailure) {
        throw parserFailure;
    }
    return simpleParser(input, options);
};

require('./helpers/mock-db').installDbMock({
    redis: { hget: async () => null, hgetall: async () => ({}), hset: async () => 1, pfadd: async () => 1, set: async () => 'OK', del: async () => 1 }
});

const settingsValues = {};
const settings = require('../lib/settings');
settings.get = async key => settingsValues[key];
settings.getMulti = async (...keys) => Object.fromEntries(await Promise.all(keys.map(async key => [key, await settings.get(key)])));

const { Mailbox } = require('../lib/email-client/imap/mailbox');
const { createMockLogger } = require('./helpers/mock-logger');
const { withInstantSleeps } = require('./helpers/instant-timers');

require('./helpers/redis-teardown')();

const MAILBOX_FILE = path.join('imap', 'mailbox.js');

const gone = () => Object.assign(new Error('Connection not available'), { code: 'NoConnection' });

function createContext({ messages, messageInfo = {}, mailbox = {}, connection = {}, download } = {}) {
    const notifications = [];
    const fetches = [];
    const pfadds = [];
    const logger = createMockLogger();

    // What successive getMessage() calls answer; the last one repeats
    const answers = messages || [Object.assign({ id: 'AAAAAQAAAAI', uid: 42, date: new Date().toISOString(), messageSpecialUse: '\\Inbox' }, messageInfo)];

    const ctx = Object.assign(
        Object.create(Mailbox.prototype),
        {
            path: 'INBOX',
            listingEntry: { path: 'INBOX', specialUse: '\\Inbox' },
            logger,
            getSeenMessagesKey: () => 'seen:test-account:INBOX',
            async getMessage(message, options) {
                fetches.push({ uid: message.uid, options: Object.assign({}, options) });
                const answer = answers[Math.min(fetches.length - 1, answers.length - 1)];
                return answer && structuredClone(answer);
            }
        },
        mailbox
    );

    ctx.connection = Object.assign(
        {
            account: 'test-account',
            imapClient: download ? { download: async (...args) => download(...args) } : null,
            notifyFrom: false,
            redis: {
                pfadd: async (key, value) => {
                    pfadds.push({ key, value });
                    return 1;
                }
            },
            packUid: async (mb, uid) => `packed-${uid}`,
            mightBeAComplaint: () => false,
            mightBeDSNResponse: () => false,
            mightBeABounce: () => false,
            call: async () => ({}),
            async notify(target, event, data) {
                notifications.push({ target, event, data });
            }
        },
        connection
    );

    const logged = level => logger.entries.filter(entry => entry.level === level).map(entry => entry.msg);

    return { ctx, notifications, fetches, pfadds, logger, logged };
}

const run = (ctx, { uid = 42, options = {}, storedStatus = {}, categories, passSettings } = {}) =>
    ctx.processNew({ uid, flags: new Set() }, options, storedStatus, categories, passSettings);

const events = notifications => notifications.map(entry => entry.event);

test('Mailbox.processNew() replication-lag retry', async t => {
    await t.test('a message found on a later attempt is announced with the retry statistics', async () => {
        const found = { id: 'AAAAAQAAAAI', uid: 42, date: new Date().toISOString(), messageSpecialUse: '\\Inbox' };
        const { ctx, notifications, fetches } = createContext({ messages: [false, false, found] });

        const { error, delays } = await withInstantSleeps(MAILBOX_FILE, () => run(ctx));

        assert.equal(error, undefined);
        assert.deepEqual(delays, [1000, 1700]);
        assert.equal(fetches.length, 3);
        assert.deepEqual(events(notifications), ['messageNew']);
        assert.equal(notifications[0].data.missingRetries, 2);
        assert.equal(notifications[0].data.missingDelay, 2700);
    });

    await t.test('a message found at once carries no retry statistics', async () => {
        const { ctx, notifications } = createContext();

        await run(ctx);

        assert.ok(!('missingRetries' in notifications[0].data));
        assert.ok(!('missingDelay' in notifications[0].data));
    });

    await t.test('a message that never shows up is reported as messageMissing after three retries', async () => {
        const { ctx, notifications, fetches, pfadds } = createContext({ messages: [false] });

        const { error, delays } = await withInstantSleeps(MAILBOX_FILE, () => run(ctx));

        assert.equal(error, undefined);
        assert.deepEqual(delays, [1000, 1700, 2890]);
        assert.equal(fetches.length, 4);
        assert.deepEqual(notifications, [{ target: ctx, event: 'messageMissing', data: { id: 'packed-42', uid: 42, missingRetries: 3, missingDelay: 5590 } }]);
        assert.deepEqual(pfadds, []);
    });

    await t.test('nothing is sent when the missing message cannot be given an id', async () => {
        const { ctx, notifications, logged } = createContext({ messages: [false], connection: { packUid: async () => false } });

        await withInstantSleeps(MAILBOX_FILE, () => run(ctx));

        assert.deepEqual(notifications, []);
        assert.deepEqual(logged('warn'), ['Skipping notification, packUid returned invalid result']);
    });

    await t.test('the fetch asks for the headers the checks need and never takes a lock', async () => {
        const { ctx, fetches, notifications } = createContext({ messageInfo: { headers: { subject: ['x'], 'content-type': ['y'] } } });

        await run(ctx, { options: { headers: ['subject'], fetchHeaders: ['subject', 'content-type'] } });

        assert.deepEqual(fetches[0].options.headers, ['subject', 'content-type']);
        assert.equal(fetches[0].options.skipLock, true);
        assert.deepEqual(Object.keys(notifications[0].data.headers), ['subject']);
    });

    await t.test('without fetchHeaders, headers default to none', async () => {
        const { ctx, fetches } = createContext();

        await run(ctx);

        assert.equal(fetches[0].options.headers, false);
    });
});

test('Mailbox.processNew() skips', async t => {
    await t.test('a message older than notifyFrom is not announced', async () => {
        const { ctx, notifications, pfadds } = createContext({
            messageInfo: { date: '2020-01-01T00:00:00.000Z' },
            connection: { notifyFrom: new Date('2021-01-01T00:00:00.000Z') }
        });

        await run(ctx);

        assert.deepEqual(notifications, []);
        assert.deepEqual(pfadds, []);
    });

    await t.test('a message newer than notifyFrom is announced', async () => {
        const { ctx, notifications } = createContext({
            messageInfo: { date: '2022-01-01T00:00:00.000Z' },
            connection: { notifyFrom: new Date('2021-01-01T00:00:00.000Z') }
        });

        await run(ctx);

        assert.deepEqual(events(notifications), ['messageNew']);
    });

    await t.test('after a reconnect, an old message in another folder is not announced', async () => {
        const { ctx, notifications, pfadds, logged } = createContext({ mailbox: { path: 'Archive', previouslyConnected: 1 } });

        await run(ctx, { uid: 42, storedStatus: { initialUidNext: 50 } });

        assert.deepEqual(notifications, []);
        assert.deepEqual(pfadds, []);
        assert.deepEqual(
            logged('debug').filter(msg => msg === 'Skip old message'),
            ['Skip old message']
        );
    });

    await t.test('a message at or above the UIDNEXT seen at connect is announced', async () => {
        const { ctx, notifications } = createContext({ mailbox: { path: 'Archive', previouslyConnected: 1 } });

        await run(ctx, { uid: 50, storedStatus: { initialUidNext: 50 } });

        assert.deepEqual(events(notifications), ['messageNew']);
    });

    await t.test('the Inbox, All Mail and a first connection are never skipped that way', async () => {
        for (const mailbox of [
            { path: 'Inbox', previouslyConnected: 1 },
            { path: 'Archive', previouslyConnected: 1, isAllMail: true },
            { path: 'Archive', previouslyConnected: 0 }
        ]) {
            const { ctx, notifications } = createContext({ mailbox });
            await run(ctx, { uid: 42, storedStatus: { initialUidNext: 50 } });
            assert.deepEqual(events(notifications), ['messageNew'], JSON.stringify(mailbox));
        }
    });
});

test('Mailbox.processNew() Gmail category', async t => {
    const gmail = (extra = {}) =>
        createContext({
            messageInfo: { labels: ['\\Inbox'] },
            mailbox: Object.assign({ isAllMail: true }, extra.mailbox),
            connection: { imapClient: { capabilities: new Set(['X-GM-EXT-1']) } }
        });
    const passSettings = { resolveGmailCategories: true };

    await t.test('an Inbox message in All Mail gets the category the resolver names', async () => {
        const { ctx, notifications } = gmail();
        const asked = [];

        await run(ctx, {
            passSettings,
            categories: {
                categoryOf: async uid => {
                    asked.push(uid);
                    return 'social';
                }
            }
        });

        assert.deepEqual(asked, [42]);
        assert.equal(notifications[0].data.category, 'social');
    });

    await t.test('without a resolver from the pass, one is made for the message', async () => {
        const { ctx, notifications } = gmail({ mailbox: { createCategoryResolver: () => ({ categoryOf: async () => 'promotions' }) } });

        await run(ctx, { passSettings });

        assert.equal(notifications[0].data.category, 'promotions');
    });

    await t.test('no category when the setting is off, the label is missing or the server is not Gmail', async () => {
        const categories = { categoryOf: async () => 'social' };

        const off = gmail();
        await run(off.ctx, { passSettings: { resolveGmailCategories: false }, categories });
        assert.equal(off.notifications[0].data.category, undefined);

        const notInbox = createContext({
            messageInfo: { labels: ['\\Important'] },
            mailbox: { isAllMail: true },
            connection: { imapClient: { capabilities: new Set(['X-GM-EXT-1']) } }
        });
        await run(notInbox.ctx, { passSettings, categories });
        assert.equal(notInbox.notifications[0].data.category, undefined);

        const notGmail = createContext({
            messageInfo: { labels: ['\\Inbox'] },
            mailbox: { isAllMail: true },
            connection: { imapClient: { capabilities: new Set() } }
        });
        await run(notGmail.ctx, { passSettings, categories });
        assert.equal(notGmail.notifications[0].data.category, undefined);
    });

    await t.test('a failed lookup is logged and the message still announced', async () => {
        const { ctx, notifications, logged } = gmail();

        await run(ctx, {
            passSettings,
            categories: {
                categoryOf: async () => {
                    throw new Error('Search failed');
                }
            }
        });

        assert.deepEqual(logged('warn'), ['Failed to resolve category for message']);
        assert.deepEqual(events(notifications), ['messageNew']);
    });

    await t.test('a gone connection during the lookup keeps the message queued', async () => {
        const { ctx, notifications } = gmail();

        await assert.rejects(
            run(ctx, {
                passSettings,
                categories: {
                    categoryOf: async () => {
                        throw gone();
                    }
                }
            }),
            { code: 'NoConnection' }
        );
        assert.deepEqual(notifications, []);
    });
});

test('Mailbox.processNew() seemsLikeNew', async t => {
    await t.test('a message the HyperLogLog had not counted seems new', async () => {
        const { ctx, notifications, pfadds } = createContext({ messageInfo: { emailId: 'e-1', messageId: '<m@x>' } });

        await run(ctx);

        assert.deepEqual(pfadds, [{ key: 'seen:test-account:INBOX', value: 'e-1' }]);
        assert.equal(notifications[0].data.seemsLikeNew, true);
    });

    await t.test('a message counted before does not, and the Message-ID is used without an emailId', async () => {
        const pfadds = [];
        const { ctx, notifications } = createContext({
            messageInfo: { messageId: '<m@x>' },
            connection: {
                redis: {
                    pfadd: async (key, value) => {
                        pfadds.push(value);
                        return 0;
                    }
                }
            }
        });

        await run(ctx);

        assert.deepEqual(pfadds, ['<m@x>']);
        assert.equal(notifications[0].data.seemsLikeNew, false);
    });

    await t.test('a message the account sent itself never seems new and is not counted', async () => {
        const { ctx, notifications, pfadds } = createContext({ mailbox: { listingEntry: { path: 'Sent', specialUse: '\\Sent' } } });

        await run(ctx);

        assert.deepEqual(pfadds, []);
        assert.equal(notifications[0].data.seemsLikeNew, false);
    });
});

test('Mailbox.processNew() arrival checks', async t => {
    const arfSource = fs.readFileSync(path.join(__dirname, 'fixtures', 'complaints', 'standard-arf.eml'));
    const parsedArf = await simpleParser(arfSource, { keepDeliveryStatus: true });
    const partId = part => Buffer.concat([Buffer.alloc(8), Buffer.from(part)]).toString('base64url');
    const arfParts = Object.fromEntries(parsedArf.attachments.map((attachment, i) => [String(i + 2), attachment]));
    const arfMessage = {
        from: parsedArf.from.value[0],
        subject: parsedArf.subject,
        attachments: Object.entries(arfParts).map(([part, attachment]) => ({ id: partId(part), contentType: attachment.contentType }))
    };

    await t.test('an abuse report is announced with its complaint after the message', async () => {
        const downloads = [];
        const { ctx, notifications } = createContext({
            messageInfo: arfMessage,
            connection: { mightBeAComplaint: () => true },
            download: async (uid, part, opts) => {
                downloads.push({ part, maxBytes: opts.maxBytes });
                return { content: Readable.from([arfParts[part].content]) };
            }
        });

        await run(ctx);

        assert.deepEqual(
            downloads.map(entry => entry.part),
            Object.keys(arfParts)
        );
        assert.ok(downloads.every(entry => entry.maxBytes === 1024 * 1024));
        assert.deepEqual(events(notifications), ['messageNew', 'messageComplaint']);
        assert.equal(notifications[0].data.isComplaint, true);
        assert.equal(notifications[1].data.complaintMessage, 'AAAAAQAAAAI');
        assert.ok(notifications[1].data.arf.originalRcptTo.includes('kijitora@example.com'));
        assert.ok(
            notifications[0].data.attachments.every(attachment => !Object.keys(attachment).includes('content')),
            'the downloaded report is not part of the payload'
        );
    });

    for (const [check, flag] of [
        ['complaint', 'mightBeAComplaint'],
        ['delivery report', 'mightBeDSNResponse'],
        ['bounce', 'mightBeABounce']
    ]) {
        await t.test(`a gone connection in the ${check} check keeps the message queued`, async () => {
            const { ctx, notifications } = createContext({
                messageInfo: arfMessage,
                connection: { [flag]: () => true },
                download: async () => {
                    throw gone();
                }
            });

            await assert.rejects(run(ctx), { code: 'NoConnection' });
            assert.deepEqual(notifications, []);
        });

        await t.test(`any other failure in the ${check} check is logged and the message announced`, async () => {
            const { ctx, notifications, logged } = createContext({
                messageInfo: arfMessage,
                connection: { [flag]: () => true },
                download: async () => {
                    throw new Error('Unexpected server answer');
                }
            });

            await run(ctx);

            assert.equal(logged('error').length, 1);
            assert.deepEqual(events(notifications), ['messageNew']);
        });
    }

    await t.test('a delivery report stream the parser left unread is destroyed', async () => {
        const stream = new Readable({ read() {} });
        stream.push('Content-Type: multipart/report; report-type=delivery-status; boundary="b"\r\n\r\n');
        parserFailure = new Error('Parser failure');
        try {
            const { ctx, notifications, logged } = createContext({
                connection: { mightBeDSNResponse: () => true },
                download: async () => ({ content: stream })
            });

            await run(ctx);

            assert.deepEqual(logged('error'), ['Failed to process DSN']);
            assert.ok(stream.destroyed);
            assert.deepEqual(events(notifications), ['messageNew']);
        } finally {
            parserFailure = null;
        }
    });

    await t.test('the calendar step loads and parses a calendar part', async () => {
        settingsValues.notifyCalendarEvents = true;
        try {
            const ics = [
                'BEGIN:VCALENDAR',
                'VERSION:2.0',
                'METHOD:REQUEST',
                'BEGIN:VEVENT',
                'UID:event-1',
                'SUMMARY:Planning',
                'DTSTART:20260101T100000Z',
                'DTEND:20260101T110000Z',
                'END:VEVENT',
                'END:VCALENDAR'
            ].join('\r\n');
            const { ctx, notifications } = createContext({
                messageInfo: { attachments: [{ id: partId('2'), contentType: 'text/calendar', encodedSize: ics.length }] },
                connection: {
                    imapClient: {
                        download: async () => ({ content: Readable.from([Buffer.from(ics)]) })
                    }
                }
            });

            await run(ctx);

            assert.equal(notifications[0].data.calendarEvents.length, 1);
            assert.equal(notifications[0].data.calendarEvents[0].eventId, 'event-1');
            assert.equal(notifications[0].data.calendarEvents[0].filename, 'invite.ics');
        } finally {
            delete settingsValues.notifyCalendarEvents;
        }
    });
});
