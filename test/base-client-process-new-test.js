'use strict';

// BaseClient.processNew(), the arrival path of the Gmail API and MS Graph clients, for the parts
// test/process-new-enrichment-test.js does not cover: an abuse report from the attachment download
// to the complaint event, the calendar step, the order of the checks, and where the notification
// says the message was found (a message carrying its own path is announced there, with the path
// taken off the payload: the Outlook client relies on that).

const test = require('node:test');
const assert = require('node:assert').strict;
const fs = require('node:fs');
const path = require('node:path');
const { simpleParser } = require('mailparser');

require('./helpers/mock-db').installDbMock({
    redis: { hget: async () => null, hgetall: async () => ({}), hset: async () => 1, pfadd: async () => 1, set: async () => 'OK', del: async () => 1 }
});

const settingsValues = {};
const settings = require('../lib/settings');
settings.get = async key => settingsValues[key];
settings.getMulti = async (...keys) => Object.fromEntries(await Promise.all(keys.map(async key => [key, await settings.get(key)])));

let bounceResult = null;
const bounceDetectModule = require('../lib/bounce-detect');
bounceDetectModule.bounceDetect = async () => bounceResult;

const { BaseClient } = require('../lib/email-client/base-client');
const { createMockLogger } = require('./helpers/mock-logger');

require('./helpers/redis-teardown')();

const ICS = [
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

function createClient({ attachments = {}, raw = Buffer.from('Subject: x\r\n\r\nhello\r\n'), calls = {} } = {}) {
    const notifications = [];
    const steps = [];
    const logger = createMockLogger();
    const ctx = Object.assign(Object.create(BaseClient.prototype), {
        account: 'test-account',
        path: 'INBOX',
        listingEntry: { path: 'INBOX', specialUse: '\\Inbox' },
        logger,
        redis: { set: async () => 'OK', del: async () => 1 },
        getRawMessage: async id => {
            steps.push(`raw:${id}`);
            if (raw instanceof Error) {
                throw raw;
            }
            return raw;
        },
        getAttachment: async id => {
            steps.push(`attachment:${id}`);
            if (!(id in attachments)) {
                throw new Error('No such attachment');
            }
            return { data: Buffer.from(attachments[id]) };
        },
        call: async message => {
            steps.push(`call:${message.cmd}`);
            return calls[message.cmd] || {};
        },
        notify: async (target, event, data) => {
            notifications.push({ target, event, data: structuredClone(data) });
        }
    });
    const logged = level => logger.entries.filter(entry => entry.level === level).map(entry => entry.msg);
    return { ctx, notifications, steps, logged };
}

const events = notifications => notifications.map(entry => entry.event);

test('BaseClient.processNew() abuse reports', async t => {
    const source = fs.readFileSync(path.join(__dirname, 'fixtures', 'complaints', 'standard-arf.eml'));
    const parsed = await simpleParser(source, { keepDeliveryStatus: true });
    const attachments = Object.fromEntries(parsed.attachments.map((attachment, i) => [`att-${i}`, attachment.content]));
    const message = () => ({
        id: 'msg-1',
        messageSpecialUse: '\\Inbox',
        from: parsed.from.value[0],
        subject: parsed.subject,
        attachments: parsed.attachments.map((attachment, i) => ({ id: `att-${i}`, contentType: attachment.contentType }))
    });

    await t.test('the report parts are downloaded, parsed and announced after the message', async () => {
        const { ctx, notifications, steps } = createClient({ attachments });
        const messageData = message();

        await ctx.processNew(messageData, {});

        assert.deepEqual(
            steps.filter(step => step.startsWith('attachment:')),
            Object.keys(attachments).map(id => `attachment:${id}`)
        );
        assert.deepEqual(events(notifications), ['messageNew', 'messageComplaint']);
        assert.equal(notifications[0].data.isComplaint, true);
        assert.equal(notifications[1].target, false);
        assert.equal(notifications[1].data.complaintMessage, 'msg-1');
        assert.equal(notifications[1].data.arf.feedbackType, 'abuse');
        assert.ok(notifications[1].data.arf.originalRcptTo.includes('kijitora@example.com'));
        // the report content is kept off the payload
        assert.ok(messageData.attachments.every(attachment => !Object.keys(attachment).includes('content')));
        assert.ok(typeof messageData.attachments[0].content === 'string');
    });

    await t.test('a message outside the Inbox is not checked', async () => {
        const { ctx, notifications, steps } = createClient({ attachments });

        await ctx.processNew(Object.assign(message(), { messageSpecialUse: '\\Junk' }), {});

        assert.deepEqual(steps, []);
        assert.deepEqual(events(notifications), ['messageNew']);
    });

    await t.test('a failed download is logged and the message still announced', async () => {
        const { ctx, notifications, logged } = createClient({ attachments: {} });

        await ctx.processNew(message(), {});

        assert.deepEqual(logged('error'), ['Failed to process ARF']);
        assert.deepEqual(events(notifications), ['messageNew']);
    });
});

test('BaseClient.processNew() checks', async t => {
    t.beforeEach(() => {
        bounceResult = null;
    });

    const dsnMessage = id => ({
        id,
        messageSpecialUse: '\\Inbox',
        from: { address: 'mailer-daemon@example.com', name: 'Mail Delivery System' },
        headers: { 'content-type': ['multipart/report; report-type=delivery-status; boundary="b"'] }
    });

    await t.test('a parsed delivery report settles it, the bounce check is skipped', async () => {
        bounceResult = { action: 'failed', recipient: 'user@example.com', messageId: '<orig@example.com>' };
        const raw = fs.readFileSync(path.join(__dirname, 'fixtures', 'bounces', 'delayed.eml'));
        const { ctx, notifications, steps } = createClient({ raw });
        const messageData = dsnMessage('msg-2');

        await ctx.processNew(messageData, {});

        assert.deepEqual(steps, ['raw:msg-2']);
        assert.equal(messageData.deliveryReport?.action, 'delayed');
        assert.deepEqual(events(notifications), ['messageNew']);
    });

    await t.test('the bounce check reuses the message the delivery report check read', async () => {
        bounceResult = { action: 'failed', recipient: 'user@example.com', messageId: '<orig@example.com>', response: { message: '550 no such user' } };
        const { ctx, notifications, steps } = createClient({ calls: { bounceClassify: { label: 'unknown_user', action: 'remove' } } });
        const messageData = dsnMessage('msg-2b');

        await ctx.processNew(messageData, {});

        assert.deepEqual(steps, ['raw:msg-2b', 'call:bounceClassify']);
        assert.equal(messageData.isBounce, true);
        assert.equal(messageData.relatedMessageId, '<orig@example.com>');
        assert.deepEqual(events(notifications), ['messageNew', 'messageBounce']);
        assert.equal(notifications[1].data.bounceMessage, 'msg-2b');
        assert.equal(notifications[1].data.response.category, 'unknown_user');
        assert.equal(notifications[1].data.response.recommendedAction, 'remove');
    });

    await t.test('a bounce with no delivery report downloads the message itself', async () => {
        bounceResult = { action: 'failed', recipient: 'user@example.com', messageId: '<orig@example.com>' };
        const { ctx, notifications, steps } = createClient();

        await ctx.processNew({ id: 'msg-3', messageSpecialUse: '\\Junk', from: { address: 'mailer-daemon@example.com', name: 'Mail Delivery System' } }, {});

        assert.deepEqual(steps, ['raw:msg-3']);
        assert.deepEqual(events(notifications), ['messageNew', 'messageBounce']);
    });

    await t.test('a message the provider returns no source for is neither parsed nor downloaded again', async () => {
        const { ctx, notifications, steps, logged } = createClient({ raw: null });

        await ctx.processNew(dsnMessage('msg-5'), {});

        assert.deepEqual(steps, ['raw:msg-5']);
        assert.deepEqual(logged('error'), []);
        assert.deepEqual(events(notifications), ['messageNew']);
    });

    await t.test('a failed download is logged in each check and the message announced', async () => {
        const { ctx, notifications, logged } = createClient({ raw: new Error('Gone') });

        await ctx.processNew(dsnMessage('msg-4'), {});

        assert.deepEqual(logged('error'), ['Failed to process DSN', 'Failed to process potential bounce']);
        assert.deepEqual(events(notifications), ['messageNew']);
    });
});

test('BaseClient.processNew() calendar step', async t => {
    t.afterEach(() => {
        delete settingsValues.notifyCalendarEvents;
        delete settingsValues.notifyAttachments;
    });

    await t.test('calendar parts are loaded and listed', async () => {
        settingsValues.notifyCalendarEvents = true;
        const { ctx, notifications, steps } = createClient({ attachments: { ics: ICS } });

        await ctx.processNew({ id: 'msg-5', attachments: [{ id: 'ics', contentType: 'text/calendar', encodedSize: ICS.length }] }, {});

        assert.deepEqual(steps, ['attachment:ics']);
        const [calendarEvent] = notifications[0].data.calendarEvents;
        assert.equal(calendarEvent.eventId, 'event-1');
        assert.equal(calendarEvent.summary, 'Planning');
        assert.equal(calendarEvent.filename, 'invite.ics');
        assert.equal(calendarEvent.content, Buffer.from(ICS).toString('base64'));
    });

    await t.test('a part notifyAttachments already loaded is not downloaded again', async () => {
        settingsValues.notifyCalendarEvents = true;
        settingsValues.notifyAttachments = true;
        const { ctx, notifications, steps } = createClient({ attachments: { ics: ICS } });

        await ctx.processNew({ id: 'msg-6', attachments: [{ id: 'ics', contentType: 'text/calendar', encodedSize: ICS.length }] }, {});

        assert.deepEqual(steps, ['attachment:ics']);
        assert.equal(notifications[0].data.calendarEvents.length, 1);
    });

    await t.test('a failed download leaves no calendar events and is logged', async () => {
        settingsValues.notifyCalendarEvents = true;
        const { ctx, notifications, logged } = createClient();

        await ctx.processNew({ id: 'msg-7', attachments: [{ id: 'ics', contentType: 'text/calendar', encodedSize: 100 }] }, {});

        assert.equal(notifications[0].data.calendarEvents, undefined);
        assert.deepEqual(logged('error'), ['Failed to load attachment content']);
    });

    await t.test('without the setting nothing is downloaded', async () => {
        const { ctx, notifications, steps } = createClient({ attachments: { ics: ICS } });

        await ctx.processNew({ id: 'msg-8', attachments: [{ id: 'ics', contentType: 'text/calendar', encodedSize: ICS.length }] }, {});

        assert.deepEqual(steps, []);
        assert.equal(notifications[0].data.calendarEvents, undefined);
    });
});

test('BaseClient.processNew() notification target', async t => {
    await t.test('a message with its own path is announced there, without the path in the payload', async () => {
        const { ctx, notifications } = createClient();
        const messageData = { id: 'msg-9', path: 'Archive', messageSpecialUse: '\\Archive' };

        await ctx.processNew(messageData, {});

        assert.deepEqual(notifications[0].target, { path: 'Archive', specialUse: '\\Archive' });
        assert.equal(messageData.path, undefined);
        assert.ok('path' in messageData, 'the key is cleared, not removed');
    });

    await t.test('otherwise the client folder is the target', async () => {
        const { ctx, notifications } = createClient();

        await ctx.processNew({ id: 'msg-10', messageSpecialUse: '\\Inbox' }, {});

        assert.deepEqual(notifications[0].target, { path: 'INBOX', specialUse: '\\Inbox' });
    });

    await t.test('headers are narrowed only after the checks read them', async () => {
        const { ctx, notifications } = createClient({ raw: new Error('Gone') });
        const seen = [];
        ctx.mightBeDSNResponse = messageData => {
            seen.push(Object.keys(messageData.headers));
            return false;
        };

        await ctx.processNew(
            { id: 'msg-11', messageSpecialUse: '\\Inbox', headers: { subject: ['x'], 'content-type': ['text/plain'] } },
            { headers: ['subject'] }
        );

        assert.deepEqual(seen, [['subject', 'content-type']]);
        assert.deepEqual(Object.keys(notifications[0].data.headers), ['subject']);
    });
});
