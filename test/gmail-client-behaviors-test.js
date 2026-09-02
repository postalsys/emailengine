'use strict';

// Hermetic unit tests for GmailClient behaviors that were fixed in the client review: the
// background timers re-arming after an authentication error clears, moveMessage() leaving the
// source folder when no source is given, bulk updates paging through the whole result set in
// batchModify-sized chunks, a message deleted before its history entry is processed being
// reported as missing, and the sync path fetching without the bounce lookup only the API
// response reads. The client is built with empty options and only the collaborators each
// method touches are stubbed.

const test = require('node:test');
const assert = require('node:assert').strict;

const { GmailClient } = require('../lib/email-client/gmail-client');
const { MESSAGE_MISSING_NOTIFY } = require('../lib/consts');
const { redis } = require('../lib/db');
const registerRedisTeardown = require('./helpers/redis-teardown');
const { noopLogger } = require('./helpers/auth-failure');

registerRedisTeardown(redis);

function makeClient() {
    const gmail = new GmailClient('test-account', {});
    gmail.logger = noopLogger;
    gmail.prepare = async () => {};
    gmail.setStateVal = async () => {};
    return gmail;
}

test('GmailClient.getToken() after an authentication error', async t => {
    function makeRecoveringClient(state) {
        const gmail = makeClient();
        gmail.state = state;
        gmail.accountObject = { getActiveAccessTokenData: async () => ({ accessToken: 'tok', cached: true }) };
        return gmail;
    }

    await t.test('re-arms the watch renewal and fallback polling timers', async () => {
        const gmail = makeRecoveringClient('authenticationError');
        gmail.backgroundTimersArmed = true;

        assert.equal(await gmail.getToken(), 'tok');

        assert.equal(gmail.state, 'connected');
        assert.ok(gmail.renewWatchTimer, 'the watch renewal timer must be running again');
        assert.ok(gmail.fallbackPollingTimer, 'the fallback polling timer must be running again');
        clearTimeout(gmail.renewWatchTimer);
        clearTimeout(gmail.fallbackPollingTimer);
    });

    await t.test('leaves a send-only account (timers never armed) without timers', async () => {
        const gmail = makeRecoveringClient('authenticationError');

        await gmail.getToken();

        assert.equal(gmail.state, 'connected');
        assert.ok(!gmail.renewWatchTimer);
        assert.ok(!gmail.fallbackPollingTimer);
    });

    await t.test('does not touch the timers while connected', async () => {
        const gmail = makeRecoveringClient('connected');
        gmail.backgroundTimersArmed = true;

        await gmail.getToken();

        assert.ok(!gmail.renewWatchTimer);
        assert.ok(!gmail.fallbackPollingTimer);
    });
});

test('GmailClient.moveMessage()', async t => {
    function makeMoveClient(labelIds) {
        const gmail = makeClient();
        const calls = [];
        gmail.getLabel = async path => ({ Projects: { id: 'Label_1' }, INBOX: { id: 'INBOX' } })[path] || null;
        gmail.request = async (url, method, payload) => {
            calls.push({ url, method, payload });
            if (method === 'get') {
                return { id: 'm1', labelIds };
            }
            return { id: 'm1', labelIds: ['Label_1'] };
        };
        return { gmail, calls };
    }

    await t.test('without a source it drops the system folder labels the message carries', async () => {
        const { gmail, calls } = makeMoveClient(['INBOX', 'UNREAD', 'IMPORTANT', 'Label_9']);

        const result = await gmail.moveMessage('m1', { path: 'Projects' });

        assert.deepEqual(result, { path: 'Projects', id: 'm1' });
        const modify = calls.find(call => /\/messages\/m1\/modify$/.test(call.url));
        assert.ok(modify, 'expected a modify call');
        assert.deepEqual(modify.payload, { addLabelIds: ['Label_1'], removeLabelIds: ['INBOX'] });
    });

    await t.test('with a source it removes exactly that label and does not read the message', async () => {
        const { gmail, calls } = makeMoveClient(['INBOX']);

        await gmail.moveMessage('m1', { path: 'Projects' }, { source: { path: 'INBOX' } });

        assert.ok(!calls.some(call => call.method === 'get'), 'no lookup is needed when the source is known');
        const modify = calls.find(call => /\/modify$/.test(call.url));
        assert.deepEqual(modify.payload, { addLabelIds: ['Label_1'], removeLabelIds: ['INBOX'] });
    });

    await t.test('moving to the Inbox from Trash removes TRASH and keeps the target', async () => {
        const { gmail, calls } = makeMoveClient(['TRASH', 'Label_9']);

        await gmail.moveMessage('m1', { path: 'INBOX' });

        const modify = calls.find(call => /\/modify$/.test(call.url));
        assert.deepEqual(modify.payload, { addLabelIds: ['INBOX'], removeLabelIds: ['TRASH'] });
    });
});

test('GmailClient.updateMessages()', async t => {
    await t.test('pages through every match and applies them in batchModify-sized chunks', async () => {
        const gmail = makeClient();
        gmail.getLabel = async () => ({ id: 'INBOX' });

        const pages = [
            { messages: Array.from({ length: 600 }, (v, i) => ({ id: `a${i}` })), nextPageCursor: 'page-2' },
            { messages: Array.from({ length: 600 }, (v, i) => ({ id: `b${i}` })), nextPageCursor: null }
        ];
        const listCalls = [];
        gmail.listMessages = async query => {
            listCalls.push(query.cursor);
            return pages[listCalls.length - 1];
        };

        const modifyCalls = [];
        gmail.request = async (url, method, payload) => {
            modifyCalls.push(payload);
            return '';
        };

        const result = await gmail.updateMessages('INBOX', {}, { flags: { add: ['\\Seen'] } });

        assert.deepEqual(listCalls, [undefined, 'page-2']);
        assert.equal(result.emailIds.length, 1200, 'used to be truncated to 1000');
        assert.deepEqual(
            modifyCalls.map(call => call.ids.length),
            [1000, 200]
        );
        assert.ok(modifyCalls.every(call => call.removeLabelIds.includes('UNREAD')));
    });
});

test('GmailClient.prepareNewMessage()', async t => {
    await t.test('reports a message deleted before its history entry was processed as missing', async () => {
        const gmail = makeClient();
        const notifications = [];
        gmail.getMessage = async () => {
            throw Object.assign(new Error('Requested entity was not found'), { statusCode: 404 });
        };
        gmail.notify = async (mailbox, event, data) => notifications.push({ event, data });

        const messageData = await gmail.prepareNewMessage({ id: 'gone' }, {});

        assert.equal(messageData, undefined);
        assert.deepEqual(notifications, [{ event: MESSAGE_MISSING_NOTIFY, data: { id: 'gone' } }]);
    });

    await t.test('any other fetch failure still propagates', async () => {
        const gmail = makeClient();
        gmail.getMessage = async () => {
            throw Object.assign(new Error('Backend Error'), { statusCode: 500 });
        };
        gmail.notify = async () => assert.fail('nothing to notify about');

        await assert.rejects(gmail.prepareNewMessage({ id: 'm1' }, {}), /Backend Error/);
    });
});

test('GmailClient.getMessage() bounce lookup', async t => {
    function makeFetchClient() {
        const gmail = makeClient();
        let lookups = 0;
        gmail.request = async () => ({ id: 'm1' });
        gmail.formatMessage = () => ({ id: 'm1', messageId: '<m1@example.com>' });
        gmail.resolveLabels = async () => {};
        gmail.attachBounces = async () => lookups++;
        return { gmail, lookups: () => lookups };
    }

    await t.test('an API fetch attaches the recorded bounces', async () => {
        const { gmail, lookups } = makeFetchClient();

        await gmail.getMessage('m1', {});

        assert.equal(lookups(), 1);
    });

    await t.test('the sync path fetches without the lookup it never reads', async () => {
        const { gmail, lookups } = makeFetchClient();

        const messageData = await gmail.prepareNewMessage({ id: 'm1' }, {});

        assert.equal(messageData.id, 'm1');
        assert.equal(lookups(), 0);
    });
});
