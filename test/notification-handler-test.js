'use strict';

// Unit tests for lib/email-client/notification-handler.js. The pure, hermetic
// surfaces are covered here: payload assembly (buildPayload) and the metrics
// post error path (postMetrics). The queue/webhook round-trips are
// intentionally out of scope.

const test = require('node:test');
const assert = require('node:assert').strict;

const { NotificationHandler, postMetrics } = require('../lib/email-client/notification-handler');
const { MESSAGE_NEW_NOTIFY } = require('../lib/consts');
const { redis } = require('../lib/db');
const registerRedisTeardown = require('./helpers/redis-teardown');

registerRedisTeardown(redis);

const noopLogger = { trace() {}, debug() {}, info() {}, warn() {}, error() {} };

function makeHandler(overrides) {
    return new NotificationHandler(Object.assign({ account: 'acc-1', logger: noopLogger }, overrides));
}

test('buildPayload', async t => {
    const handler = makeHandler();

    await t.test('assembles the full payload', () => {
        const payload = handler.buildPayload(
            { path: 'INBOX', listingEntry: { specialUse: '\\Inbox' } },
            MESSAGE_NEW_NOTIFY,
            { id: 'm1' },
            'https://ee.example'
        );
        assert.strictEqual(payload.account, 'acc-1');
        assert.strictEqual(payload.serviceUrl, 'https://ee.example');
        assert.strictEqual(payload.path, 'INBOX');
        assert.strictEqual(payload.specialUse, '\\Inbox');
        assert.strictEqual(payload.event, MESSAGE_NEW_NOTIFY);
        assert.deepStrictEqual(payload.data, { id: 'm1' });
        assert.match(payload.date, /^\d{4}-\d{2}-\d{2}T.*Z$/);
    });

    await t.test('falls back to data.path when the mailbox has no path', () => {
        const payload = handler.buildPayload({}, MESSAGE_NEW_NOTIFY, { path: 'Sent' }, null);
        assert.strictEqual(payload.path, 'Sent');
    });

    await t.test('omits path/specialUse/data when not present', () => {
        const payload = handler.buildPayload(null, MESSAGE_NEW_NOTIFY, undefined, null);
        assert.ok(!('path' in payload));
        assert.ok(!('specialUse' in payload));
        assert.ok(!('data' in payload));
        assert.strictEqual(payload.serviceUrl, null);
        assert.strictEqual(payload.event, MESSAGE_NEW_NOTIFY);
    });

    await t.test('omits specialUse when listingEntry lacks it', () => {
        const payload = handler.buildPayload({ path: 'INBOX', listingEntry: {} }, MESSAGE_NEW_NOTIFY, { id: 'x' }, null);
        assert.strictEqual(payload.path, 'INBOX');
        assert.ok(!('specialUse' in payload));
    });
});

test('postMetrics', async t => {
    await t.test('never throws into the caller and routes a failed post to the logger', () => {
        // Contract: metrics are best-effort, so postMetrics must swallow any failure
        // and report it through the supplied logger rather than propagating. Under the
        // test runner this executes on the main thread where worker_threads.parentPort
        // is null, so the postMessage call fails - the same graceful-degradation path
        // that must hold whenever the parent port is unavailable.
        let errors = 0;
        const logger = { error: () => errors++ };
        assert.doesNotThrow(() => postMetrics({ account: 'a' }, logger, 'events', 'inc', { event: 'x' }));
        assert.strictEqual(errors, 1);
    });
});

test('buildPayload specialUse for API clients', async t => {
    await t.test('reads specialUse off a plain { path, specialUse } mailbox object', () => {
        // The Gmail API and Graph clients pass this shape instead of an IMAP Mailbox with a
        // listingEntry, and their webhooks used to lack the top-level specialUse
        const payload = makeHandler().buildPayload({ path: 'Sent Items', specialUse: '\\Sent' }, MESSAGE_NEW_NOTIFY, { id: 'm1' }, null);
        assert.strictEqual(payload.path, 'Sent Items');
        assert.strictEqual(payload.specialUse, '\\Sent');
    });

    await t.test('the listing entry still wins when both are present', () => {
        const payload = makeHandler().buildPayload(
            { path: 'INBOX', specialUse: '\\Sent', listingEntry: { specialUse: '\\Inbox' } },
            MESSAGE_NEW_NOTIFY,
            {},
            null
        );
        assert.strictEqual(payload.specialUse, '\\Inbox');
    });
});

test('notify', async t => {
    const { webhooks } = require('../lib/webhooks');
    const savedFormatPayload = Object.prototype.hasOwnProperty.call(webhooks, 'formatPayload') ? webhooks.formatPayload : undefined;
    const savedPushToQueue = Object.prototype.hasOwnProperty.call(webhooks, 'pushToQueue') ? webhooks.pushToQueue : undefined;
    t.after(() => {
        for (const [name, saved] of [
            ['formatPayload', savedFormatPayload],
            ['pushToQueue', savedPushToQueue]
        ]) {
            if (saved) {
                webhooks[name] = saved;
            } else {
                delete webhooks[name];
            }
        }
    });

    await t.test('queues the formatted payload for webhook delivery', async () => {
        const pushed = [];
        webhooks.formatPayload = async (event, payload) => Object.assign({ formatted: true }, payload);
        webhooks.pushToQueue = async (event, payload) => pushed.push({ event, payload });

        await makeHandler().notify({ path: 'INBOX' }, MESSAGE_NEW_NOTIFY, { id: 'm1' });

        assert.strictEqual(pushed.length, 1);
        assert.strictEqual(pushed[0].event, MESSAGE_NEW_NOTIFY);
        assert.strictEqual(pushed[0].payload.formatted, true);
        assert.strictEqual(pushed[0].payload.account, 'acc-1');
        assert.deepStrictEqual(pushed[0].payload.data, { id: 'm1' });
    });
});
