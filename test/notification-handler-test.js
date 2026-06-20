'use strict';

// Unit tests for lib/email-client/notification-handler.js. The pure, hermetic
// surfaces are covered here: payload assembly (buildPayload), BullMQ job-option
// derivation and retention (buildJobOptions), the document-store gating
// short-circuits (shouldSyncDocuments), the metrics post error path
// (postMetrics), and the thread-id early returns (generateThreadId). The
// queue/webhook/ElasticSearch round-trips are intentionally out of scope.

const test = require('node:test');
const assert = require('node:assert').strict;

const {
    NotificationHandler,
    DOCUMENT_SYNC_EVENTS,
    DEFAULT_JOB_OPTIONS,
    DOCUMENT_JOB_OPTIONS,
    postMetrics
} = require('../lib/email-client/notification-handler');
const {
    MESSAGE_NEW_NOTIFY,
    MESSAGE_DELETED_NOTIFY,
    MESSAGE_UPDATED_NOTIFY,
    EMAIL_BOUNCE_NOTIFY,
    MAILBOX_DELETED_NOTIFY,
    AUTH_ERROR_NOTIFY
} = require('../lib/consts');
const { redis } = require('../lib/db');
const registerRedisTeardown = require('./helpers/redis-teardown');

registerRedisTeardown(redis);

const noopLogger = { trace() {}, debug() {}, info() {}, warn() {}, error() {} };

function makeHandler(overrides) {
    return new NotificationHandler(Object.assign({ account: 'acc-1', logger: noopLogger, flowProducer: {}, documentsQueue: {} }, overrides));
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

test('buildJobOptions', async t => {
    const handler = makeHandler();

    await t.test('maps a numeric queueKeep to age+count retention', () => {
        const opts = handler.buildJobOptions(500);
        const retention = { age: 24 * 3600, count: 500 };
        assert.deepStrictEqual(opts.notify.removeOnComplete, retention);
        assert.deepStrictEqual(opts.notify.removeOnFail, retention);
        assert.deepStrictEqual(opts.documents.removeOnComplete, retention);
        // Attempt counts come from the respective base option sets.
        assert.strictEqual(opts.notify.attempts, 10);
        assert.strictEqual(opts.documents.attempts, 16);
    });

    await t.test('passes a boolean queueKeep through unchanged', () => {
        const opts = handler.buildJobOptions(true);
        assert.strictEqual(opts.notify.removeOnComplete, true);
        assert.strictEqual(opts.notify.removeOnFail, true);
        assert.strictEqual(opts.documents.removeOnComplete, true);
    });

    await t.test('does not mutate the shared base option objects', () => {
        const beforeDefault = JSON.stringify(DEFAULT_JOB_OPTIONS);
        const beforeDocument = JSON.stringify(DOCUMENT_JOB_OPTIONS);
        handler.buildJobOptions(7);
        assert.strictEqual(JSON.stringify(DEFAULT_JOB_OPTIONS), beforeDefault);
        assert.strictEqual(JSON.stringify(DOCUMENT_JOB_OPTIONS), beforeDocument);
        // The base retention is unchanged (count 1000), proving a copy was made.
        assert.strictEqual(DEFAULT_JOB_OPTIONS.removeOnComplete.count, 1000);
    });
});

test('shouldSyncDocuments gating', async t => {
    await t.test('returns false when canSync is false', async () => {
        assert.strictEqual(await makeHandler().shouldSyncDocuments(MESSAGE_NEW_NOTIFY, false), false);
    });

    await t.test('returns false when there is no documents queue', async () => {
        assert.strictEqual(await makeHandler({ documentsQueue: null }).shouldSyncDocuments(MESSAGE_NEW_NOTIFY, true), false);
    });

    await t.test('returns false for an event that never syncs to the document store', async () => {
        // AUTH_ERROR_NOTIFY is not in DOCUMENT_SYNC_EVENTS, so this short-circuits
        // before any document-store/Redis lookup.
        assert.strictEqual(await makeHandler().shouldSyncDocuments(AUTH_ERROR_NOTIFY, true), false);
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

test('generateThreadId early returns', async t => {
    await t.test('does nothing when the payload has no data', async () => {
        const payload = { account: 'a' };
        await makeHandler().generateThreadId(payload);
        assert.deepStrictEqual(payload, { account: 'a' });
    });

    await t.test('leaves an existing threadId untouched', async () => {
        const payload = { data: { id: 'm1', threadId: 'thread-existing' } };
        await makeHandler().generateThreadId(payload);
        assert.strictEqual(payload.data.threadId, 'thread-existing');
    });
});

test('exported constants', async t => {
    await t.test('DOCUMENT_SYNC_EVENTS lists exactly the document-syncing events', () => {
        assert.deepStrictEqual(
            [...DOCUMENT_SYNC_EVENTS].sort(),
            [MESSAGE_NEW_NOTIFY, MESSAGE_DELETED_NOTIFY, MESSAGE_UPDATED_NOTIFY, EMAIL_BOUNCE_NOTIFY, MAILBOX_DELETED_NOTIFY].sort()
        );
    });

    await t.test('document jobs retry more than default jobs', () => {
        assert.strictEqual(DEFAULT_JOB_OPTIONS.attempts, 10);
        assert.strictEqual(DOCUMENT_JOB_OPTIONS.attempts, 16);
        assert.strictEqual(DEFAULT_JOB_OPTIONS.backoff.delay, 5000);
        assert.strictEqual(DEFAULT_JOB_OPTIONS.backoff.jitter, 0.2);
    });
});
