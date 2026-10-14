'use strict';

// Unit tests for the pure half of the queue browser: how a stored BullMQ job is shown, and how a
// failure is explained. No Redis: the formatters take job-shaped objects.

const test = require('node:test');
const assert = require('node:assert').strict;

const { QUEUES_BY_NAME, STATES, STATE_NAMES, QUEUE_NAMES, DEFAULT_STATE } = require('../lib/queue-browser/definitions');
const { formatJob, describeFailure, matchesQuery, rawJob, humanSize, notifyPayloadSize } = require('../lib/queue-browser/format');

const submitQueue = QUEUES_BY_NAME.get('submit');
const notifyQueue = QUEUES_BY_NAME.get('notify');
const exportQueue = QUEUES_BY_NAME.get('export');

const NOW = Date.parse('2026-10-14T10:00:00.000Z');

function submitJob(overrides) {
    return Object.assign(
        {
            id: 'q1',
            name: 'queued',
            data: {
                account: 'acc',
                queueId: 'q1',
                messageId: '<m1@example.com>',
                subject: 'Hello',
                envelope: { from: 'a@example.com', to: ['b@example.com', 'c@example.com'] },
                gateway: null,
                source: 'api',
                created: NOW
            },
            opts: { attempts: 10, backoff: { type: 'exponential', delay: 5000 } },
            progress: { status: 'queued' },
            attemptsMade: 0,
            timestamp: NOW,
            processedOn: null,
            finishedOn: null,
            failedReason: null,
            stacktrace: [],
            returnvalue: null
        },
        overrides
    );
}

function notifyJob(overrides) {
    return Object.assign(
        {
            id: '42',
            name: 'messageNew',
            data: {
                account: 'acc',
                date: '2026-10-14T09:59:00.000Z',
                path: 'INBOX',
                specialUse: '\\Inbox',
                event: 'messageNew',
                data: { messageId: '<m1@example.com>', subject: 'Hello' }
            },
            opts: { attempts: 10 },
            progress: 0,
            attemptsMade: 0,
            timestamp: NOW,
            stacktrace: []
        },
        overrides
    );
}

// What the submit worker records on a failed attempt
const submitError = error => ({ status: 'error', error });

test('queue browser definitions', async t => {
    await t.test('name the three queues and the five states in a fixed order', () => {
        assert.deepEqual(QUEUE_NAMES, ['notify', 'submit', 'export']);
        assert.deepEqual(STATE_NAMES, ['waiting', 'active', 'delayed', 'failed', 'completed']);
        assert.equal(DEFAULT_STATE, 'waiting');
        for (const state of STATES) {
            assert.ok(state.label && state.variant && state.description, `${state.name} is fully described`);
        }
        for (const queue of QUEUES_BY_NAME.values()) {
            assert.ok(queue.searchHint && queue.description && queue.noun && queue.nounPlural, `${queue.name} is fully described`);
        }
    });

    await t.test('keep the export queue read-only', () => {
        assert.deepEqual(exportQueue.actions, { retry: false, promote: false, remove: false });
        assert.deepEqual(submitQueue.actions, { retry: true, promote: true, remove: true });
    });
});

test('formatJob', async t => {
    await t.test('shows an outgoing message as a message', () => {
        const entry = formatJob(submitQueue, submitJob(), 'waiting');

        assert.equal(entry.title, 'Hello');
        assert.equal(entry.from, 'a@example.com');
        assert.equal(entry.toFirst, 'b@example.com');
        assert.equal(entry.toMore, 1);
        assert.equal(entry.messageId, '<m1@example.com>');
        assert.equal(entry.url, '/admin/queues/submit/jobs/q1');
        assert.equal(entry.attemptsLabel, '0 of 10');
        assert.equal(entry.failure, null);
        assert.equal(entry.isScheduledSend, false);
        assert.deepEqual(entry.when, { label: 'Queued', time: new Date(NOW).toISOString() });
        assert.ok(entry.canRemove && !entry.canRetry && !entry.canPromote);
    });

    await t.test('a scheduled send is due at its sendAt, a retry at its backoff time', () => {
        const scheduled = formatJob(submitQueue, submitJob({ name: 'delayed', opts: { attempts: 10, delay: 3600 * 1000 } }), 'delayed');
        assert.equal(scheduled.isScheduledSend, true);
        assert.equal(scheduled.isRetryWait, false);
        assert.equal(scheduled.dueAt, new Date(NOW + 3600 * 1000).toISOString());
        assert.deepEqual(scheduled.when, { label: 'Scheduled', time: scheduled.dueAt });
        assert.ok(scheduled.canPromote);

        const retrying = formatJob(
            submitQueue,
            submitJob({
                attemptsMade: 2,
                processedOn: NOW,
                failedReason: 'Greylisted',
                progress: submitError({ message: 'Greylisted', code: 'EENVELOPE', statusCode: 450, responseCode: 450 })
            }),
            'delayed'
        );
        assert.equal(retrying.isRetryWait, true);
        // attempt 2 failed: 2^(2-1) * 5s after processedOn, the same figure the outbox API reports
        assert.equal(retrying.dueAt, new Date(NOW + 10000).toISOString());
        assert.deepEqual(retrying.when, { label: 'Retry', time: retrying.dueAt });
        assert.equal(retrying.failure.label, 'Temporarily refused by the receiving server');
        assert.equal(retrying.failure.shortLabel, 'Refused 450');
    });

    await t.test('a failed message cannot be retried until the listing confirms its content', () => {
        const entry = formatJob(submitQueue, submitJob({ attemptsMade: 10, finishedOn: NOW, failedReason: 'boom' }), 'failed');
        assert.equal(entry.canRetry, true, 'retryable by state; the Redis-backed listing clears it when the content is gone');
        assert.equal(entry.hasContent, null);
        assert.equal(entry.canRemove, true);
        assert.deepEqual(entry.when, { label: 'Failed', time: new Date(NOW).toISOString() });
    });

    await t.test('an active job offers nothing', () => {
        const entry = formatJob(submitQueue, submitJob({ processedOn: NOW }), 'active');
        assert.ok(entry.isActive && !entry.canRemove && !entry.canRetry && !entry.canPromote);
        assert.deepEqual(entry.when, { label: 'Started', time: new Date(NOW).toISOString() });
    });

    await t.test('shows a webhook delivery by its event, route and subject', () => {
        const entry = formatJob(notifyQueue, notifyJob({ data: Object.assign(notifyJob().data, { _route: { id: 'route1' } }) }), 'waiting');
        assert.equal(entry.title, 'messageNew');
        assert.equal(entry.event, 'messageNew');
        assert.equal(entry.routeId, 'route1');
        assert.equal(entry.hasMapping, false);
        assert.equal(entry.about, 'Hello');
        assert.equal(entry.url, '/admin/queues/notify/jobs/42');
    });

    await t.test('a completed delivery shows what the endpoint answered, from the return value', () => {
        const entry = formatJob(notifyQueue, notifyJob({ finishedOn: NOW, returnvalue: { status: 'delivered', statusCode: 204, duration: 120 } }), 'completed');
        assert.equal(entry.outcome.statusCode, 204);
        assert.equal(entry.duration, 120);
        assert.equal(entry.failure, null);
        assert.deepEqual(entry.when, { label: 'Finished', time: new Date(NOW).toISOString() });
    });

    await t.test('measures the mapped payload when a route mapped it', () => {
        const data = Object.assign(notifyJob().data, { _route: { id: 'route1', mapping: { tiny: 1 } } });
        const entry = formatJob(notifyQueue, notifyJob({ data }), 'waiting');
        assert.equal(entry.hasMapping, true);
        assert.equal(notifyPayloadSize(notifyJob({ data })), Buffer.byteLength(JSON.stringify({ tiny: 1 })));
        assert.ok(notifyPayloadSize(notifyJob()) > Buffer.byteLength(JSON.stringify({ tiny: 1 })));
    });

    await t.test('shows an export by its id', () => {
        const entry = formatJob(
            exportQueue,
            { id: 'exp1', name: 'export', data: { account: 'acc', exportId: 'exp1' }, opts: {}, timestamp: NOW, attemptsMade: 0 },
            'waiting'
        );
        assert.equal(entry.title, 'Export exp1');
        assert.equal(entry.exportId, 'exp1');
        assert.ok(!entry.canRemove && !entry.canRetry && !entry.canPromote);
    });

    await t.test('tolerates a job with no data at all', () => {
        for (const queueDef of [submitQueue, notifyQueue, exportQueue]) {
            const entry = formatJob(queueDef, { id: 'x', name: 'n', opts: {}, timestamp: NOW }, 'completed');
            assert.equal(entry.id, 'x');
            assert.equal(entry.account, null);
        }
    });
});

test('describeFailure', async t => {
    await t.test('returns null while nothing has failed', () => {
        assert.equal(describeFailure('submit', submitJob()), null);
    });

    await t.test('a permanent SMTP rejection is what lib/delivery-error.js says it is, and keeps the server reason', () => {
        const failure = describeFailure(
            'submit',
            submitJob({
                failedReason: '550 No such user',
                stacktrace: ['UnrecoverableError: 550 No such user\n    at ...'],
                progress: submitError({ message: '550 No such user', code: 'EENVELOPE', statusCode: 550, responseCode: 550 })
            })
        );
        assert.equal(failure.kind, 'rejected');
        assert.equal(failure.label, 'Rejected by the receiving server');
        assert.equal(failure.shortLabel, 'Rejected 550');
        assert.equal(failure.reason, '550 No such user');
        assert.equal(failure.statusCode, 550);
        assert.equal(failure.permanent, true);
    });

    await t.test('a 503 reply is transient, and a status that is not an SMTP reply is no verdict at all', () => {
        const busy = describeFailure(
            'submit',
            submitJob({ failedReason: 'busy', progress: submitError({ message: 'busy', statusCode: 503, responseCode: 503 }) })
        );
        assert.equal(busy.kind, 'refused');
        assert.equal(busy.permanent, false);

        // a 504 RPC timeout carries a statusCode but no responseCode: the worker retries it, and
        // so must the browser say
        const rpc = describeFailure('submit', submitJob({ failedReason: 'Timeout', progress: submitError({ message: 'Timeout', statusCode: 504 }) }));
        assert.equal(rpc.kind, 'failed');
        assert.equal(rpc.permanent, false);
    });

    await t.test('names authentication and connection failures', () => {
        const auth = describeFailure('submit', submitJob({ failedReason: 'x', progress: submitError({ message: 'x', code: 'EAUTH' }) }));
        assert.equal(auth.label, 'Authentication failed at the outgoing server');
        assert.equal(auth.shortLabel, 'Auth failed');
        assert.equal(
            describeFailure('submit', submitJob({ failedReason: 'x', progress: submitError({ message: 'x', code: 'ECONNECTION' }) })).shortLabel,
            'Unreachable'
        );
    });

    await t.test('reads the recorded webhook error, and says only that an older job failed', () => {
        const recorded = describeFailure('notify', notifyJob({ failedReason: 'Not Found', progress: submitError({ message: 'Not Found', statusCode: 404 }) }));
        assert.equal(recorded.label, 'The endpoint answered 404');
        assert.equal(recorded.shortLabel, 'HTTP 404');
        assert.equal(recorded.statusCode, 404);

        // a job from before the worker recorded anything has only the message; no guessing
        const older = describeFailure('notify', notifyJob({ failedReason: 'Internal Server Error' }));
        assert.equal(older.kind, 'failed');
        assert.equal(older.reason, 'Internal Server Error');
    });

    await t.test('marks the final webhook failures as permanent', () => {
        const redirect = describeFailure(
            'notify',
            notifyJob({
                failedReason: 'Webhook endpoint returned a redirect, which is not followed.',
                stacktrace: ['UnrecoverableError: Webhook endpoint returned a redirect'],
                progress: submitError({
                    message: 'Webhook endpoint returned a redirect, which is not followed.',
                    code: 'EREDIRECTNOTFOLLOWED',
                    statusCode: 302
                })
            })
        );
        assert.equal(redirect.label, 'The endpoint answered with a redirect');
        assert.equal(redirect.permanent, true);

        const blocked = describeFailure(
            'notify',
            notifyJob({ failedReason: 'blocked', progress: submitError({ message: 'blocked', code: 'EEGRESSBLOCKED' }) })
        );
        assert.equal(blocked.shortLabel, 'Blocked');
        assert.equal(blocked.permanent, true);

        const timeout = describeFailure(
            'notify',
            notifyJob({
                failedReason: 'Webhook request timed out after 30s',
                progress: submitError({ message: 'Webhook request timed out after 30s', code: 'ETIMEDOUT' })
            })
        );
        assert.equal(timeout.label, 'The endpoint did not answer in time');
        assert.equal(timeout.permanent, false);

        // an older job that ended early still reads as permanent from the stack head alone
        const olderFinal = describeFailure('notify', notifyJob({ failedReason: 'x', stacktrace: ['UnrecoverableError: x'] }));
        assert.equal(olderFinal.permanent, true);
    });

    await t.test('explains an export failure', () => {
        assert.equal(describeFailure('export', { failedReason: 'disk full', data: {} }).label, 'Export failed');
    });
});

test('matchesQuery', async t => {
    await t.test('matches a message by any of its addresses, subject and ids, case-insensitively', () => {
        const job = submitJob();
        for (const needle of ['HELLO', 'c@example', 'm1@example.com', 'q1', 'acc', 'a@example.com']) {
            assert.ok(matchesQuery(submitQueue, job, needle), needle);
        }
        assert.ok(!matchesQuery(submitQueue, job, 'nothing-like-this'));
        assert.ok(matchesQuery(submitQueue, job, ''), 'an empty query matches everything');
    });

    await t.test('matches a webhook delivery by event, route, folder and payload ids', () => {
        const job = notifyJob({ data: Object.assign(notifyJob().data, { _route: { id: 'route1' } }) });
        for (const needle of ['messagenew', 'route1', 'inbox', 'm1@example.com', 'Hello', '42']) {
            assert.ok(matchesQuery(notifyQueue, job, needle), needle);
        }
        assert.ok(!matchesQuery(notifyQueue, job, 'messageDeleted'));
    });
});

test('rawJob and humanSize', async t => {
    await t.test('keeps what the detail page shows', () => {
        const raw = rawJob(submitJob({ finishedOn: NOW, failedReason: 'x', stacktrace: ['Error: x', 'Error: y'] }));
        assert.equal(raw.name, 'queued');
        assert.equal(raw.stacktrace, 'Error: x\n\nError: y');
        assert.deepEqual(raw.progress, { status: 'queued' });
        assert.equal(raw.returnvalue, null);
        assert.deepEqual(Object.keys(raw).sort(), ['data', 'name', 'opts', 'progress', 'returnvalue', 'stacktrace']);
    });

    await t.test('formats sizes for people', () => {
        assert.equal(humanSize(0), '0 B');
        assert.equal(humanSize(840), '840 B');
        assert.equal(humanSize(1536), '1.5 KB');
        assert.equal(humanSize(100 * 1024 * 1024), '100 MB');
        assert.equal(humanSize(3 * 1024 * 1024 * 1024), '3.0 GB');
    });
});
