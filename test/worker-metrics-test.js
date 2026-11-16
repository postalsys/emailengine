'use strict';

// The counters a worker's `metrics` message bumps (lib/worker-metrics.js, used by the message
// handler in server.js).

const test = require('node:test');
const assert = require('node:assert').strict;

const { resolveMetricKeys, statBuckets } = require('../lib/worker-metrics');
const { MESSAGE_NEW_NOTIFY, MESSAGE_DELETED_NOTIFY, CONNECT_ERROR_NOTIFY, MESSAGE_UPDATED_NOTIFY } = require('../lib/consts');

const metric = (key, args, meta) => ({ cmd: 'metrics', key, method: 'inc', args, meta });

test('resolveMetricKeys', async t => {
    await t.test('a webhook delivery counts under its status', () => {
        assert.deepEqual(resolveMetricKeys(metric('webhooks', [{ status: 'success' }])), {
            account: undefined,
            statUpdateKey: 'webhooks:success',
            accountUpdateKey: false
        });
        assert.equal(resolveMetricKeys(metric('webhooks', [{ status: 'fail' }])).statUpdateKey, 'webhooks:fail');
    });

    await t.test('a webhook request histogram bumps no counter', () => {
        assert.deepEqual(resolveMetricKeys(metric('webhookReq', [{}, 0.5], { account: 'a1' })), {
            account: 'a1',
            statUpdateKey: false,
            accountUpdateKey: false
        });
    });

    await t.test('the counted events bump both the instance and the account counters', () => {
        for (let event of [MESSAGE_NEW_NOTIFY, MESSAGE_DELETED_NOTIFY, CONNECT_ERROR_NOTIFY]) {
            assert.deepEqual(resolveMetricKeys(metric('events', [{ event }], { account: 'a1' })), {
                account: 'a1',
                statUpdateKey: `events:${event}`,
                accountUpdateKey: `events:${event}`
            });
        }
    });

    await t.test('any other event only bumps the account counter', () => {
        assert.deepEqual(resolveMetricKeys(metric('events', [{ event: MESSAGE_UPDATED_NOTIFY }], { account: 'a1' })), {
            account: 'a1',
            statUpdateKey: false,
            accountUpdateKey: `events:${MESSAGE_UPDATED_NOTIFY}`
        });
    });

    await t.test('an event without an account bumps no account counter', () => {
        assert.deepEqual(resolveMetricKeys(metric('events', [{ event: MESSAGE_NEW_NOTIFY }])), {
            account: undefined,
            statUpdateKey: `events:${MESSAGE_NEW_NOTIFY}`,
            accountUpdateKey: false
        });
    });

    await t.test('an API call counts as success only for a 2xx status', () => {
        const keyFor = statusCode => resolveMetricKeys(metric('apiCall', [{ statusCode, method: 'get', route: '/v1/x' }])).statUpdateKey;
        assert.equal(keyFor(200), 'apiCall:success');
        assert.equal(keyFor(299), 'apiCall:success');
        assert.equal(keyFor(199), 'apiCall:fail');
        assert.equal(keyFor(300), 'apiCall:fail');
        assert.equal(keyFor(404), 'apiCall:fail');
        assert.equal(keyFor(undefined), 'apiCall:fail');
    });

    await t.test('only the submit queue is counted, completed as success and anything else as fail', () => {
        assert.equal(resolveMetricKeys(metric('queuesProcessed', [{ queue: 'submit', status: 'completed' }])).statUpdateKey, 'submit:success');
        assert.equal(resolveMetricKeys(metric('queuesProcessed', [{ queue: 'submit', status: 'failed' }])).statUpdateKey, 'submit:fail');
        assert.equal(resolveMetricKeys(metric('queuesProcessed', [{ queue: 'submit' }])).statUpdateKey, 'submit:fail');
        assert.equal(resolveMetricKeys(metric('queuesProcessed', [{ queue: 'notify', status: 'completed' }])).statUpdateKey, false);
    });

    await t.test('a message without arguments or meta resolves to nothing rather than throwing', () => {
        for (let key of ['webhooks', 'events', 'apiCall', 'queuesProcessed']) {
            assert.doesNotThrow(() => resolveMetricKeys(metric(key, [])), key);
        }
        assert.deepEqual(resolveMetricKeys(metric('imapConnections', [{ status: 'connected' }, 1])), {
            account: undefined,
            statUpdateKey: false,
            accountUpdateKey: false
        });
    });
});

test('statBuckets names the UTC day and minute', () => {
    assert.deepEqual(statBuckets(new Date('2026-11-16T09:05:59.999Z')), { dateStr: '20261116', timeStr: '202611160905' });
    assert.deepEqual(statBuckets(new Date('2026-01-02T23:59:00Z')), { dateStr: '20260102', timeStr: '202601022359' });
});
