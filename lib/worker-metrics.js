'use strict';

// Which dashboard counters a worker's `metrics` message bumps. The message handler lives in
// server.js, which cannot be loaded by a test (it starts the whole application on require), so
// the decision is kept here, pure, and test/worker-metrics-test.js covers it.

const { MESSAGE_NEW_NOTIFY, MESSAGE_DELETED_NOTIFY, CONNECT_ERROR_NOTIFY } = require('./consts');

// The events that also count towards the instance-wide stats, not only the account's own
const COUNTED_EVENTS = new Set([MESSAGE_NEW_NOTIFY, MESSAGE_DELETED_NOTIFY, CONNECT_ERROR_NOTIFY]);

/**
 * Resolves the counters a `metrics` message from a worker updates.
 *
 * @param {Object} message - the worker message (`key`, `args`, `meta`)
 * @returns {{account: (String|undefined), statUpdateKey: (String|false), accountUpdateKey: (String|false)}}
 *   `statUpdateKey` names the instance-wide stats counter, `accountUpdateKey` the per-account one;
 *   false when there is none
 */
function resolveMetricKeys(message) {
    let statUpdateKey = false;
    let accountUpdateKey = false;

    let { account } = message.meta || {};

    switch (message.key) {
        case 'webhooks': {
            let { status } = message.args[0] || {};
            statUpdateKey = `${message.key}:${status}`;
            break;
        }

        case 'events': {
            let { event } = message.args[0] || {};
            if (account) {
                accountUpdateKey = `${message.key}:${event}`;
            }

            // Track specific events
            if (COUNTED_EVENTS.has(event)) {
                statUpdateKey = `${message.key}:${event}`;
            }
            break;
        }

        case 'apiCall': {
            let { statusCode } = message.args[0] || {};
            let success = statusCode >= 200 && statusCode < 300;
            statUpdateKey = `${message.key}:${success ? 'success' : 'fail'}`;
            break;
        }

        case 'queuesProcessed': {
            let { queue, status } = message.args[0] || {};
            if (['submit'].includes(queue)) {
                statUpdateKey = `${queue}:${status === 'completed' ? 'success' : 'fail'}`;
            }
            break;
        }
    }

    return { account, statUpdateKey, accountUpdateKey };
}

/**
 * The Redis hash buckets a stats counter is written to: one hash per UTC day, one field per
 * UTC minute.
 *
 * @param {Date} now
 * @returns {{dateStr: String, timeStr: String}} `YYYYMMDD` and `YYYYMMDDHHmm`
 */
function statBuckets(now) {
    // Create daily bucket
    let dateStr = `${now
        .toISOString()
        .substr(0, 10)
        .replace(/[^0-9]+/g, '')}`;

    // Create minute bucket
    let timeStr = `${now
        .toISOString()
        .substr(0, 16)
        .replace(/[^0-9]+/g, '')}`;

    return { dateStr, timeStr };
}

module.exports = { resolveMetricKeys, statBuckets };
