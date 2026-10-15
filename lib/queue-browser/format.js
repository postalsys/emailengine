'use strict';

// Turns a BullMQ job into what the queue browser shows for it: a webhook delivery, an outgoing
// message or an export, rather than "job #123 with data {...}". Pure functions over the job's
// stored fields, so the wording and the failure classification can be tested without Redis.

const { nextAttemptOfStoredJob, isPermanentDeliveryError } = require('../delivery-error');
const { STATES_BY_NAME } = require('./definitions');

// Error codes nodemailer and the socket layer use for "could not get a connection at all"
const CONNECTION_CODES = new Set(['ECONNECTION', 'ETIMEDOUT', 'ESOCKET', 'EDNS', 'ECONNREFUSED', 'ENOTFOUND', 'EAI_AGAIN', 'ECONNRESET', 'EPROTOCOL', 'ETLS']);

// What each kind of failure is called: the sentence for a detail page and the word or two a
// listing row has room for. `{status}` is the HTTP or SMTP status the worker recorded.
const FAILURE_KINDS = {
    auth: { label: 'Authentication failed at the outgoing server', short: 'Auth failed' },
    unreachable: { label: 'Could not reach the outgoing server', short: 'Unreachable' },
    rejected: { label: 'Rejected by the receiving server', short: 'Rejected {status}' },
    refused: { label: 'Temporarily refused by the receiving server', short: 'Refused {status}' },
    timeout: { label: 'The endpoint did not answer in time', short: 'Timed out' },
    redirect: { label: 'The endpoint answered with a redirect', short: 'Redirected' },
    blocked: { label: 'Destination blocked by the egress policy', short: 'Blocked' },
    http: { label: 'The endpoint answered {status}', short: 'HTTP {status}' },
    endpoint: { label: 'Could not reach the endpoint', short: 'Unreachable' },
    failed: { label: 'Delivery failed', short: 'Failed' },
    export: { label: 'Export failed', short: 'Failed' }
};

function isoOrNull(value) {
    const time = Number(value);
    return time ? new Date(time).toISOString() : null;
}

/**
 * Formats a byte count for people: "1.2 MB", "840 B".
 *
 * @param {number} bytes
 * @returns {string}
 */
function humanSize(bytes) {
    const value = Number(bytes) || 0;
    if (value < 1024) {
        return `${value} B`;
    }
    const units = ['KB', 'MB', 'GB', 'TB'];
    let size = value / 1024;
    let unit = 0;
    while (size >= 1024 && unit < units.length - 1) {
        size /= 1024;
        unit++;
    }
    return `${size < 10 ? size.toFixed(1) : Math.round(size)} ${units[unit]}`;
}

/**
 * The recorded outcome of the last attempt, as the workers store it: `{status: 'error', error:
 * {message, code, statusCode, responseCode}}` on the job's progress field after a failed
 * attempt, and `{status: 'delivered', statusCode, duration}` as the webhook worker's return
 * value after a delivery. Anything else (a plain number, the `{status: 'queued'}` marker)
 * carries no outcome.
 */
function recordedOutcome(job) {
    for (const value of [job.progress, job.returnvalue]) {
        if (value && typeof value === 'object' && value.status) {
            return value;
        }
    }
    return null;
}

/**
 * Classifies a failure of a submission, from what the submit worker recorded.
 *
 * Whether it is permanent is lib/delivery-error.js's call, made on the same fields the worker
 * decided with (the SMTP reply code before the nodemailer error code); nothing here reads a
 * status as a verdict of its own.
 */
function submitFailureKind(recorded) {
    const permanent = isPermanentDeliveryError(recorded);
    const responseCode = Number(recorded.responseCode) || null;
    if (recorded.code === 'EAUTH') {
        return { kind: 'auth', permanent };
    }
    if (responseCode) {
        return { kind: permanent ? 'rejected' : 'refused', permanent, status: responseCode };
    }
    if (CONNECTION_CODES.has(recorded.code)) {
        return { kind: 'unreachable', permanent: false };
    }
    return { kind: 'failed', permanent };
}

/**
 * Classifies a failure of a webhook delivery, from what the webhook worker recorded.
 */
function notifyFailureKind(recorded) {
    const statusCode = Number(recorded.statusCode) || null;
    switch (recorded.code) {
        case 'ETIMEDOUT':
            return { kind: 'timeout', permanent: false };
        case 'EREDIRECTNOTFOLLOWED':
            return { kind: 'redirect', permanent: true, status: statusCode };
        case 'EEGRESSBLOCKED':
            return { kind: 'blocked', permanent: true };
        default:
            if (statusCode) {
                return { kind: 'http', permanent: false, status: statusCode };
            }
            if (CONNECTION_CODES.has(recorded.code)) {
                return { kind: 'endpoint', permanent: false };
            }
            return { kind: 'failed', permanent: false };
    }
}

/**
 * Explains why a job failed, in the terms the worker that ran it uses.
 *
 * Reads the error the worker recorded on the job (its code and status are exact) and falls back
 * to the text of BullMQ's `failedReason`, which is all a job from before the workers recorded
 * anything has. A job whose last attempt failed but that is waiting for its next one is explained
 * the same way, so the delayed list can say what it is retrying from.
 *
 * @param {string} queueName - notify, submit or export
 * @param {Object} job - BullMQ job as stored
 * @returns {Object|null} `{ kind, label, shortLabel, reason, code, statusCode, permanent }`, or
 *   null when nothing has failed. `label` is the sentence for the detail page, `shortLabel` the
 *   word or two a listing row has room for
 */
function describeFailure(queueName, job) {
    const outcome = recordedOutcome(job);
    const recorded = outcome && outcome.status === 'error' && outcome.error && typeof outcome.error === 'object' ? outcome.error : {};
    const reason = job.failedReason || recorded.message || null;
    if (!reason) {
        return null;
    }

    let classified;
    switch (queueName) {
        case 'submit':
            classified = submitFailureKind(recorded);
            break;
        case 'notify':
            classified = notifyFailureKind(recorded);
            break;
        default:
            classified = { kind: 'export', permanent: false };
    }

    // The workers end a job early with UnrecoverableError when retrying cannot help; BullMQ keeps
    // the class name at the head of the stored stack, which is the one signal an older job has
    const stackHead = Array.isArray(job.stacktrace) && job.stacktrace.length ? String(job.stacktrace[0]).split('\n')[0] : '';
    const permanent = classified.permanent || /^UnrecoverableError\b/.test(stackHead);

    const wording = FAILURE_KINDS[classified.kind];
    const status = classified.status ? String(classified.status) : '';
    const fill = text => text.replace(' {status}', status ? ` ${status}` : '').replace('{status}', status);

    return {
        kind: classified.kind,
        label: fill(wording.label),
        shortLabel: fill(wording.short),
        reason: String(reason),
        code: recorded.code || null,
        statusCode: classified.status || Number(recorded.statusCode) || null,
        permanent
    };
}

/**
 * The one timestamp a listing row shows for an entry, with the word that says what it is:
 * when a delayed entry is due, when a running one started, when a finished one finished, and
 * otherwise when it was queued.
 */
function whenOf(queueDef, state, times) {
    switch (state) {
        case 'delayed':
            return { label: times.isRetryWait ? 'Retry' : 'Scheduled', time: times.dueAt };
        case 'active':
            return { label: 'Started', time: times.processedOn };
        case 'failed':
            return { label: 'Failed', time: times.finishedOn };
        case 'completed':
            return { label: queueDef.name === 'submit' ? 'Sent' : 'Finished', time: times.finishedOn };
        default:
            return { label: 'Queued', time: times.created };
    }
}

/**
 * The fields every row and detail view carries, whatever the queue.
 */
function formatCommon(queueDef, job, state) {
    const stateInfo = STATES_BY_NAME.get(state) || { name: state, label: state, variant: 'neutral' };
    const attempts = Number(job.opts && job.opts.attempts) || 1;
    const attemptsMade = Number(job.attemptsMade) || 0;

    const scheduledMs = Number(job.timestamp) + (Number(job.opts && job.opts.delay) || 0);
    const nextAttemptMs = nextAttemptOfStoredJob(job, scheduledMs);

    const isRetryWait = state === 'delayed' && attemptsMade > 0;
    const times = {
        created: isoOrNull(job.timestamp),
        // A delayed entry is either scheduled (nothing has run yet) or waiting out a backoff
        dueAt: state === 'delayed' ? (attemptsMade ? isoOrNull(nextAttemptMs) : new Date(scheduledMs).toISOString()) : null,
        isRetryWait,
        processedOn: isoOrNull(job.processedOn),
        finishedOn: isoOrNull(job.finishedOn)
    };

    const outcome = recordedOutcome(job);

    return Object.assign(
        {
            id: String(job.id),
            queue: queueDef.name,
            url: entryUrl(queueDef.name, job.id),
            state,
            stateInfo,
            account: (job.data && job.data.account) || null,
            scheduled: new Date(scheduledMs).toISOString(),
            attemptsMade,
            attempts,
            // Attempt numbers for people: "attempt 3 of 10" while running, "3 of 10 attempts" after
            attemptsLabel: `${attemptsMade} of ${attempts}`,
            when: whenOf(queueDef, state, times),
            failure: describeFailure(queueDef.name, job),
            // What the worker recorded of the last outcome, beyond the error
            outcome,
            duration: outcome && Number(outcome.duration) ? Number(outcome.duration) : null,
            canPromote: !!queueDef.actions.promote && state === 'delayed',
            canRetry: !!queueDef.actions.retry && state === 'failed',
            canRemove: !!queueDef.actions.remove && state !== 'active'
        },
        times
    );
}

function formatSubmit(queueDef, job, state) {
    const data = job.data || {};
    const envelope = data.envelope || {};
    const to = Array.isArray(envelope.to) ? envelope.to : envelope.to ? [envelope.to] : [];

    return Object.assign(formatCommon(queueDef, job, state), {
        title: data.subject || '(no subject)',
        subject: data.subject || null,
        messageId: data.messageId || null,
        from: envelope.from || null,
        to,
        toFirst: to[0] || null,
        toMore: to.length > 1 ? to.length - 1 : 0,
        gateway: data.gateway || null,
        source: data.source || null,
        idempotencyKey: data.idempotencyKey || null,
        // 'delayed' names a scheduled send, 'queued' an immediate one; the job name is set once
        isScheduledSend: job.name === 'delayed',
        // Filled in by the Redis-backed listing, which knows whether the content is still stored
        hasContent: null
    });
}

function formatNotify(queueDef, job, state) {
    const data = job.data || {};
    const route = data._route && typeof data._route === 'object' ? data._route : null;
    const payload = data.data && typeof data.data === 'object' ? data.data : {};

    return Object.assign(formatCommon(queueDef, job, state), {
        title: job.name,
        event: job.name,
        eventId: data.eventId || null,
        date: data.date || null,
        path: data.path || null,
        specialUse: data.specialUse || null,
        routeId: route ? route.id : null,
        // resolved by the Redis-backed listing, which can look the route up
        routeName: null,
        hasMapping: !!(route && route.mapping !== undefined),
        // What the event is about, for the row: a message's subject, an account's new state
        about: payload.subject || payload.messageId || (payload.state ? `state: ${payload.state}` : null),
        messageId: payload.messageId || null
    });
}

function formatExport(queueDef, job, state) {
    const data = job.data || {};
    return Object.assign(formatCommon(queueDef, job, state), {
        title: `Export ${data.exportId || job.id}`,
        exportId: data.exportId || String(job.id)
    });
}

const FORMATTERS = { submit: formatSubmit, notify: formatNotify, export: formatExport };

/**
 * The page of one entry in the browser.
 *
 * @param {string} queueName - Queue name
 * @param {string|number} jobId - Job ID
 * @returns {string} Path
 */
function entryUrl(queueName, jobId) {
    return `/admin/queues/${queueName}/jobs/${encodeURIComponent(jobId)}`;
}

/**
 * Formats a job of a queue for the browser.
 *
 * @param {Object} queueDef - Queue definition from ./definitions
 * @param {Object} job - BullMQ job as stored
 * @param {string} state - The state the job was listed from
 * @returns {Object} Row or detail model
 */
function formatJob(queueDef, job, state) {
    return (FORMATTERS[queueDef.name] || formatExport)(queueDef, job, state);
}

/**
 * The size of what a webhook delivery posts: the mapped payload when a route mapped it, the
 * event payload otherwise. Measured on the detail page only, because serializing every row's
 * payload (up to notifyTextSize of message text each) just to print a size is not worth it.
 *
 * @param {Object} job - BullMQ job as stored
 * @returns {number} Bytes
 */
function notifyPayloadSize(job) {
    const data = job.data || {};
    const route = data._route && typeof data._route === 'object' ? data._route : null;
    try {
        return Buffer.byteLength(JSON.stringify(route && route.mapping !== undefined ? route.mapping : data));
    } catch (err) {
        return 0;
    }
}

// The fields a person would search a queue by, per queue
const SEARCH_FIELDS = {
    submit: (job, data) => {
        const envelope = data.envelope || {};
        return [data.messageId, data.subject, data.gateway, data.idempotencyKey, envelope.from, ...(Array.isArray(envelope.to) ? envelope.to : [envelope.to])];
    },
    notify: (job, data) => {
        const payload = data.data && typeof data.data === 'object' ? data.data : {};
        return [job.name, data._route && data._route.id, data.path, payload.messageId, payload.subject, data.eventId];
    },
    export: (job, data) => [data.exportId]
};

/**
 * Whether a job matches a free-text filter: a substring match over the fields a person would
 * search a queue by. Case-insensitive; an empty filter matches everything.
 *
 * @param {Object} queueDef - Queue definition
 * @param {Object} job - BullMQ job as stored
 * @param {string} query - Filter text, already trimmed
 * @returns {boolean}
 */
function matchesQuery(queueDef, job, query) {
    const needle = String(query || '').toLowerCase();
    if (!needle) {
        return true;
    }

    const data = job.data || {};
    const fields = [job.id, data.account, ...(SEARCH_FIELDS[queueDef.name] || SEARCH_FIELDS.export)(job, data)];

    return fields.some(field => field !== null && field !== undefined && String(field).toLowerCase().includes(needle));
}

/**
 * The raw job, for the collapsed section of the detail page: what a support case asks for, in
 * the shape BullMQ stores it.
 *
 * @param {Object} job - BullMQ job as stored
 * @returns {Object} `{ name, data, opts, progress, returnvalue, stacktrace }`
 */
function rawJob(job) {
    return {
        name: job.name,
        data: job.data,
        opts: job.opts,
        progress: job.progress && typeof job.progress === 'object' ? job.progress : null,
        returnvalue: job.returnvalue !== null && job.returnvalue !== undefined ? job.returnvalue : null,
        stacktrace: Array.isArray(job.stacktrace) && job.stacktrace.length ? job.stacktrace.join('\n\n') : null
    };
}

module.exports = { formatJob, describeFailure, matchesQuery, rawJob, humanSize, notifyPayloadSize, entryUrl, FAILURE_KINDS };
