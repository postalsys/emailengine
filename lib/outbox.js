'use strict';

const { submitQueue, redis } = require('./db');
const { REDIS_PREFIX } = require('../lib/consts');
const msgpack = require('./msgpack');
const { nextAttemptOfStoredJob } = require('./delivery-error');
const { readEnvValue } = require('./read-env-value');
const { getByteSize } = require('./tools');
const { statusError } = require('./utils/status-error');
const { retryFailedJob, promoteDelayedJob, assertJobState } = require('./queue-job-actions');
const {
    selectFailedContentToDrop,
    FAILED_JOB_RETENTION_AGE,
    FAILED_JOB_RETENTION_COUNT,
    DEFAULT_FAILED_CONTENT_RETENTION_COUNT,
    DEFAULT_FAILED_CONTENT_RETENTION_SIZE
} = require('./queue-retention');

// Job reads and removals are issued in bounded batches. ioredis writes each command as it is
// issued, so a batch costs one round trip rather than one per job, while the bound keeps an account
// with a huge outbox from putting an unlimited number of Lua scripts in flight at once.
const BATCH_SIZE = 100;

// The states an outbox entry can be in, in the order they concatenate into the listing. 'waiting',
// not 'wait': getRanges() accepts either, but getJobCounts() keys its result only by 'waiting', so
// 'wait' read back undefined and left total/pages at 0. There is no 'paused' either - BullMQ 6
// dropped it as a job state and reports the jobs of a paused queue as waiting.
const JOB_STATES = ['delayed', 'waiting', 'active', 'failed'];

function outboxKey(account) {
    return `${REDIS_PREFIX}iaq:${account}`;
}

// The contents retained for messages whose delivery failed for good, so they can be retried: a
// hash whose field names the account and the queue ID and whose value records when the failure
// happened and how large the content is. A hash rather than a sorted set because every operation
// but the trim addresses one message, and a hash field is removed by name; the trim reads the
// whole thing, which the count bound keeps small. Its own key rather than a field convention
// inside the account hashes, because the bounds apply across every account at once, and `iaqf`
// cannot collide with an account's `iaq:<account>` hash, whatever the account is called.
const FAILED_CONTENT_KEY = `${REDIS_PREFIX}iaqf`;

function retainedField(account, queueId) {
    return JSON.stringify([account, queueId]);
}

/**
 * An environment bound, with `0` meaning "none" rather than "the default".
 *
 * @param {string} key - Environment variable
 * @param {Function} parse - Parser for a value that is set
 * @param {number} defaultValue - Used when the variable is unset or unparsable
 * @returns {number}
 */
function envBound(key, parse, defaultValue) {
    const raw = readEnvValue(key);
    if (raw === undefined || raw === null || raw === '') {
        return defaultValue;
    }
    const value = parse(raw);
    return typeof value === 'number' && value >= 0 && !isNaN(value) ? value : defaultValue;
}

// How much failed content is kept. Setting either count or size to 0 keeps none, which is the
// behavior before retries existed: the content went the moment the last attempt failed. The
// count is capped at the failed-job retention count and the age is the failed-job age, so
// BullMQ's own `removeOnFail` policy never removes a job before its content is dropped here -
// the record of a failure always outlives the content it would need to retry.
const FAILED_CONTENT_LIMITS = {
    maxCount: Math.min(envBound('EENGINE_QUEUE_KEEP_FAILED_CONTENT', Number, DEFAULT_FAILED_CONTENT_RETENTION_COUNT), FAILED_JOB_RETENTION_COUNT),
    maxBytes: envBound('EENGINE_QUEUE_KEEP_FAILED_CONTENT_SIZE', getByteSize, DEFAULT_FAILED_CONTENT_RETENTION_SIZE),
    maxAge: FAILED_JOB_RETENTION_AGE
};

/**
 * Decodes a message stored in an account's outbox hash.
 *
 * The stored value is always a msgpack map. lib/msgpack decodes the first value of a buffer and
 * ignores whatever follows, so a foreign or truncated value does not necessarily throw: a buffer
 * that happens to start with a byte that is a valid scalar comes back as that scalar. Anything
 * other than a map is unusable as a queued message and must be treated like an undecodable one -
 * the submit worker stamps its job metadata onto the entry, and doing that to a scalar throws a
 * TypeError that would otherwise be reported and retried as a delivery failure.
 *
 * @param {Buffer} entryBuf - Raw hash field value
 * @returns {Object} Decoded queue entry
 * @throws {Error} If the value is not a msgpack map
 */
function decodeQueueEntry(entryBuf) {
    let queueEntry = msgpack.decode(entryBuf);

    // Every other msgpack type decodes to something a queued message can never be: nil, a scalar,
    // a Buffer (bin), an array, or a Date (timestamp extension)
    if (!queueEntry || typeof queueEntry !== 'object' || Array.isArray(queueEntry) || Buffer.isBuffer(queueEntry) || queueEntry instanceof Date) {
        throw new Error('Unexpected outbox entry format');
    }

    return queueEntry;
}

function formatQueueEntry(job, state) {
    let scheduled = job.timestamp + (Number(job.opts.delay) || 0);

    let nextAttempt = nextAttemptOfStoredJob(job, scheduled);

    return Object.assign(job.data, {
        created: new Date(Number(job.data.created || job.timestamp)).toISOString(),
        state,
        progress: job.progress,
        attemptsMade: job.attemptsMade,
        attempts: job.opts.attempts,
        scheduled: new Date(scheduled).toISOString(),
        nextAttempt: nextAttempt ? new Date(nextAttempt).toISOString() : false
    });
}

/**
 * Maps a page of the outbox onto a sub-range of each job state.
 *
 * The outbox is the concatenation of the submit queue's per-state lists, in the order given, and
 * the job counts already say how long each one is - which is enough to work out how much of the
 * requested window falls in which state. Asking getRanges() for [start, end] across all the states
 * at once instead (what this used to do) applies that range to every state separately, so a page
 * came back holding up to pageSize entries PER state, and page 1 skipped the first pageSize entries
 * of each state rather than the first pageSize entries overall.
 *
 * @param {String[]} jobStates - Job states, in the order they concatenate into the outbox
 * @param {Object} jobCounts - Job count per state, as returned by Queue#getJobCounts()
 * @param {Number} start - Index of the first entry of the page, within the concatenated list
 * @param {Number} pageSize - How many entries the page holds at most
 * @returns {Object[]} `{ state, start, end }` ranges, inclusive, totalling at most pageSize entries
 */
function selectPageRanges(jobStates, jobCounts, start, pageSize) {
    let ranges = [];
    let remaining = pageSize;
    // How many entries the states already walked hold between them
    let precedingEntries = 0;

    for (let state of jobStates) {
        if (remaining <= 0) {
            break;
        }

        let stateLength = Number(jobCounts[state]) || 0;
        // Clamped to 0 once the page has started in an earlier state, in which case this one is
        // read from its first entry
        let from = Math.max(start - precedingEntries, 0);
        precedingEntries += stateLength;

        // Also covers a page that begins past the end of this state, where from >= stateLength
        let take = Math.min(stateLength - from, remaining);
        if (take > 0) {
            ranges.push({ state, start: from, end: from + take - 1 });
            remaining -= take;
        }
    }

    return ranges;
}

/**
 * Loads jobs by ID in bounded batches, skipping the ones that are gone or cannot be read.
 *
 * @param {string[]} jobIds - Job IDs
 * @param {Object} logger - Logger instance
 * @returns {Promise<Object[]>} The jobs that exist
 */
async function loadJobs(jobIds, logger) {
    let jobs = [];
    for (let i = 0; i < jobIds.length; i += BATCH_SIZE) {
        let batch = await Promise.all(
            jobIds.slice(i, i + BATCH_SIZE).map(async jobId => {
                try {
                    return await submitQueue.getJob(jobId);
                } catch (err) {
                    logger.error({ msg: 'Failed to retrieve message info from outbox', jobId, err });
                    return null;
                }
            })
        );
        jobs.push(...batch.filter(Boolean));
    }
    return jobs;
}

/**
 * The outbox of one account. The submit queue has no index by account, but the account's outbox
 * hash does: every message waiting to be sent has its content there under its queue ID, and so
 * does a failed message whose content is retained for a retry. So the listing reads the queue IDs
 * from that hash rather than scanning the whole queue, and costs what that account has queued.
 * A failed message whose content is already gone cannot be retried and is not listed here; the
 * instance-wide listing still shows it.
 *
 * @param {Object} options
 * @param {string} options.account - Account ID
 * @param {string[]} options.states - Job states to include
 * @param {number} options.page - Zero-based page
 * @param {number} options.pageSize - Entries per page
 * @param {Object} options.logger - Logger instance
 * @returns {Promise<Object>} `{ total, page, pages, messages }`
 */
async function listAccount(options) {
    let { account, states, page, pageSize, logger } = options;

    let queueIds = await redis.hkeys(outboxKey(account));
    let jobs = (await loadJobs(queueIds, logger)).filter(job => job.data && job.data.account === account);

    let entries = [];
    for (let i = 0; i < jobs.length; i += BATCH_SIZE) {
        let batch = jobs.slice(i, i + BATCH_SIZE);
        let jobStates = await Promise.all(batch.map(job => job.getState()));
        batch.forEach((job, j) => {
            if (states.includes(jobStates[j])) {
                entries.push({ job, state: jobStates[j] });
            }
        });
    }

    // The same order as the instance-wide listing: by state, then oldest first
    entries.sort((a, b) => states.indexOf(a.state) - states.indexOf(b.state) || a.job.timestamp - b.job.timestamp);

    return {
        total: entries.length,
        page,
        pages: Math.ceil(entries.length / pageSize),
        messages: entries.slice(page * pageSize, (page + 1) * pageSize).map(({ job, state }) => formatQueueEntry(job, state))
    };
}

/**
 * One page of the outbox, optionally narrowed to one account and to one state.
 *
 * @param {Object} options
 * @param {number} [options.page] - Zero-based page
 * @param {number} [options.pageSize] - Entries per page
 * @param {string} [options.account] - Only this account's messages
 * @param {string} [options.state] - Only messages in this state, one of JOB_STATES
 * @param {Object} options.logger - Logger instance
 * @returns {Promise<Object>} `{ total, page, pages, messages }`
 */
async function list(options) {
    options = options || {};
    let page = Number(options.page) || 0;
    let pageSize = Number(options.pageSize) || 20;
    let logger = options.logger;
    let states = options.state ? JOB_STATES.filter(state => state === options.state) : JOB_STATES;

    if (options.account) {
        return await listAccount({ account: options.account, states, page, pageSize, logger });
    }

    let jobCounts = await submitQueue.getJobCounts(...states);

    let totalJobs = states.map(state => Number(jobCounts[state]) || 0).reduce((previousValue, currentValue) => previousValue + currentValue, 0);

    // The counts above and the ranges below are separate reads, so a job that changes state in
    // between can be listed twice or missed. That is inherent to paging a live queue without
    // locking it, and the next request reflects the queue as it then stands.
    let ranges = selectPageRanges(states, jobCounts, page * pageSize, pageSize);

    let idsPerRange = await Promise.all(ranges.map(range => submitQueue.getRanges([range.state], range.start, range.end, true)));
    // Each ID is read from a known state's list, which is what the entry reports as its state -
    // there is no second round trip asking the job
    let jobIds = idsPerRange.flatMap((ids, i) => ids.map(jobId => ({ jobId, state: ranges[i].state })));

    // Queue#getJobs() is this same id-fetch-plus-getJob, but with an unbounded Promise.all and no
    // per-entry error handling: one unreadable job would reject the whole page. Batched here
    // instead, the same shape as removeJobs() below, because pageSize goes up to 1000.
    let messages = [];
    for (let i = 0; i < jobIds.length; i += BATCH_SIZE) {
        let batch = await Promise.all(
            jobIds.slice(i, i + BATCH_SIZE).map(async ({ jobId, state }) => {
                try {
                    let job = await submitQueue.getJob(jobId);
                    return job ? formatQueueEntry(job, state) : null;
                } catch (err) {
                    logger.error({ msg: 'Failed to retrieve message info from outbox', jobId, err });
                    return null;
                }
            })
        );

        for (let entry of batch) {
            if (entry) {
                messages.push(entry);
            }
        }
    }

    return {
        total: totalJobs,
        page,
        pages: Math.ceil(totalJobs / pageSize),
        messages
    };
}

/**
 * The submit job of a queue ID, or null when there is none - or when `account` is given and the
 * message belongs to another account. The per-account routes pass the account from their path,
 * so a credential bound to one account cannot reach another's message by guessing its queue ID.
 *
 * @param {string} queueId - Queue ID
 * @param {string} [account] - Account the message has to belong to
 * @returns {Promise<Object|null>} BullMQ job
 */
async function getOwnJob(queueId, account) {
    if (!queueId) {
        return null;
    }
    let job = await submitQueue.getJob(queueId);
    if (!job || (account && (!job.data || job.data.account !== account))) {
        return null;
    }
    return job;
}

// Resolves to { deleted } - with `locked: true` when the message could not be removed because a
// submit worker is delivering it right now. That is the one refusal a caller can act on (retry
// once the attempt is over), so it is reported rather than folded into a plain false; a failure to
// remove for any other reason is thrown.
async function del(options) {
    options = options || {};

    let logger = options.logger;

    let job = await getOwnJob(options.queueId, options.account);
    if (!job) {
        return { deleted: false };
    }

    // BullMQ refuses to remove a job a worker holds the lock on, and for the submit queue that is
    // a message in the middle of a delivery attempt. Checked before touching the content: the
    // attempt in flight still needs it, and removing it here would not stop the attempt anyway.
    if (await job.isActive()) {
        logger.info({
            msg: 'Queued message is being delivered, not removed',
            account: job.data.account,
            queueId: job.data.queueId,
            messageId: job.data.messageId
        });
        return { deleted: false, locked: true };
    }

    // Delete message content
    try {
        let res = await redis.hdel(outboxKey(job.data.account), job.data.queueId);
        await releaseFailedContent({ account: job.data.account, queueId: job.data.queueId });
        logger.info({ msg: 'Removed queued message', res, account: job.data.account, queueId: job.data.queueId, messageId: job.data.messageId });
    } catch (err) {
        logger.error({ msg: 'Failed to remove queued message', account: job.data.account, queueId: job.data.queueId, messageId: job.data.messageId, err });
    }

    // Delete job entry
    try {
        await job.remove();
    } catch (err) {
        logger.error({ msg: 'Failed to remove queue entry', account: job.data.account, queueId: job.data.queueId, messageId: job.data.messageId, err });
        throw err;
    }

    logger.info({ msg: 'Removed queue entry', account: job.data.account, queueId: job.data.queueId, messageId: job.data.messageId });
    return { deleted: true };
}

async function get(options) {
    options = options || {};

    let logger = options.logger;

    let job = await getOwnJob(options.queueId, options.account);
    if (!job) {
        return false;
    }

    try {
        let queueEntryBuf = await redis.hgetBuffer(outboxKey(job.data.account), job.data.queueId);
        if (!queueEntryBuf) {
            return false;
        }
    } catch (err) {
        logger.error({ msg: 'Failed to retrieve queued message', account: job.data.account, queueId: job.data.queueId, messageId: job.data.messageId, err });
        throw err;
    }

    return formatQueueEntry(job, await job.getState());
}

/**
 * Removes the submit queue jobs of messages that were queued for an account that no longer exists.
 *
 * Deleting an account removes the message content, but the queue job pointing at it is a separate
 * structure that the deletion does not touch, and its job data still carries the envelope, the
 * subject and the message ID. A job that is merely waiting cleans itself up the moment it runs,
 * because the worker finds no content and returns, but a *delayed* job does not run until its
 * `sendAt`, which the API caller chooses and which can be arbitrarily far in the future. Without
 * this, a message scheduled for next year would keep its recipient addresses and subject line in
 * Redis for that long after the account was erased.
 *
 * The `notify` queue is deliberately not handled the same way. Webhook entries for a deleted
 * account are never delivered, as the notify worker checks that the account still exists before
 * doing anything, and the entries that do not clean themselves up - deliveries that already failed
 * permanently - are bounded by EENGINE_QUEUE_KEEP_FAILED_AGE. They are inert and self-expiring,
 * whereas finding them would mean matching on job payloads that BullMQ reads inside a blocking Lua
 * script. Submit jobs that already reached the failed set are bounded the same way, and are left
 * alone for the same reason.
 *
 * @param {String[]} queueIds - Queue IDs, which are also the submit queue job IDs
 * @param {Object} options - Options
 * @param {String} options.account - Account ID, for logging
 * @param {Object} options.logger - Logger instance
 * @returns {Promise<Number>} Number of jobs removed. A job a worker holds the lock on is left
 *   behind, which is harmless: the worker finds no content for it and completes without sending.
 */
async function removeJobs(queueIds, options) {
    const { account, logger } = options;

    // The retained failed contents among these go with the outbox hash the caller unlinks
    if (queueIds.length) {
        try {
            await redis.hdel(FAILED_CONTENT_KEY, ...queueIds.map(queueId => retainedField(account, queueId)));
        } catch (err) {
            logger.error({ msg: 'Failed to release the retained failed messages of an account', account, err });
        }
    }

    let removed = 0;

    for (let i = 0; i < queueIds.length; i += BATCH_SIZE) {
        let batch = queueIds.slice(i, i + BATCH_SIZE);

        let results = await Promise.all(
            batch.map(async queueId => {
                try {
                    // Removes by ID without loading the job payload, and returns 0 instead of
                    // throwing when a worker holds the job lock. Submit jobs are never flow nodes,
                    // so skipping the child lookups saves five Redis calls per job.
                    return await submitQueue.remove(queueId, { removeChildren: false });
                } catch (err) {
                    logger.error({ msg: 'Failed to remove queued message job', account, queueId, err });
                    return 0;
                }
            })
        );

        removed += results.filter(code => code === 1).length;
    }

    return removed;
}

/**
 * The retained failed contents, as the hash holds them.
 *
 * @returns {Promise<Array<{account: string, queueId: string, size: number, finishedOn: number, field: string}>>}
 *   An entry whose field cannot be read carries `unreadable: true` and is dropped by the next prune
 */
async function listRetainedFailedContent() {
    const raw = await redis.hgetall(FAILED_CONTENT_KEY);

    const entries = [];
    for (const [field, value] of Object.entries(raw || {})) {
        let decoded;
        let record;
        try {
            decoded = JSON.parse(field);
            record = JSON.parse(value);
        } catch (err) {
            decoded = null;
        }
        if (Array.isArray(decoded) && typeof decoded[0] === 'string' && typeof decoded[1] === 'string' && record && typeof record === 'object') {
            entries.push({ account: decoded[0], queueId: decoded[1], size: Number(record.s) || 0, finishedOn: Number(record.t) || 0, field });
        } else {
            entries.push({ account: null, queueId: null, size: 0, finishedOn: 0, field, unreadable: true });
        }
    }

    return entries;
}

/**
 * Removes the content of the given retained entries and forgets them.
 *
 * @param {Array<Object>} entries - Entries from listRetainedFailedContent()
 * @param {Object} [options]
 * @param {Object} [options.logger] - Logger instance
 * @returns {Promise<number>} How many entries were dropped
 */
async function dropFailedContent(entries, options) {
    if (!entries.length) {
        return 0;
    }

    const logger = (options && options.logger) || null;

    const pipeline = redis.multi();
    for (const entry of entries) {
        if (entry.account) {
            pipeline.hdel(outboxKey(entry.account), entry.queueId);
        }
    }
    pipeline.hdel(FAILED_CONTENT_KEY, ...entries.map(entry => entry.field));
    await pipeline.exec();

    if (logger) {
        for (const entry of entries) {
            logger.info({ msg: 'Dropped the content of a failed message', account: entry.account, queueId: entry.queueId, size: entry.size });
        }
    }

    return entries.length;
}

/**
 * Keeps the content of a message whose delivery just failed for good, so it can be retried.
 *
 * Called from the submit worker's `failed` handler in place of the deletion it used to do. The
 * bounds in FAILED_CONTENT_LIMITS are applied on every call, so the set never holds more than
 * `maxCount` entries or `maxBytes` of content: whatever has to go to make room for this one goes
 * now, oldest first, and this one itself goes at once when it does not fit (a message larger than
 * the whole size bound, or a bound of zero).
 *
 * @param {Object} options
 * @param {string} options.account - Account ID
 * @param {string} options.queueId - Queue ID, also the job ID
 * @param {number} [options.finishedOn] - When the last attempt failed (defaults to now)
 * @param {Object} [options.logger] - Logger instance
 * @returns {Promise<boolean>} Whether the content is retained after the bounds were applied
 */
async function retainFailedContent(options) {
    const { account, queueId, logger } = options;

    const size = await redis.hstrlen(outboxKey(account), queueId);
    if (!size) {
        // the content is already gone, so there is nothing to retain
        return false;
    }

    const field = retainedField(account, queueId);
    const [, [, raw]] = await redis
        .multi()
        .hset(FAILED_CONTENT_KEY, field, JSON.stringify({ t: options.finishedOn || Date.now(), s: size }))
        .hgetall(FAILED_CONTENT_KEY)
        .exec();

    const entries = [];
    for (const [entryField, value] of Object.entries(raw || {})) {
        try {
            const [entryAccount, entryQueueId] = JSON.parse(entryField);
            const record = JSON.parse(value);
            entries.push({ account: entryAccount, queueId: entryQueueId, size: Number(record.s) || 0, finishedOn: Number(record.t) || 0, field: entryField });
        } catch (err) {
            // unreadable entries are the prune's business
        }
    }

    const drop = selectFailedContentToDrop(entries, FAILED_CONTENT_LIMITS);
    await dropFailedContent(drop, { logger });

    return !drop.some(entry => entry.field === field);
}

/**
 * Forgets a retained content without deleting it, because the message is live again (retried) or
 * its content was deleted by the caller. A no-op for a message that was never retained.
 *
 * @param {Object} options
 * @param {string} options.account - Account ID
 * @param {string} options.queueId - Queue ID
 */
async function releaseFailedContent(options) {
    await redis.hdel(FAILED_CONTENT_KEY, retainedField(options.account, options.queueId));
}

/**
 * Applies the retention bounds to everything retained, and reconciles the set with the queue.
 *
 * The bounds are applied on every retain, so this mostly catches age. The reconciliation is what
 * makes a job removed by a path this module does not see - a clean of the failed set, BullMQ's
 * own removal of an aged-out job - take its content with it: a retained content whose job is gone
 * is dropped. One whose job is no longer in the failed state is released to the worker, which
 * deletes the content when the job finishes; every retry today goes through retry() below, which
 * releases, so this is a guard against a future path that does not. Run by the periodic queue
 * cleanup and after a clean of the failed set.
 *
 * @param {Object} [options]
 * @param {Object} [options.logger] - Logger instance
 * @returns {Promise<{dropped: number, released: number}>}
 */
async function pruneFailedContent(options) {
    const logger = (options && options.logger) || null;

    const entries = await listRetainedFailedContent();
    if (!entries.length) {
        return { dropped: 0, released: 0 };
    }

    const dropping = new Map(entries.filter(entry => entry.unreadable).map(entry => [entry.field, entry]));
    for (const entry of selectFailedContentToDrop(
        entries.filter(entry => !entry.unreadable),
        FAILED_CONTENT_LIMITS
    )) {
        dropping.set(entry.field, entry);
    }

    const remaining = entries.filter(entry => !dropping.has(entry.field));
    const states = await Promise.all(
        remaining.map(async entry => {
            try {
                return await submitQueue.getJobState(entry.queueId);
            } catch (err) {
                if (logger) {
                    logger.error({ msg: 'Failed to check the job of a retained failed message', account: entry.account, queueId: entry.queueId, err });
                }
                return null;
            }
        })
    );

    const release = [];
    remaining.forEach((entry, i) => {
        if (states[i] === 'unknown') {
            dropping.set(entry.field, entry);
        } else if (states[i] && states[i] !== 'failed') {
            release.push(entry.field);
        }
    });

    const dropped = await dropFailedContent([...dropping.values()], { logger });
    if (release.length) {
        await redis.hdel(FAILED_CONTENT_KEY, ...release);
    }

    return { dropped, released: release.length };
}

/**
 * Puts a message whose delivery failed for good back into the queue with a fresh set of attempts.
 *
 * Only a failed message can be retried, and only while its content is still retained: the
 * submit worker completes a job it finds no content for without sending anything, so a retry of
 * such a job would report success for a message that never left. That is what the bull-board
 * Retry button used to do, which is why this refuses instead.
 *
 * @param {Object} options
 * @param {string} options.queueId - Queue ID
 * @param {Object} options.logger - Logger instance
 * @returns {Promise<Object|false>} `{ retried, queueId, messageId }`, or false when there is no such message
 * @throws {Error} With `statusCode` 409 and a `code` naming why the message cannot be retried
 */
async function retry(options) {
    const { queueId, account, logger } = options;

    const job = await getOwnJob(queueId, account);
    if (!job) {
        return false;
    }

    await assertJobState(job, 'failed', 'message', 'retried');

    if (!(await redis.hexists(outboxKey(job.data.account), job.id))) {
        throw statusError('The content of this message is no longer stored, so it cannot be retried. Submit the message again', 'ContentGone', 409);
    }

    await retryFailedJob(job, 'message');
    await releaseFailedContent({ account: job.data.account, queueId: job.id });

    logger.info({ msg: 'Retrying failed message', account: job.data.account, queueId: job.id, messageId: job.data.messageId });

    return { retried: true, queueId: job.id, messageId: job.data.messageId };
}

/**
 * Sends a message waiting in the delayed set now: one scheduled with `sendAt`, or one waiting out
 * the backoff before its next attempt.
 *
 * @param {Object} options
 * @param {string} options.queueId - Queue ID
 * @param {Object} options.logger - Logger instance
 * @returns {Promise<Object|false>} `{ promoted, queueId, messageId }`, or false when there is no such message
 * @throws {Error} With `statusCode` 409 and `code` NotDelayed when the message is not waiting for a time
 */
async function promote(options) {
    const { queueId, account, logger } = options;

    const job = await getOwnJob(queueId, account);
    if (!job) {
        return false;
    }

    await assertJobState(job, 'delayed', 'message', 'sent now');
    await promoteDelayedJob(job, 'message');

    logger.info({ msg: 'Promoted queued message', account: job.data.account, queueId: job.id, messageId: job.data.messageId });

    return { promoted: true, queueId: job.id, messageId: job.data.messageId };
}

// selectPageRanges and JOB_STATES are exported for the pagination tests: exercising the arithmetic
// through list() alone would need a queue populated across all four states to cover the cases.
module.exports = {
    list,
    del,
    get,
    retry,
    promote,
    removeJobs,
    decodeQueueEntry,
    retainFailedContent,
    pruneFailedContent,
    listRetainedFailedContent,
    selectPageRanges,
    outboxKey,
    JOB_STATES,
    FAILED_CONTENT_KEY,
    FAILED_CONTENT_LIMITS
};
