'use strict';

// The queue browser behind /admin/queues: counts, listings, job details and the actions the
// pages offer, over the three BullMQ queues. Everything that touches Redis lives here; the
// wording and the per-job formatting are in ./format and ./definitions, which are pure.
//
// The submit queue is special in one way the generic BullMQ operations cannot see: a message's
// content lives outside its job, in the account's outbox hash. Removing a job without that
// content orphans the message in Redis, and retrying one whose content is gone sends nothing
// while reporting success, which is what the bull-board buttons this replaced used to do. So
// the submit queue's actions are lib/outbox's, which owns both halves; the per-queue table
// below is where that difference lives, and the rest of this module does not branch on it.

const config = require('@zone-eu/wild-config');
const { QUEUES_BY_NAME: QUEUE_OBJECTS_BY_NAME, exportQueue, redis } = require('../db');
const { readEnvValue } = require('../read-env-value');
const { accountsExist } = require('../account');
const { webhooks: Webhooks } = require('../webhooks');
const outbox = require('../outbox');
const settings = require('../settings');
const { buildRetentionPolicy, FAILED_JOB_RETENTION_COUNT } = require('../queue-retention');
const { maskSecrets } = require('../api-routes/route-helpers');
const { statusError } = require('../utils/status-error');
const { retryFailedJob, promoteDelayedJob, assertJobState } = require('../queue-job-actions');
const { QUEUES, QUEUES_BY_NAME, STATES, STATES_BY_NAME, STATE_NAMES, SCAN_LIMIT, BATCH_SIZE } = require('./definitions');
const { formatJob, matchesQuery, rawJob, humanSize, notifyPayloadSize, entryUrl } = require('./format');

// lib/db keys the API-addressable queues by name and leaves the export queue out on purpose;
// the browser shows it, read-only
const QUEUE_OBJECTS = Object.assign({ export: exportQueue }, QUEUE_OBJECTS_BY_NAME);

function queueObject(queueDef) {
    return QUEUE_OBJECTS[queueDef.name];
}

/**
 * The state of one job, for a route that has to know where an entry was before acting on it.
 *
 * @param {Object} queueDef - Queue definition
 * @param {string} jobId - Job ID
 * @returns {Promise<string|null>} BullMQ state, or null when there is no such job
 */
async function jobState(queueDef, jobId) {
    const job = await queueObject(queueDef).getJob(jobId);
    return job ? await job.getState() : null;
}

/**
 * Removes a job through BullMQ alone: refused, as `locked`, when a worker is running it.
 */
async function removeBullJob(queueDef, jobId, logger) {
    const job = await queueObject(queueDef).getJob(jobId);
    if (!job) {
        return { removed: false };
    }
    if (await job.isActive()) {
        return { removed: false, locked: true };
    }

    try {
        await job.remove();
    } catch (err) {
        // the lock was taken between the check and the removal
        logger.warn({ msg: 'Failed to remove a queue job', queue: queueDef.name, job: jobId, err });
        return { removed: false, locked: true };
    }

    logger.info({ msg: 'Removed queue job', queue: queueDef.name, job: jobId, event: job.name, account: job.data && job.data.account });
    return { removed: true };
}

async function retryBullJob(queueDef, jobId, logger) {
    const job = await queueObject(queueDef).getJob(jobId);
    if (!job) {
        return false;
    }
    await assertJobState(job, 'failed', queueDef.noun, 'retried');
    await retryFailedJob(job, queueDef.noun);
    logger.info({ msg: 'Retrying failed queue job', queue: queueDef.name, job: jobId, event: job.name, account: job.data && job.data.account });
    return true;
}

async function promoteBullJob(queueDef, jobId, logger) {
    const job = await queueObject(queueDef).getJob(jobId);
    if (!job) {
        return false;
    }
    await assertJobState(job, 'delayed', queueDef.noun, 'sent now');
    await promoteDelayedJob(job, queueDef.noun);
    logger.info({ msg: 'Promoted delayed queue job', queue: queueDef.name, job: jobId, event: job.name, account: job.data && job.data.account });
    return true;
}

// Why a failed message offers no retry once its content is gone: shown on the Retry that is kept
// visible but disabled, so the reader learns why rather than wondering where it went
const CONTENT_GONE_REASON = 'The message content is no longer stored, so there is nothing to send. Submit the message again instead.';

// What each queue's actions do, and what its listing needs decorated. The submit entries are
// lib/outbox's own operations; `afterClean` is what a cleaned failed set leaves behind.
const QUEUE_OPS = {
    submit: {
        remove: ({ jobId, logger }) => outbox.del({ queueId: jobId, logger }).then(result => ({ removed: !!result.deleted, locked: !!result.locked })),
        retry: ({ jobId, logger }) => outbox.retry({ queueId: jobId, logger }).then(Boolean),
        promote: ({ jobId, logger }) => outbox.promote({ queueId: jobId, logger }).then(Boolean),
        afterClean: ({ state, logger }) => (state === 'failed' ? outbox.pruneFailedContent({ logger }) : null),
        // whether a failed message still has its content, which is what a retry needs
        decorate: async entries => {
            const failed = entries.filter(entry => entry.state === 'failed' && entry.account);
            if (!failed.length) {
                return;
            }
            const pipeline = redis.pipeline();
            for (const entry of failed) {
                pipeline.hexists(outbox.outboxKey(entry.account), entry.id);
            }
            const results = await pipeline.exec();
            failed.forEach((entry, i) => {
                const retriable = entry.canRetry;
                entry.hasContent = !!(results[i] && results[i][1] === 1);
                entry.canRetry = retriable && entry.hasContent;
                // a failed message without content keeps its Retry visible, disabled, with the why
                entry.retryBlockedReason = retriable && !entry.hasContent ? CONTENT_GONE_REASON : null;
            });
        }
    },
    notify: {
        remove: ({ queue, jobId, logger }) => removeBullJob(queue, jobId, logger),
        retry: ({ queue, jobId, logger }) => retryBullJob(queue, jobId, logger),
        promote: ({ queue, jobId, logger }) => promoteBullJob(queue, jobId, logger),
        afterClean: () => null,
        // the name of the webhook route a delivery was queued for, and whether it still exists
        decorate: async (entries, logger) => {
            const routeIds = Array.from(new Set(entries.map(entry => entry.routeId).filter(Boolean)));
            const names = new Map();
            await Promise.all(
                routeIds.map(async routeId => {
                    try {
                        const meta = await Webhooks.getMeta(routeId);
                        names.set(routeId, meta && meta.name ? meta.name : null);
                    } catch (err) {
                        logger.error({ msg: 'Failed to resolve a webhook route', webhook: routeId, err });
                    }
                })
            );
            for (const entry of entries) {
                if (entry.routeId) {
                    entry.routeName = names.get(entry.routeId) || null;
                    // a route that no longer exists is skipped by the worker, which is worth saying
                    entry.routeKnown = !!names.get(entry.routeId);
                }
            }
        }
    },
    export: {
        afterClean: () => null,
        decorate: async () => {}
    }
};

/**
 * How many jobs a queue can run at once, and where that number comes from.
 *
 * The same expressions the main thread and the workers evaluate at startup, because the API
 * worker holds its own copy of the config object and the main thread's env overrides never reach
 * it.
 *
 * @param {Object} queueDef - Queue definition
 * @returns {{workers: number, perWorker: number, total: number, workersEnv: string, concurrencyEnv: string}}
 */
function concurrencyInfo(queueDef) {
    const { workersEnv, workersConfig, concurrencyEnv, concurrencyConfig } = queueDef.concurrency;
    const workers = Number(readEnvValue(workersEnv)) || (config.workers && config.workers[workersConfig]) || 1;
    const perWorker = Number(readEnvValue(concurrencyEnv)) || (config.queues && config.queues[concurrencyConfig]) || 1;
    return { workers, perWorker, total: workers * perWorker, workersEnv, concurrencyEnv };
}

/**
 * Job counts per state plus the paused flag, for one queue.
 *
 * @param {Object} queueDef - Queue definition
 * @returns {Promise<Object>} `{ counts: {waiting, active, delayed, failed, completed}, isPaused }`
 */
async function queueCounts(queueDef) {
    const queueObj = queueObject(queueDef);
    const [raw, isPaused] = await Promise.all([queueObj.getJobCounts(...STATE_NAMES), queueObj.isPaused()]);

    const counts = {};
    for (const state of STATE_NAMES) {
        counts[state] = Number(raw[state]) || 0;
    }

    return { counts, isPaused: !!isPaused };
}

/**
 * The counts of every queue, keyed by name - what the pages poll.
 *
 * @returns {Promise<Object>}
 */
async function allCounts() {
    const result = {};
    await Promise.all(
        QUEUES.map(async queueDef => {
            result[queueDef.name] = await queueCounts(queueDef);
        })
    );
    return result;
}

/**
 * What the retained failed-message content amounts to, for the overview.
 *
 * @returns {Promise<Object>} `{ count, bytes, bytesLabel, limits: {maxCount, maxBytes, maxBytesLabel, maxAgeDays} }`
 */
const toDays = seconds => Math.round(seconds / (24 * 3600));

/**
 * What the overview says is kept: the options the webhook and submit jobs are queued with, read
 * the way lib/webhooks.js and base-client.js read them. (Export jobs are not kept at all; the
 * help text says so.)
 *
 * @param {number|null} queueKeep - The `queueKeep` setting as stored
 * @returns {Object} `{ completedCount, failedCount, failedCountFloor, failedCountFromSetting, failedAgeDays }`
 */
function describeRetention(queueKeep) {
    const { removeOnComplete, removeOnFail } = buildRetentionPolicy(queueKeep ?? true);
    return {
        // The failed count is the environment floor or the queueKeep setting, whichever is higher,
        // so a page that says where the number comes from has to know which one won
        failedCountFloor: FAILED_JOB_RETENTION_COUNT,
        failedCountFromSetting: removeOnFail.count > FAILED_JOB_RETENTION_COUNT,
        // a boolean here is BullMQ's "remove as soon as it completes"; server.js seeds the setting
        // with a number at boot, so this is the unset case only
        completedCount: typeof removeOnComplete === 'object' ? removeOnComplete.count : 0,
        failedCount: removeOnFail.count,
        failedAgeDays: toDays(removeOnFail.age)
    };
}

async function failedContentSummary() {
    const entries = await outbox.listRetainedFailedContent();
    const bytes = entries.reduce((sum, entry) => sum + (Number(entry.size) || 0), 0);
    return { count: entries.length, bytes, bytesLabel: humanSize(bytes), limits: failedContentLimits() };
}

/**
 * The bounds on retained failed-message content, for the pages that say what can be retried.
 *
 * @returns {Object} `{ maxCount, maxBytes, maxBytesLabel, maxAgeDays, keepsContent }`
 */
function failedContentLimits() {
    const limits = outbox.FAILED_CONTENT_LIMITS;
    return {
        maxCount: limits.maxCount,
        maxBytes: limits.maxBytes,
        maxBytesLabel: humanSize(limits.maxBytes),
        maxAgeDays: toDays(limits.maxAge),
        // either bound at zero keeps no content at all
        keepsContent: limits.maxCount > 0 && limits.maxBytes > 0
    };
}

/**
 * What is kept of completed and failed jobs, for the pages that say so.
 *
 * @returns {Promise<Object>} See `describeRetention()`
 */
async function retention() {
    return describeRetention(await settings.get('queueKeep'));
}

/**
 * What one account holds in the queues, for the card on its page: the messages still to send,
 * the failed ones kept for a retry, and the links to the filtered listings.
 *
 * The account's outbox hash has one field per message that still has content, which is every
 * pending message plus the failed ones retained for a retry; the retained set says which are
 * which.
 *
 * @param {string} account - Account ID
 * @returns {Promise<Object>} `{ pending, failed, url, failedUrl, webhooksUrl }`
 */
async function accountQueueSummary(account) {
    const [outboxSize, retained] = await Promise.all([redis.hlen(outbox.outboxKey(account)), outbox.listRetainedFailedContent()]);
    const failed = retained.filter(entry => entry.account === account).length;
    const filter = `account=${encodeURIComponent(account)}`;

    return {
        pending: Math.max(outboxSize - failed, 0),
        failed,
        url: `/admin/queues/submit?${filter}`,
        failedUrl: `/admin/queues/submit?state=failed&${filter}`,
        webhooksUrl: `/admin/queues/notify?state=failed&${filter}`
    };
}

/**
 * The overview page's model: every queue with its counts, paused flag and concurrency.
 *
 * @returns {Promise<Object>} `{ queues, states, failedContent, retention }`
 */
async function overview() {
    const [statuses, failedContent, kept] = await Promise.all([Promise.all(QUEUES.map(queueCounts)), failedContentSummary(), retention()]);

    const queues = QUEUES.map((queueDef, i) =>
        Object.assign({}, queueDef, statuses[i], {
            concurrency: concurrencyInfo(queueDef),
            stateCounts: STATES.map(state =>
                Object.assign({}, state, { count: statuses[i].counts[state.name], url: `/admin/queues/${queueDef.name}?state=${state.name}` })
            )
        })
    );

    return { queues, states: STATES, failedContent, retention: kept };
}

/**
 * Reads the jobs for a list of IDs, in order, dropping the ones that vanished meanwhile.
 *
 * @param {Object} queueObj - BullMQ Queue
 * @param {string[]} ids - Job IDs
 * @param {Object} logger - Logger instance
 * @returns {Promise<Object[]>} Jobs
 */
async function loadJobs(queueObj, ids, logger) {
    const jobs = [];
    for (let i = 0; i < ids.length; i += BATCH_SIZE) {
        const batch = await Promise.all(
            ids.slice(i, i + BATCH_SIZE).map(async id => {
                try {
                    return await queueObj.getJob(id);
                } catch (err) {
                    logger.error({ msg: 'Failed to read a queue job', queue: queueObj.name, job: id, err });
                    return null;
                }
            })
        );
        for (const job of batch) {
            if (job) {
                jobs.push(job);
            }
        }
    }
    return jobs;
}

/**
 * Fills in what a row cannot know from the job alone: whether the account still exists, plus
 * whatever the queue's own decoration adds (a route name, a message's retained content).
 *
 * @param {Object} queueDef - Queue definition
 * @param {Object[]} entries - Formatted entries
 * @param {Object} logger - Logger instance
 */
async function decorateEntries(queueDef, entries, logger) {
    if (!entries.length) {
        return;
    }

    const [known] = await Promise.all([
        accountsExist(redis, Array.from(new Set(entries.map(entry => entry.account).filter(Boolean)))),
        QUEUE_OPS[queueDef.name].decorate(entries, logger)
    ]);

    for (const entry of entries) {
        entry.accountKnown = entry.account ? !!known.get(entry.account) : false;
    }
}

/**
 * One page of a queue's jobs in a state, optionally filtered.
 *
 * Without a filter the page is read straight out of the state's list, so the cost is one page
 * of jobs whatever the queue holds. With a filter the state is scanned from its head up to
 * SCAN_LIMIT jobs and the matches paged in memory; the result says how far the scan went so the
 * page can tell the reader when a busy queue was not searched to the end.
 *
 * @param {Object} options
 * @param {Object} options.queue - Queue definition
 * @param {string} options.state - Job state
 * @param {number} [options.stateTotal] - How many jobs the state holds, when the caller counted already
 * @param {number} [options.page] - Zero-based page
 * @param {number} [options.pageSize] - Entries per page
 * @param {string} [options.query] - Free-text filter
 * @param {string} [options.account] - Account filter (exact)
 * @param {string} [options.route] - Webhook route filter (exact, notify queue)
 * @param {Object} options.logger - Logger instance
 * @returns {Promise<Object>} `{ entries, total, page, pages, filtered, scanned, scanLimited, stateTotal }`
 */
async function listJobs(options) {
    const { queue: queueDef, state, logger } = options;
    const page = Math.max(Number(options.page) || 0, 0);
    const pageSize = Math.max(Number(options.pageSize) || 20, 1);
    const query = options.query || '';
    const account = options.account || '';
    const route = options.route || '';

    const queueObj = queueObject(queueDef);
    const asc = !STATES_BY_NAME.get(state).newestFirst;

    const stateTotal = typeof options.stateTotal === 'number' ? options.stateTotal : Number((await queueObj.getJobCounts(state))[state]) || 0;

    let entries;
    let total;
    let scanned = 0;
    let scanLimited = false;
    const filtered = !!(query || account || route);

    if (!filtered) {
        total = stateTotal;
        const start = page * pageSize;
        const ids = start < total ? await queueObj.getRanges([state], start, start + pageSize - 1, asc) : [];
        const jobs = await loadJobs(queueObj, ids, logger);
        entries = jobs.map(job => formatJob(queueDef, job, state));
    } else {
        // Every ID of the scan window in one read, then the jobs in batches
        const ids = stateTotal ? await queueObj.getRanges([state], 0, SCAN_LIMIT - 1, asc) : [];
        const jobs = await loadJobs(queueObj, ids, logger);
        scanned = ids.length;
        scanLimited = scanned >= SCAN_LIMIT && stateTotal > scanned;

        const matches = jobs.filter(job => {
            const data = job.data || {};
            return (!account || data.account === account) && (!route || (data._route && data._route.id === route)) && matchesQuery(queueDef, job, query);
        });
        total = matches.length;
        entries = matches.slice(page * pageSize, (page + 1) * pageSize).map(job => formatJob(queueDef, job, state));
    }

    await decorateEntries(queueDef, entries, logger);

    return {
        entries,
        total,
        page,
        pages: Math.max(Math.ceil(total / pageSize), 1),
        filtered,
        scanned,
        scanLimited,
        stateTotal
    };
}

/**
 * One job, formatted for its detail page, with the raw record beside it.
 *
 * @param {Object} options
 * @param {Object} options.queue - Queue definition
 * @param {string} options.jobId - Job ID
 * @param {Object} options.logger - Logger instance
 * @returns {Promise<Object|null>} `{ entry, raw }`, or null when there is no such job
 */
async function getJob(options) {
    const { queue: queueDef, jobId, logger } = options;

    const job = await queueObject(queueDef).getJob(jobId);
    if (!job) {
        return null;
    }

    const state = await job.getState();
    if (state === 'unknown') {
        return null;
    }

    const entry = formatJob(queueDef, job, state);
    await decorateEntries(queueDef, [entry], logger);

    const raw = rawJob(job);
    if (queueDef.name === 'submit') {
        // The stored data of a submission names the proxy it was told to use, credentials
        // included, and a failed one records the route it took. Masked the way the outbox API
        // masks them, on a copy, so the page shows the record without echoing a password
        raw.data = maskSecrets(structuredClone(raw.data || {}));
        if (raw.progress) {
            raw.progress = maskSecrets(structuredClone(raw.progress));
        }
    } else if (queueDef.name === 'notify') {
        entry.payloadSizeLabel = humanSize(notifyPayloadSize(job));
    }

    return { entry, raw };
}

/**
 * Pauses or resumes a queue. A paused queue keeps accepting jobs; the workers stop taking them.
 *
 * @param {Object} queueDef - Queue definition
 * @param {boolean} paused - Whether the queue should be paused
 * @returns {Promise<boolean>} The queue's paused state afterwards
 */
async function setPaused(queueDef, paused) {
    const queueObj = queueObject(queueDef);
    if (paused) {
        await queueObj.pause();
    } else {
        await queueObj.resume();
    }
    return !!(await queueObj.isPaused());
}

/**
 * Removes every finished job of a state: the completed or the failed set. For the submit queue a
 * cleaned failed set takes the retained message contents with it, which is what BullMQ's own
 * clean cannot do.
 *
 * @param {Object} options
 * @param {Object} options.queue - Queue definition
 * @param {string} options.state - `completed` or `failed`
 * @param {Object} options.logger - Logger instance
 * @returns {Promise<number>} How many jobs were removed
 */
async function cleanQueue(options) {
    const { queue: queueDef, state, logger } = options;
    if (!['completed', 'failed'].includes(state)) {
        throw statusError('Only completed and failed jobs can be cleaned', 'NotCleanable', 409);
    }

    const removed = await queueObject(queueDef).clean(0, 1000000, state);
    await QUEUE_OPS[queueDef.name].afterClean({ state, logger });

    logger.info({ msg: 'Queue cleaned', queue: queueDef.name, state, removed: removed.length });
    return removed.length;
}

/**
 * Runs one of the per-job actions, after checking the queue offers it.
 *
 * @param {string} action - remove, retry or promote
 * @param {Object} options
 * @param {Object} options.queue - Queue definition
 * @param {string} options.jobId - Job ID
 * @param {Object} options.logger - Logger instance
 * @returns {Promise<Object|boolean>} For remove `{ removed, locked }`; otherwise false when there is no such job, true when done
 * @throws {Error} With `statusCode` 409 when the queue does not offer the action or the job is in the wrong state
 */
async function runJobAction(action, options) {
    const { queue: queueDef } = options;
    const run = queueDef.actions[action] && QUEUE_OPS[queueDef.name][action];
    if (!run) {
        throw statusError(
            `A ${queueDef.noun} cannot be ${action === 'remove' ? 'removed' : action === 'retry' ? 'retried' : 'promoted'} from here`,
            'NotOffered',
            409
        );
    }
    return run(options);
}

module.exports = {
    QUEUES_BY_NAME,
    STATES,
    STATES_BY_NAME,
    overview,
    retention,
    failedContentLimits,
    accountQueueSummary,
    allCounts,
    queueCounts,
    listJobs,
    getJob,
    jobState,
    entryUrl,
    setPaused,
    cleanQueue,
    runJobAction,
    concurrencyInfo
};
