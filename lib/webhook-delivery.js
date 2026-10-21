'use strict';

// The notify queue's job processor: decides whether and where a queued webhook event is delivered,
// sends it, and records the outcome. It used to be written inline in workers/webhooks.js, which a
// test cannot import (requiring it starts a BullMQ worker and talks to the parent thread), so its
// decisions were only tested through the helpers it calls. Everything with a side effect is passed
// in, see createWebhookProcessor().

const { UnrecoverableError, DelayedError } = require('bullmq');

const { redactUrlCredentials, splitUrlCredentials } = require('./tools');
const { sendWebhookRequest, isUnrecoverableWebhookError, baseDeliveryHeaders, signDelivery } = require('./webhook-request');
const { willBeFinalAttempt } = require('./delivery-error');
const { penaltyKey, penaltyFor } = require('./webhook-penalty');
const {
    resolveTargetUrl,
    isDeliverableRoute,
    eventAllowed,
    defaultRouteTakes,
    headerLevels,
    deliveryCustomHeaders,
    isRouteMappingMissing
} = require('./webhook-routing');
const { REDIS_PREFIX, ACCOUNT_DELETED_NOTIFY, DEFAULT_WEBHOOK_REQUEST_TIMEOUT } = require('./consts');

// The payload fields of `data` that are logged as they are; anything else only marks it partial
const LOGGED_DATA_KEYS = new Set(['id', 'uid', 'path', 'messageId']);

const getAccountKey = account => `${REDIS_PREFIX}iad:${account}`;

/**
 * Log context shared by every line about one job
 * @param {Object} job - BullMQ job
 * @returns {Object} Fields to spread into a log entry
 */
const jobLogFields = job => ({ action: 'webhook', queue: job.queue.name, job: job.id, event: job.name, account: job.data.account });

/**
 * The job payload reduced to what is safe and useful to log: everything except `data`, of which
 * only the identifying fields are kept
 * @param {Object} payload - Job data
 * @returns {Object} Loggable copy
 */
function filterLogData(payload) {
    let filteredData = {};
    for (let key of Object.keys(payload)) {
        if (key !== 'data') {
            filteredData[key] = payload[key];
            continue;
        }

        let filteredSubData = {};
        let isPartial = false;
        for (let dataKey of Object.keys(payload.data || {})) {
            if (LOGGED_DATA_KEYS.has(dataKey)) {
                filteredSubData[dataKey] = payload.data[dataKey];
            } else {
                isPartial = true;
            }
        }
        if (isPartial) {
            if (Object.keys(filteredSubData).length) {
                filteredSubData.partial = true;
            } else {
                filteredSubData = true;
            }
        }
        filteredData[key] = filteredSubData;
    }
    return filteredData;
}

/**
 * Loads the custom route a job was queued for. Removes `_route` from the payload, so it is never
 * delivered
 * @returns {Promise<Object>} `{ skip }` when nothing is to be sent, otherwise `{ customRoute, customMapping }`
 */
async function loadCustomRoute(job, deps) {
    if (!job.data._route || !job.data._route.id) {
        return {};
    }

    let customRoute = await deps.webhooks.getMeta(job.data._route.id);
    let customMapping = job.data._route.mapping;
    let mappingMissing = isRouteMappingMissing(job.data._route);
    delete job.data._route;

    if (!isDeliverableRoute(customRoute)) {
        return { skip: true };
    }

    if (mappingMissing) {
        deps.logger.warn({
            msg: 'Custom webhook route has no mapped payload, not sending',
            ...jobLogFields(job),
            code: 'missing_mapping',
            route: customRoute.id
        });
        return { skip: true };
    }

    return { customRoute, customMapping };
}

/**
 * Parses the account's custom header list. A value that does not parse is ignored, as before
 * @returns {Object[]|undefined} Header entries
 */
function parseAccountHeaders(json, job, logger) {
    if (!json) {
        return undefined;
    }
    try {
        return JSON.parse(json);
    } catch (err) {
        // do not log the header values, they may carry authentication secrets
        logger.debug({ msg: 'Failed to parse custom webhook headers', ...jobLogFields(job), jsonLength: json.length, err });
        return undefined;
    }
}

/**
 * Delays the job while its target is penalised; see lib/webhook-penalty.js. The attempt count is
 * not spent by the wait
 * @returns {Promise<string|null>} The target's penalty key, for recordFailure()
 * @throws {DelayedError} When the job was moved to the delayed set
 */
async function waitOutPenalty(job, token, webhooks, deps) {
    const targetPenaltyKey = penaltyKey(webhooks);
    if (!targetPenaltyKey) {
        return null;
    }
    let remaining = await deps.redis.pttl(targetPenaltyKey);
    if (remaining > 0) {
        deps.logger.debug({
            msg: 'Webhook target is penalised, delaying delivery',
            ...jobLogFields(job),
            code: 'target_penalised',
            webhooks: redactUrlCredentials(webhooks),
            delay: remaining
        });
        await job.moveToDelayed(Date.now() + remaining, token);
        throw new DelayedError();
    }
    return targetPenaltyKey;
}

/**
 * Decides whether a job is delivered and, if it is, where and with which header lists. Every
 * check that can skip a job runs here, in the order the inline processor ran them
 * @returns {Promise<Object|null>} Delivery plan, or null when the job is completed without sending
 */
async function planDelivery(job, token, deps) {
    const { redis, settings, logger, openAccountField } = deps;
    let accountKey = getAccountKey(job.data.account);

    // Keep the route id reachable for the completed/failed event handlers, which see this same
    // job instance after _route has been deleted from the payload. Stashed before the early
    // returns below so a job that never reaches delivery still reports which route queued it.
    if (job.data._route && job.data._route.id) {
        job.__routeId = job.data._route.id;
    }

    // One round trip for the existence check and the two account fields a delivery may need.
    // The fields are opened where they are used, below.
    let [accountExists, storedWebhooks, storedCustomHeaders] = await redis.hmget(accountKey, 'account', 'webhooks', 'webhooksCustomHeaders');
    if (!accountExists && job.name !== ACCOUNT_DELETED_NOTIFY) {
        logger.debug({ msg: 'Account not found', ...jobLogFields(job), code: 'account_not_found' });
        return null;
    }

    if (!(await settings.get('webhooksEnabled'))) {
        logger.debug({ msg: 'Webhooks are disabled', ...jobLogFields(job), code: 'webhooks_disabled' });
        return null;
    }

    let { skip, customRoute, customMapping } = await loadCustomRoute(job, deps);
    if (skip) {
        return null;
    }

    let accountWebhooks = await openAccountField('webhooks', storedWebhooks, job.data.account);

    // the global setting is only fetched when neither a custom route nor the account override decides the target
    let target = resolveTargetUrl(customRoute && customRoute.targetUrl, accountWebhooks, null);
    if (!target.url) {
        target = resolveTargetUrl(null, null, await settings.get('webhooks'));
    }
    let webhooks = target.url;
    if (!webhooks) {
        // A skipped delivery still reports the job as completed, so without this line a
        // missing target is indistinguishable from a successful delivery - it reads as the
        // receiver being slow rather than as nothing having been sent
        logger.debug({ msg: 'Webhook URL is not set', ...jobLogFields(job), code: 'no_target_url' });
        return null;
    }

    const targetPenaltyKey = await waitOutPenalty(job, token, webhooks, deps);

    // Only the header lists that travel to this target are loaded; lib/webhook-routing.js
    // holds the rule and the reasons
    let levels = headerLevels(target.source);
    let accountHeadersJson = levels.includes('account') ? await openAccountField('webhooksCustomHeaders', storedCustomHeaders, job.data.account) : null;
    let accountCustomHeaders = parseAccountHeaders(accountHeadersJson, job, logger);

    if (!customRoute) {
        // custom routes have their own mappings; the default route follows webhookEvents and
        // inboxNewOnly, by the same rule pushToQueue() applied before queueing
        let { webhookEvents, inboxNewOnly } = await settings.getMulti('webhookEvents', 'inboxNewOnly');
        if (!defaultRouteTakes(job.name, job.data, { webhookEvents, inboxNewOnly })) {
            logger.trace({
                msg: 'Webhook event not taken by the default route',
                ...jobLogFields(job),
                code: eventAllowed(webhookEvents, job.name) ? 'inbox_new_only' : 'event_not_whitelisted',
                webhookEvents
            });
            return null;
        }
    }

    return {
        accountKey,
        customRoute,
        customMapping,
        accountWebhooks,
        target,
        // never log the raw target URL, it may embed basic auth credentials
        redactedWebhooks: redactUrlCredentials(webhooks),
        accountCustomHeaders,
        targetPenaltyKey
    };
}

/**
 * Builds the request: the body, and every header that goes with it, the signature last
 * @returns {Promise<Object>} `{ url, headers, body }`
 */
async function buildRequest(job, plan, deps) {
    let { url: parsed, authorization } = splitUrlCredentials(plan.target.url);
    let headers = Object.assign(baseDeliveryHeaders(authorization), {
        'X-EE-Wh-Id': (job.id || '').toString(),
        'X-EE-Wh-Attempts-Made': (job.attemptsMade || 0).toString(),
        'X-EE-Wh-Queued-Time': Math.round(Math.max(0, (Date.now() - job.timestamp) / 1000)) + 's'
    });

    if (plan.customRoute) {
        headers['X-EE-Wh-Custom-Route'] = plan.customRoute.id;
    }
    Object.assign(
        headers,
        deliveryCustomHeaders(plan.target.source, {
            route: plan.customRoute && plan.customRoute.customHeaders,
            global: headerLevels(plan.target.source).includes('global') ? await deps.settings.get('webhooksCustomHeaders') : null,
            account: plan.accountCustomHeaders
        })
    );

    let webhookPayload = plan.customMapping || job.data;
    if (webhookPayload.eventId) {
        headers['X-EE-Wh-Event-Id'] = webhookPayload.eventId;
        webhookPayload.eventId = undefined; // not included in JSON
    }
    let body = Buffer.from(JSON.stringify(webhookPayload));

    // Explicitly set Content-Length to prevent undici mismatch errors
    headers['Content-Length'] = body.length.toString();

    signDelivery(headers, body, await deps.getServiceSecret());

    return { url: parsed.toString(), headers, body };
}

/**
 * Writes the error flag of whichever level decided the target: the custom route, the account
 * override or the global setting. An empty flag clears it, by removing the field: every successful
 * delivery clears, and a removal of a field that is not there changes nothing, so Redis neither
 * writes nor replicates it. Never throws, a missed flag write must not change the outcome of the
 * delivery
 */
async function writeErrorFlag(plan, flag, deps) {
    try {
        if (plan.customRoute || plan.accountWebhooks) {
            const [key, field] = plan.customRoute
                ? [deps.webhooks.getWebhooksContentKey(), `${plan.customRoute.id}:webhookErrorFlag`]
                : [plan.accountKey, 'webhookErrorFlag'];
            await (flag ? deps.redis.hset(key, field, JSON.stringify(flag)) : deps.redis.hdel(key, field));
        } else if (flag) {
            await deps.settings.set('webhookErrorFlag', flag);
        } else {
            await deps.settings.clear('webhookErrorFlag');
        }
    } catch (err) {
        // ignore
    }
}

/**
 * Records a failed attempt everywhere it is read back: the target penalty, the job's progress
 * field (for the queue browser), the log, the error flag and the metrics
 */
async function recordFailure(job, plan, request, err, duration, deps) {
    const { redis, logger } = deps;

    // egress and redirect failures are thrown as UnrecoverableError, so they are final as well
    let isFinalAttempt = willBeFinalAttempt(job) || isUnrecoverableWebhookError(err);

    // A target that held the attempt until it timed out is penalised so the next deliveries to
    // it do not each cost the same wait
    let penalty = penaltyFor(err, deps.timeout || DEFAULT_WEBHOOK_REQUEST_TIMEOUT);
    if (penalty && plan.targetPenaltyKey) {
        try {
            await redis.set(plan.targetPenaltyKey, '1', 'PX', penalty);
        } catch (penaltyErr) {
            // a missed penalty costs the queue one more timeout, nothing else
        }
    }

    // BullMQ keeps only the message of a failure on the job. The code and the HTTP status
    // are what explain it, so they are recorded the way the submit worker records its own
    // delivery errors, for the queue browser to read back
    try {
        await job.updateProgress({ status: 'error', error: { message: err.message, code: err.code, statusCode: err.statusCode }, duration });
    } catch (progressErr) {
        // ignore
    }

    logger[isFinalAttempt ? 'error' : 'warn']({
        msg: 'Failed posting webhook',
        ...jobLogFields(job),
        code: 'result_fail',
        webhooks: plan.redactedWebhooks,
        requestBodySize: request.body.length,
        accountWebhooks: !!plan.accountWebhooks,
        route: plan.customRoute && plan.customRoute.id,
        err
    });

    await writeErrorFlag(
        plan,
        {
            event: job.name,
            message: err.message,
            time: Date.now(),
            // stored without credentials: the flag is read back through the webhook route
            // listing, the account page and the settings API. A route's own URL is the target
            url: plan.redactedWebhooks,
            code: err.code,
            statusCode: err.statusCode
        },
        deps
    );

    deps.metrics('webhooks', 'inc', { event: job.name, status: 'fail' });
}

/**
 * Sends a planned delivery and records the outcome
 * @returns {Promise<Object>} The job's return value, stored by BullMQ
 */
async function deliver(job, plan, deps) {
    const { logger } = deps;

    // the redacted target stays reachable for the failed event handler
    job.__redactedTargetUrl = plan.redactedWebhooks;

    logger.trace({
        msg: 'Processing webhook',
        ...jobLogFields(job),
        code: 'processing',
        webhooks: plan.redactedWebhooks,
        accountWebhooks: !!plan.accountWebhooks,
        data: filterLogData(job.data),
        route: plan.customRoute && plan.customRoute.id
    });

    let request = await buildRequest(job, plan, deps);

    let start = Date.now();
    let duration;
    try {
        let status;
        try {
            status = await sendWebhookRequest(deps.fetch, request.url, {
                method: 'post',
                body: request.body,
                headers: request.headers,
                dispatcher: deps.dispatcher,
                timeout: deps.timeout,
                validateTarget: deps.validateTarget
            });
            duration = Date.now() - start;
        } catch (err) {
            duration = Date.now() - start;
            throw err.cause || err;
        }

        logger.trace({
            msg: 'Webhook posted',
            ...jobLogFields(job),
            code: 'result_success',
            webhooks: plan.redactedWebhooks,
            requestBodySize: request.body.length,
            accountWebhooks: !!plan.accountWebhooks,
            status,
            route: plan.customRoute && plan.customRoute.id
        });

        await writeErrorFlag(plan, null, deps);
        deps.metrics('webhooks', 'inc', { event: job.name, status: 'success' });

        // Stored by BullMQ as the job's return value in the same write that completes it, so
        // a retained completed job shows what the endpoint answered and how long it took
        return { status: 'delivered', statusCode: status, duration };
    } catch (err) {
        await recordFailure(job, plan, request, err, duration, deps);

        // Spending the remaining attempts on an unrecoverable failure only delays the operator
        // seeing the real reason in the error flag. Fail the job now and keep the message.
        if (isUnrecoverableWebhookError(err)) {
            // UnrecoverableError copies the message only, and the failed-event handler logs the
            // error it is given, so carry the code over or that log loses the actual reason
            let unrecoverableErr = new UnrecoverableError(err.message);
            unrecoverableErr.code = err.code;
            throw unrecoverableErr;
        }

        throw err;
    } finally {
        if (duration) {
            deps.metrics('webhookReq', 'observe', duration);
        }
    }
}

/**
 * Creates the notify queue's job processor
 * @param {Object} deps
 * @param {Object} deps.redis - ioredis client (hmget, pttl, set, hset)
 * @param {Object} deps.settings - lib/settings (get, getMulti, set, clear)
 * @param {Object} deps.webhooks - lib/webhooks instance (getMeta, getWebhooksContentKey)
 * @param {Object} deps.logger - pino logger
 * @param {Function} deps.metrics - (key, method, ...args) metrics reporter
 * @param {Function} deps.openAccountField - (field, value, account) decrypts an account field
 * @param {Function} deps.getServiceSecret - Resolves the HMAC signing secret
 * @param {Function} deps.fetch - fetch implementation
 * @param {Object} [deps.dispatcher] - undici dispatcher
 * @param {number|false} [deps.timeout] - Attempt timeout in ms, false for the default
 * @param {Function} [deps.validateTarget] - Egress policy check
 * @returns {Function} async (job, token) => result
 */
function createWebhookProcessor(deps) {
    return async function processWebhookJob(job, token) {
        let plan = await planDelivery(job, token, deps);
        if (!plan) {
            return;
        }
        return await deliver(job, plan, deps);
    };
}

module.exports = { createWebhookProcessor, filterLogData };
