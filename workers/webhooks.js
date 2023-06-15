'use strict';

const { parentPort } = require('worker_threads');

const packageData = require('../package.json');
const config = require('wild-config');
const logger = require('../lib/logger');
const { webhooks: Webhooks } = require('../lib/webhooks');

const { readEnvValue, threadStats } = require('../lib/tools');

const Bugsnag = require('@bugsnag/js');
if (readEnvValue('BUGSNAG_API_KEY')) {
    Bugsnag.start({
        apiKey: readEnvValue('BUGSNAG_API_KEY'),
        appVersion: packageData.version,
        logger: {
            debug(...args) {
                logger.debug({ msg: args.shift(), worker: 'webhooks', source: 'bugsnag', args: args.length ? args : undefined });
            },
            info(...args) {
                logger.debug({ msg: args.shift(), worker: 'webhooks', source: 'bugsnag', args: args.length ? args : undefined });
            },
            warn(...args) {
                logger.warn({ msg: args.shift(), worker: 'webhooks', source: 'bugsnag', args: args.length ? args : undefined });
            },
            error(...args) {
                logger.error({ msg: args.shift(), worker: 'webhooks', source: 'bugsnag', args: args.length ? args : undefined });
            }
        }
    });
    logger.notifyError = Bugsnag.notify.bind(Bugsnag);
}

const { redis, queueConf } = require('../lib/db');
const { Worker } = require('bullmq');
const settings = require('../lib/settings');

const { REDIS_PREFIX, ACCOUNT_DELETED_NOTIFY, MESSAGE_NEW_NOTIFY, FETCH_TIMEOUT } = require('../lib/consts');
const he = require('he');

const { fetch: fetchCmd, Agent } = require('undici');
const fetchAgent = new Agent({ connect: { timeout: FETCH_TIMEOUT } });

config.queues = config.queues || {
    notify: 1
};

const NOTIFY_QC = (readEnvValue('EENGINE_NOTIFY_QC') && Number(readEnvValue('EENGINE_NOTIFY_QC'))) || config.queues.notify || 1;

function getAccountKey(account) {
    return `${REDIS_PREFIX}iad:${account}`;
}

async function metrics(logger, key, method, ...args) {
    try {
        parentPort.postMessage({
            cmd: 'metrics',
            key,
            method,
            args
        });
    } catch (err) {
        logger.error({ msg: 'Failed to post metrics to parent', err });
    }
}

async function onCommand(command) {
    switch (command.cmd) {
        case 'resource-usage':
            return threadStats.usage();
        default:
            logger.debug({ msg: 'Unhandled command', command });
            return 999;
    }
}

parentPort.on('message', message => {
    if (message && message.cmd === 'call' && message.mid) {
        return onCommand(message.message)
            .then(response => {
                parentPort.postMessage({
                    cmd: 'resp',
                    mid: message.mid,
                    response
                });
            })
            .catch(err => {
                parentPort.postMessage({
                    cmd: 'resp',
                    mid: message.mid,
                    error: err.message,
                    code: err.code,
                    statusCode: err.statusCode
                });
            });
    }
});

const notifyWorker = new Worker(
    'notify',
    async job => {
        // do not process active jobs, use it for debugging only
        //return new Promise((resolve, reject) => {});
        let accountKey = getAccountKey(job.data.account);

        // validate if we should even process this webhook
        let accountExists = await redis.exists(accountKey);
        if (!accountExists && job.name !== ACCOUNT_DELETED_NOTIFY) {
            logger.debug({
                msg: 'Account is not enabled',
                action: 'webhook',
                queue: job.queue.name,
                code: 'account_not_found',
                job: job.id,
                event: job.name,
                account: job.data.account
            });
            return;
        }

        let webhooksEnabled = await settings.get('webhooksEnabled');
        if (!webhooksEnabled) {
            return;
        }

        let customRoute;
        let customMapping;
        if (job.data._route && job.data._route.id) {
            customRoute = await Webhooks.getMeta(job.data._route.id);
            customMapping = job.data._route.mapping;
            delete job.data._route;
            if (!customRoute || !customRoute.enabled || !customRoute.targetUrl) {
                return;
            }
        }

        let accountWebhooks = await redis.hget(accountKey, 'webhooks');

        let webhooks = (customRoute && customRoute.targetUrl) || accountWebhooks || (await settings.get('webhooks'));
        if (!webhooks) {
            // logger.debug({ msg: 'Webhook URL is not set', action: 'webhook', event: job.name, account: job.data.account });
            return;
        }

        if (!customRoute) {
            // custom routes have their own mappings
            let webhookEvents = (await settings.get('webhookEvents')) || [];
            if (!webhookEvents.includes('*') && !webhookEvents.includes(job.name)) {
                logger.trace({
                    msg: 'Webhook event not in whitelist',
                    action: 'webhook',
                    queue: job.queue.name,
                    code: 'event_not_whitelisted',
                    job: job.id,
                    event: job.name,
                    account: job.data.account,
                    webhookEvents,
                    data: job.data
                });
                return;
            }

            switch (job.data.event) {
                case MESSAGE_NEW_NOTIFY: {
                    // check if we need to send this event or not
                    let isInbox = false;
                    if (
                        (job.data.account && job.data.path === 'INBOX') ||
                        job.data.specialUse === '\\Inbox' ||
                        (job.data.data && job.data.data.labels && job.data.data.labels.includes('\\Inbox'))
                    ) {
                        isInbox = true;
                    }

                    const inboxNewOnly = (await settings.get('inboxNewOnly')) || false;
                    if (inboxNewOnly && !isInbox) {
                        // ignore this message
                        return;
                    }

                    break;
                }
            }
        }

        // only log some of the properties for webhooks, not full contents
        let filteredData = {};
        for (let key of Object.keys(job.data)) {
            switch (key) {
                case 'data':
                    {
                        let filteredSubData = {};
                        let isPartial = false;
                        for (let dataKey of Object.keys(job.data.data)) {
                            switch (dataKey) {
                                case 'id':
                                case 'uid':
                                case 'path':
                                case 'messageId':
                                    filteredSubData[dataKey] = job.data.data[dataKey];
                                    break;
                                default:
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
                    break;
                default:
                    filteredData[key] = job.data[key];
            }
        }

        logger.trace({
            msg: 'Processing webhook',
            action: 'webhook',
            queue: job.queue.name,
            code: 'processing',
            job: job.id,
            webhooks,
            accountWebhooks: !!accountWebhooks,
            event: job.name,
            data: filteredData,
            account: job.data.account,
            route: customRoute && customRoute.id
        });

        let headers = {
            'Content-Type': 'application/json',
            'User-Agent': `${packageData.name}/${packageData.version} (+${packageData.homepage})`,
            'X-EE-Wh-Id': (job.id || '').toString(),
            'X-EE-Wh-Attempts-Made': (job.attemptsMade || 0).toString(),
            'X-EE-Wh-Queued-Time': Math.round(Math.max(0, (Date.now() - job.timestamp) / 1000)) + 's'
        };

        let parsed = new URL(webhooks);
        let username, password;

        if (parsed.username) {
            username = he.decode(parsed.username);
            parsed.username = '';
        }

        if (parsed.password) {
            password = he.decode(parsed.password);
            parsed.password = '';
        }

        if (username || password) {
            headers.Authorization = `Basic ${Buffer.from(he.encode(username || '') + ':' + he.encode(password || '')).toString('base64')}`;
        }

        if (customRoute) {
            headers['X-EE-Wh-Custom-Route'] = customRoute.id;
            for (let header of customRoute.customHeaders || []) {
                headers[header.key] = header.value;
            }
        } else {
            let webhookCustomHeaders = await settings.get('webhooksCustomHeaders');
            for (let header of webhookCustomHeaders || []) {
                headers[header.key] = header.value;
            }
        }

        let start = Date.now();
        let duration;

        let webhookPayload = customMapping || job.data;
        if (webhookPayload.eventId) {
            headers['X-EE-Wh-Event-Id'] = webhookPayload.eventId;
            webhookPayload.eventId = undefined; // not included in JSON
        }
        let body = Buffer.from(JSON.stringify(webhookPayload));

        try {
            let res;
            try {
                res = await fetchCmd(parsed.toString(), {
                    method: 'post',
                    body,
                    headers,
                    dispatcher: fetchAgent
                });
                duration = Date.now() - start;
            } catch (err) {
                duration = Date.now() - start;
                throw err;
            }

            if (!res.ok) {
                let err = new Error(`Invalid response: ${res.status} ${res.statusText}`);
                err.status = res.status;
                throw err;
            }

            logger.trace({
                msg: 'Webhook posted',
                action: 'webhook',
                queue: job.queue.name,
                code: 'result_success',
                job: job.id,
                webhooks,
                requestBodySize: body.length,
                accountWebhooks: !!accountWebhooks,
                event: job.name,
                status: res.status,
                account: job.data.account,
                route: customRoute && customRoute.id
            });

            try {
                if (customRoute) {
                    await redis.hset(Webhooks.getWebhooksContentKey(), `${customRoute.id}:webhookErrorFlag`, JSON.stringify({}));
                } else if (accountWebhooks) {
                    await redis.hset(accountKey, 'webhookErrorFlag', JSON.stringify({}));
                } else {
                    await settings.clear('webhookErrorFlag');
                }
            } catch (err) {
                // ignore
            }

            metrics(logger, 'webhooks', 'inc', {
                event: job.name,
                status: 'success'
            });
        } catch (err) {
            /*
            // do not disable by default
            if (err.status === 410) {
                // disable webhook
                logger.error({
                    msg: 'Webhooks were disabled by server',
                    action: 'webhook',
                    queue: job.queue.name,
                    code: 'disabled_by_server',
                    job: job.id,
                    webhooks,
                    accountWebhooks: !!accountWebhooks,
                    event: job.name,
                    status: err.status,
                    account: job.data.account,
route: customRoute && customRoute.id,
                    err
                });
                await settings.set('webhooksEnabled', false);
                return;
            }
            */
            logger.error({
                msg: 'Failed posting webhook',
                action: 'webhook',
                queue: job.queue.name,
                code: 'result_fail',
                job: job.id,
                webhooks,
                requestBodySize: body.length,
                accountWebhooks: !!accountWebhooks,
                event: job.name,
                account: job.data.account,
                route: customRoute && customRoute.id,
                err
            });

            try {
                if (customRoute) {
                    await redis.hset(
                        Webhooks.getWebhooksContentKey(),
                        `${customRoute.id}:webhookErrorFlag`,
                        JSON.stringify({
                            event: job.name,
                            message: err.message,
                            time: Date.now(),
                            url: customRoute.targetUrl
                        })
                    );
                } else if (accountWebhooks) {
                    await redis.hset(
                        accountKey,
                        'webhookErrorFlag',
                        JSON.stringify({
                            event: job.name,
                            message: err.message,
                            time: Date.now(),
                            url: webhooks
                        })
                    );
                } else {
                    await settings.set('webhookErrorFlag', {
                        event: job.name,
                        message: err.message,
                        time: Date.now(),
                        url: webhooks
                    });
                }
            } catch (err) {
                // ignore
            }

            metrics(logger, 'webhooks', 'inc', {
                event: job.name,
                status: 'fail'
            });

            throw err;
        } finally {
            if (duration) {
                metrics(logger, 'webhookReq', 'observe', duration);
            }
        }
    },
    Object.assign(
        {
            concurrency: Number(NOTIFY_QC) || 1
        },
        queueConf || {}
    )
);

notifyWorker.on('completed', async job => {
    metrics(logger, 'queuesProcessed', 'inc', {
        queue: 'notify',
        status: 'completed'
    });

    logger.info({
        msg: 'Notification queue entry completed',
        action: 'webhook',
        queue: job.queue.name,
        code: 'completed',
        job: job.id,
        account: job.data.account,
        route: job.data._route && job.data._route.id
    });
});

notifyWorker.on('failed', async job => {
    metrics(logger, 'queuesProcessed', 'inc', {
        queue: 'notify',
        status: 'failed'
    });

    logger.info({
        msg: 'Notification queue entry failed',
        action: 'webhook',
        queue: job.queue.name,
        code: 'failed',
        job: job.id,
        account: job.data.account,
        route: job.data._route && job.data._route.id,

        failedReason: job.failedReason,
        stacktrace: job.stacktrace,
        attemptsMade: job.attemptsMade
    });
});

logger.info({ msg: 'Started Webhooks worker thread', version: packageData.version });
