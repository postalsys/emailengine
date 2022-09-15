'use strict';

if (!process.env.EE_ENV_LOADED) {
    require('dotenv').config(); // eslint-disable-line global-require
    process.env.EE_ENV_LOADED = 'true';
}

try {
    process.chdir(__dirname);
} catch (err) {
    // ignore
}

process.title = 'emailengine';

const os = require('os');
process.env.UV_THREADPOOL_SIZE =
    process.env.UV_THREADPOOL_SIZE && !isNaN(process.env.UV_THREADPOOL_SIZE) ? Number(process.env.UV_THREADPOOL_SIZE) : Math.max(os.cpus().length, 4);

// cache before wild-config
const argv = process.argv.slice(2);

const { Worker, SHARE_ENV } = require('worker_threads');
const packageData = require('./package.json');
const config = require('wild-config');
const logger = require('./lib/logger');
const { readEnvValue, hasEnvValue } = require('./lib/tools');
const nodeFetch = require('node-fetch');
const fetchCmd = global.fetch || nodeFetch;

const Bugsnag = require('@bugsnag/js');
if (readEnvValue('BUGSNAG_API_KEY')) {
    Bugsnag.start({
        apiKey: readEnvValue('BUGSNAG_API_KEY'),
        appVersion: packageData.version,
        logger: {
            debug(...args) {
                logger.debug({ msg: args.shift(), worker: 'main', source: 'bugsnag', args: args.length ? args : undefined });
            },
            info(...args) {
                logger.debug({ msg: args.shift(), worker: 'main', source: 'bugsnag', args: args.length ? args : undefined });
            },
            warn(...args) {
                logger.warn({ msg: args.shift(), worker: 'main', source: 'bugsnag', args: args.length ? args : undefined });
            },
            error(...args) {
                logger.error({ msg: args.shift(), worker: 'main', source: 'bugsnag', args: args.length ? args : undefined });
            }
        }
    });
}

const pathlib = require('path');
const { redis, queueConf, notifyQueue } = require('./lib/db');
const promClient = require('prom-client');
const fs = require('fs').promises;
const crypto = require('crypto');
const { compare: cv } = require('compare-versions');
const Joi = require('joi');
const { settingsSchema } = require('./lib/schemas');
const settings = require('./lib/settings');
const tokens = require('./lib/tokens');

const { QueueScheduler } = require('bullmq');

const getSecret = require('./lib/get-secret');

const {
    getDuration,
    getByteSize,
    getBoolean,
    getWorkerCount,
    selectRendezvousNode,
    checkLicense,
    checkForUpgrade,
    setLicense,
    getRedisStats
} = require('./lib/tools');
const {
    MAX_DAYS_STATS,
    MESSAGE_NEW_NOTIFY,
    MESSAGE_DELETED_NOTIFY,
    CONNECT_ERROR_NOTIFY,
    REDIS_PREFIX,
    ACCOUNT_ADDED_NOTIFY,
    ACCOUNT_DELETED_NOTIFY
} = require('./lib/consts');

const msgpack = require('msgpack5')();

config.service = config.service || {};

config.workers = config.workers || {
    imap: 4,
    webhooks: 1,
    submit: 1,
    imapProxy: 1
};

config.dbs = config.dbs || {
    redis: 'redis://127.0.0.1:6379/8'
};

config.log = config.log || {
    level: 'trace'
};

config.api = config.api || {
    port: 3000,
    host: '127.0.0.1'
};

config.smtp = config.smtp || {
    enabled: false,
    port: 2525,
    host: '127.0.0.1',
    secret: '',
    proxy: false
};

config['imap-proxy'] = config['imap-proxy'] || {
    enabled: false,
    port: 2993,
    host: '127.0.0.1',
    secret: '',
    proxy: false
};

const DEFAULT_EENGINE_TIMEOUT = 10 * 1000;
const EENGINE_TIMEOUT = getDuration(readEnvValue('EENGINE_TIMEOUT') || config.service.commandTimeout) || DEFAULT_EENGINE_TIMEOUT;
const DEFAULT_MAX_ATTACHMENT_SIZE = 5 * 1024 * 1024;
const SUBSCRIPTION_CHECK_TIMEOUT = 1 * 24 * 60 * 60 * 1000;
const SUBSCRIPTION_ALLOW_DELAY = 28 * 24 * 60 * 60 * 1000;

const CONNECION_SETUP_DELAY = getDuration(readEnvValue('EENGINE_CONNECION_SETUP_DELAY') || config.service.setupDelay) || 0;

config.api.maxSize = getByteSize(readEnvValue('EENGINE_MAX_SIZE') || config.api.maxSize) || DEFAULT_MAX_ATTACHMENT_SIZE;
config.dbs.redis = readEnvValue('EENGINE_REDIS') || readEnvValue('REDIS_URL') || config.dbs.redis;

config.workers.imap = getWorkerCount(readEnvValue('EENGINE_WORKERS') || config.workers.imap) || 4;

config.workers.webhooks = Number(readEnvValue('EENGINE_WORKERS_WEBHOOKS')) || config.workers.webhooks || 1;
config.workers.submit = Number(readEnvValue('EENGINE_WORKERS_SUBMIT')) || config.workers.submit || 1;

config.api.port =
    (readEnvValue('EENGINE_PORT') && Number(readEnvValue('EENGINE_PORT'))) || (readEnvValue('PORT') && Number(readEnvValue('PORT'))) || config.api.port;
config.api.host = readEnvValue('EENGINE_HOST') || config.api.host;

config.log.level = readEnvValue('EENGINE_LOG_LEVEL') || config.log.level;

// legacy options, will be removed in the future
const SMTP_ENABLED = hasEnvValue('EENGINE_SMTP_ENABLED') ? getBoolean(readEnvValue('EENGINE_SMTP_ENABLED')) : getBoolean(config.smtp.enabled);
const SMTP_SECRET = readEnvValue('EENGINE_SMTP_SECRET') || config.smtp.secret;
const SMTP_PORT = (readEnvValue('EENGINE_SMTP_PORT') && Number(readEnvValue('EENGINE_SMTP_PORT'))) || Number(config.smtp.port) || 2525;
const SMTP_HOST = readEnvValue('EENGINE_SMTP_HOST') || config.smtp.host || '127.0.0.1';
const SMTP_PROXY = hasEnvValue('EENGINE_SMTP_PROXY') ? getBoolean(readEnvValue('EENGINE_SMTP_PROXY')) : getBoolean(config.smtp.proxy);

const IMAP_PROXY_ENABLED = hasEnvValue('EENGINE_IMAP_PROXY_ENABLED')
    ? getBoolean(readEnvValue('EENGINE_IMAP_PROXY_ENABLED'))
    : getBoolean(config['imap-proxy'].enabled);
const IMAP_PROXY_SECRET = readEnvValue('EENGINE_IMAP_PROXY_SECRET') || config['imap-proxy'].secret;
const IMAP_PROXY_PORT =
    (readEnvValue('EENGINE_IMAP_PROXY_PORT') && Number(readEnvValue('EENGINE_IMAP_PROXY_PORT'))) || Number(config['imap-proxy'].port) || 2993;
const IMAP_PROXY_HOST = readEnvValue('EENGINE_IMAP_PROXY_HOST') || config['imap-proxy'].host || '127.0.0.1';
const IMAP_PROXY_PROXY = hasEnvValue('EENGINE_IMAP_PROXY_PROXY')
    ? getBoolean(readEnvValue('EENGINE_IMAP_PROXY_PROXY'))
    : getBoolean(config['imap-proxy'].proxy);

const API_PROXY = hasEnvValue('EENGINE_API_PROXY') ? getBoolean(readEnvValue('EENGINE_API_PROXY')) : getBoolean(config.api.proxy);

logger.info({
    msg: 'Starting EmailEngine',
    version: packageData.version,
    node: process.versions.node,
    uvThreadpoolSize: Number(process.env.UV_THREADPOOL_SIZE),
    workersImap: config.workers.imap,
    workersWebhooks: config.workers.webhooks,
    workersSubmission: config.workers.submit
});

const NO_ACTIVE_HANDLER_RESP = {
    error: 'No active handler for requested account. Try again later.',
    statusCode: 503
};

// check for upgrades once in 8 hours
const UPGRADE_CHECK_TIMEOUT = 1 * 24 * 3600 * 1000;
const LICENSE_CHECK_TIMEOUT = 20 * 60 * 1000;

const licenseInfo = {
    active: false,
    details: false,
    type: packageData.license
};

let notifyScheduler;
let submitScheduler;
let documentsScheduler;

let preparedSettings = false;
const preparedSettingsString = readEnvValue('EENGINE_SETTINGS') || config.settings;
if (preparedSettingsString) {
    // received a configuration block
    try {
        const { error, value } = Joi.object(settingsSchema).validate(JSON.parse(preparedSettingsString), {
            abortEarly: false,
            stripUnknown: true,
            convert: true
        });

        if (error) {
            throw error;
        }

        preparedSettings = value;
    } catch (err) {
        logger.error({ msg: 'Received invalid settings string', input: preparedSettingsString, err });
        process.exit(1);
    }
}

let preparedToken = false;
const preparedTokenString = readEnvValue('EENGINE_PREPARED_TOKEN') || config.preparedToken;
if (preparedTokenString) {
    try {
        preparedToken = msgpack.decode(Buffer.from(preparedTokenString, 'base64url'));
        if (!preparedToken || !/^[0-9a-f]{64}$/i.test(preparedToken.id)) {
            throw new Error('Invalid token format');
        }
    } catch (err) {
        logger.error({ msg: 'Received invalid token string', input: preparedTokenString, err });
        process.exit(1);
    }
}

let preparedPassword = false;
const preparedPasswordString = readEnvValue('EENGINE_PREPARED_PASSWORD') || config.preparedPassword;
if (preparedPasswordString) {
    try {
        preparedPassword = Buffer.from(preparedPasswordString, 'base64url').toString();
        if (!preparedPassword || preparedPassword.indexOf('$pbkdf2') !== 0) {
            throw new Error('Invalid password format');
        }
    } catch (err) {
        logger.error({ msg: 'Received invalid password string', input: preparedPasswordString, err });
        process.exit(1);
    }
}

const collectDefaultMetrics = promClient.collectDefaultMetrics;
collectDefaultMetrics({});

const metrics = {
    threadStarts: new promClient.Counter({
        name: 'thread_starts',
        help: 'Number of started threads'
    }),

    threadStops: new promClient.Counter({
        name: 'thread_stops',
        help: 'Number of stopped threads'
    }),

    apiCall: new promClient.Counter({
        name: 'api_call',
        help: 'Number of API calls',
        labelNames: ['method', 'statusCode', 'route']
    }),

    imapConnections: new promClient.Gauge({
        name: 'imap_connections',
        help: 'Current IMAP connection state',
        labelNames: ['status']
    }),

    imapResponses: new promClient.Counter({
        name: 'imap_responses',
        help: 'IMAP responses',
        labelNames: ['response', 'code']
    }),

    webhooks: new promClient.Counter({
        name: 'webhooks',
        help: 'Webhooks sent',
        labelNames: ['status', 'event']
    }),

    events: new promClient.Counter({
        name: 'events',
        help: 'Events fired',
        labelNames: ['event']
    }),

    webhookReq: new promClient.Histogram({
        name: 'webhook_req',
        help: 'Duration of webhook requests',
        buckets: [100, 250, 500, 750, 1000, 2500, 5000, 7500, 10000, 60 * 1000]
    }),

    queues: new promClient.Gauge({
        name: 'queue_size',
        help: 'Queue size',
        labelNames: ['queue', 'state']
    }),

    queuesProcessed: new promClient.Counter({
        name: 'queues_processed',
        help: 'Processed job count',
        labelNames: ['queue', 'status']
    }),

    emailengineConfig: new promClient.Gauge({
        name: 'emailengine_config',
        help: 'Configuration values',
        labelNames: ['version', 'config']
    }),

    redisVersion: new promClient.Gauge({
        name: 'redis_version',
        help: 'Redis version',
        labelNames: ['version']
    }),

    redisUptimeInSeconds: new promClient.Gauge({
        name: 'redis_uptime_in_seconds',
        help: 'Redis uptime in seconds'
    }),

    redisRejectedConnectionsTotal: new promClient.Gauge({
        name: 'redis_rejected_connections_total',
        help: 'Number of connections rejected by Redis'
    }),

    redisConfigMaxclients: new promClient.Gauge({
        name: 'redis_config_maxclients',
        help: 'Maximum client number for Redis'
    }),

    redisConnectedClients: new promClient.Gauge({
        name: 'redis_connected_clients',
        help: 'Number of client connections for Redis'
    }),

    redisSlowlogLength: new promClient.Gauge({
        name: 'redis_slowlog_length',
        help: 'Number of of entries in the Redis slow log'
    }),

    redisCommandsDurationSecondsTotal: new promClient.Gauge({
        name: 'redis_commands_duration_seconds_total',
        help: 'How many seconds spend on processing Redis commands'
    }),

    redisCommandsProcessedTotal: new promClient.Gauge({
        name: 'redis_commands_processed_total',
        help: 'How many commands processed by Redis'
    }),

    redisKeyspaceHitsTotal: new promClient.Gauge({
        name: 'redis_keyspace_hits_total',
        help: 'Number of successful lookup of keys in Redis'
    }),

    redisKeyspaceMissesTotal: new promClient.Gauge({
        name: 'redis_keyspace_misses_total',
        help: 'Number of failed lookup of keys in Redis'
    }),

    redisEvictedKeysTotal: new promClient.Gauge({
        name: 'redis_evicted_keys_total',
        help: 'Number of evicted keys due to maxmemory limit in Redis'
    }),

    redisMemoryUsedBytes: new promClient.Gauge({
        name: 'redis_memory_used_bytes',
        help: 'Total number of bytes allocated by Redis using its allocator'
    }),

    redisMemoryMaxBytes: new promClient.Gauge({
        name: 'redis_memory_max_bytes',
        help: 'The value of the Redis maxmemory configuration directive'
    }),

    redisMemFragmentationRatio: new promClient.Gauge({
        name: 'redis_mem_fragmentation_ratio',
        help: 'Ratio between used_memory_rss and used_memory in Redis'
    }),

    redisKeyCount: new promClient.Gauge({
        name: 'redis_key_count',
        help: 'Redis key counts',
        labelNames: ['db']
    }),

    redisLastSaveTime: new promClient.Gauge({
        name: 'redis_last_save_time',
        help: 'Unix timestamp of the last RDB save time'
    }),

    redisOpsPerSec: new promClient.Gauge({
        name: 'redis_instantaneous_ops_per_sec',
        help: 'Throughput operations per second'
    }),

    redisCommandRuns: new promClient.Gauge({
        name: 'redis_command_runs',
        help: 'Redis command counts',
        labelNames: ['command']
    }),

    redisCommandRunsFailed: new promClient.Gauge({
        name: 'redis_command_runs_fail',
        help: 'Redis command counts',
        labelNames: ['command', 'status']
    })
};

let callQueue = new Map();
let mids = 0;

let isClosing = false;
let assigning = false;

let unassigned = false;
let assigned = new Map();
let unassignCounter = new Map();
let workerAssigned = new WeakMap();
let onlineWorkers = new WeakSet();

let workers = new Map();
let availableIMAPWorkers = new Set();

let suspendedWorkerTypes = new Set();

const postMessage = (worker, payload, ignoreOffline, transferList) => {
    if (!onlineWorkers.has(worker)) {
        if (ignoreOffline) {
            return false;
        }
        throw new Error('Requested worker thread not available');
    }

    return worker.postMessage(payload, transferList);
};

const countUnassignment = async account => {
    if (!unassignCounter.has(account)) {
        unassignCounter.set(account, []);
    }
    let arr = unassignCounter.get(account);
    arr.push(Date.now());

    if (arr.length > 10) {
        arr = arr.slice(-10);
        unassignCounter.set(account, arr);
    }

    let delay = 0;
    if (arr.length === 1) {
        delay = 0;
    } else {
        let lastDelay = arr[arr.length - 1] - arr[arr.length - 2];
        // if last delay was longer than a minute, then reset
        if (lastDelay >= 60 * 1000) {
            delay = 0;
        } else {
            delay = Math.min(Math.ceil(lastDelay * 1.5), 60 * 1000);
        }
    }

    await redis.hSetExists(`${REDIS_PREFIX}iad:${account}`, 'state', 'disconnected');

    for (let worker of workers.get('api')) {
        let callPayload = {
            cmd: 'change',
            account,
            type: 'state',
            key: 'disconnected',
            payload: null
        };

        try {
            postMessage(worker, callPayload, true);
        } catch (err) {
            logger.error({ msg: 'Failed to post state change to child', worker: worker.threadId, callPayload, err });
        }
    }

    if (delay) {
        await new Promise(resolve => setTimeout(resolve, delay));
        return true;
    } else {
        return false;
    }
};

let clearUnassignmentCounter = account => {
    unassignCounter.delete(account);
};

let updateServerState = async (type, state, payload) => {
    await redis.hset(`${REDIS_PREFIX}${type}`, 'state', state);
    if (payload) {
        await redis.hset(`${REDIS_PREFIX}${type}`, 'payload', JSON.stringify(payload));
    }

    if (workers.has('api')) {
        for (let worker of workers.get('api')) {
            let callPayload = {
                cmd: 'change',
                type: '${type}ServerState',
                key: state,
                payload: payload || null
            };

            try {
                postMessage(worker, callPayload, true);
            } catch (err) {
                logger.error({ msg: 'Failed to post state change to child', worker: worker.threadId, callPayload, err });
            }
        }
    }
};

async function sendWebhook(account, event, data) {
    let payload = {
        account,
        date: new Date().toISOString()
    };

    if (event) {
        payload.event = event;
    }

    if (data) {
        payload.data = data;
    }

    let queueKeep = (await settings.get('queueKeep')) || true;
    await notifyQueue.add(event, payload, {
        removeOnComplete: queueKeep,
        removeOnFail: queueKeep,
        attempts: 10,
        backoff: {
            type: 'exponential',
            delay: 5000
        }
    });
}

let spawnWorker = async type => {
    if (isClosing) {
        return;
    }

    if (!workers.has(type)) {
        workers.set(type, new Set());
    }

    if (suspendedWorkerTypes.has(type)) {
        if (['smtp', 'imapProxy'].includes(type)) {
            await updateServerState(type, 'suspended', {});
        }
        return;
    }

    if (['smtp', 'imapProxy'].includes(type)) {
        let serverEnabled = await settings.get(`${type}ServerEnabled`);
        if (!serverEnabled) {
            await updateServerState(type, 'disabled', {});
            return;
        }

        await updateServerState(type, 'spawning');
    }

    let worker = new Worker(pathlib.join(__dirname, 'workers', `${type.replace(/[A-Z]/g, c => `-${c.toLowerCase()}`)}.js`), {
        argv,
        env: SHARE_ENV,
        trackUnmanagedFds: true
    });
    metrics.threadStarts.inc();

    workers.get(type).add(worker);

    worker.on('online', () => {
        if (['smtp', 'imapProxy'].includes(type)) {
            updateServerState(type, 'initializing').catch(err => logger.error({ msg: `Failed to update ${type} server state`, err }));
        }
        onlineWorkers.add(worker);
    });

    let exitHandler = async exitCode => {
        onlineWorkers.delete(worker);
        metrics.threadStops.inc();

        workers.get(type).delete(worker);

        if (['smtp', 'imapProxy'].includes(type)) {
            updateServerState(type, suspendedWorkerTypes.has(type) ? 'suspended' : 'exited');
        }

        if (type === 'imap') {
            availableIMAPWorkers.delete(worker);

            if (workerAssigned.has(worker)) {
                let accountList = workerAssigned.get(worker);
                workerAssigned.delete(worker);
                accountList.forEach(account => {
                    assigned.delete(account);
                    let shouldReassign = false;
                    // graceful reconnect
                    countUnassignment(account)
                        .then(sr => {
                            shouldReassign = sr;
                        })
                        .catch(() => {
                            shouldReassign = true;
                        })
                        .finally(() => {
                            unassigned.add(account);
                            if (shouldReassign) {
                                assignAccounts().catch(err => logger.error({ msg: 'Failed to assign accounts', n: 1, err }));
                            }
                        });
                });
            }
        }

        if (isClosing) {
            return;
        }

        // spawning a new worker trigger reassign
        if (suspendedWorkerTypes.has(type)) {
            logger.info({ msg: 'Worker thread closed', exitCode, type });
        } else {
            logger.error({ msg: 'Worker exited', exitCode, type });
        }

        // trigger new spawn
        await new Promise(r => setTimeout(r, 1000));
        await spawnWorker(type);
    };

    worker.on('exit', exitCode => {
        exitHandler(exitCode).catch(err => {
            logger.error({ msg: 'Failed to handle worker exit', exitCode, worker: worker.threadId, err });
        });
    });

    worker.on('message', message => {
        if (!message) {
            return;
        }

        if (message.cmd === 'resp' && message.mid && callQueue.has(message.mid)) {
            let { resolve, reject, timer } = callQueue.get(message.mid);
            clearTimeout(timer);
            callQueue.delete(message.mid);
            if (message.error) {
                let err = new Error(message.error);
                if (message.code) {
                    err.code = message.code;
                }
                if (message.statusCode) {
                    err.statusCode = message.statusCode;
                }
                if (message.info) {
                    err.info = message.info;
                }
                return reject(err);
            } else {
                return resolve(message.response);
            }
        }

        if (message.cmd === 'call' && message.mid) {
            return onCommand(worker, message.message)
                .then(response => {
                    let callPayload = {
                        cmd: 'resp',
                        mid: message.mid,
                        response
                    };

                    try {
                        postMessage(worker, callPayload);
                    } catch (err) {
                        logger.error({ msg: 'Failed to post state change to child', worker: worker.threadId, callPayload, err });
                    }
                })
                .catch(err => {
                    let callPayload = {
                        cmd: 'resp',
                        mid: message.mid,
                        error: err.message,
                        code: err.code,
                        statusCode: err.statusCode,
                        info: err.info
                    };

                    try {
                        postMessage(worker, callPayload);
                    } catch (err) {
                        logger.error({ msg: 'Failed to post state change to child', worker: worker.threadId, callPayload, err });
                    }
                });
        }

        switch (message.cmd) {
            case 'metrics': {
                let statUpdateKey = false;

                switch (message.key) {
                    // gather for dashboard counter
                    case 'webhooks': {
                        let { status } = message.args[0] || {};
                        statUpdateKey = `${message.key}:${status}`;
                        break;
                    }

                    case 'webhookReq': {
                        break;
                    }

                    case 'events': {
                        let { event } = message.args[0] || {};
                        switch (event) {
                            case MESSAGE_NEW_NOTIFY:
                            case MESSAGE_DELETED_NOTIFY:
                            case CONNECT_ERROR_NOTIFY:
                                statUpdateKey = `${message.key}:${event}`;
                                break;
                        }
                        break;
                    }

                    case 'apiCall': {
                        let { statusCode } = message.args[0] || {};
                        let success = statusCode >= 200 && statusCode < 300;
                        statUpdateKey = `${message.key}:${success ? 'success' : 'fail'}`;
                        break;
                    }
                }

                if (statUpdateKey) {
                    // increment counter in redis

                    let now = new Date();

                    // we keep a separate hash value for each ISO day
                    let dateStr = `${now
                        .toISOString()
                        .substr(0, 10)
                        .replace(/[^0-9]+/g, '')}`;

                    // hash key for bucket
                    let timeStr = `${now
                        .toISOString()
                        // bucket includes 1 minute
                        .substr(0, 16)
                        .replace(/[^0-9]+/g, '')}`;

                    let hkey = `${REDIS_PREFIX}stats:${statUpdateKey}:${dateStr}`;

                    redis
                        .multi()
                        .hincrby(hkey, timeStr, 1)
                        .sadd(`${REDIS_PREFIX}stats:keys`, statUpdateKey)
                        // keep alive at most 2 days
                        .expire(hkey, MAX_DAYS_STATS + 1 * 24 * 3600)
                        .exec()
                        .catch(() => false);
                }

                if (message.key && metrics[message.key] && typeof metrics[message.key][message.method] === 'function') {
                    metrics[message.key][message.method](...message.args);
                }

                return;
            }

            case 'settings':
                availableIMAPWorkers.forEach(worker => {
                    try {
                        postMessage(worker, message);
                    } catch (err) {
                        logger.error({ msg: 'Failed to post command to child', worker: worker.threadId, callPayload: message, err });
                    }
                });
                return;

            case 'change':
                switch (message.type) {
                    case 'smtpServerState':
                    case 'imapProxyServerState': {
                        let type = message.type.replace(/ServerState$/, '');
                        updateServerState(type, message.key, message.payload).catch(err => logger.error({ msg: `Failed to update ${type} server state`, err }));
                        break;
                    }
                    default:
                        // forward all state changes to the API worker
                        for (let worker of workers.get('api')) {
                            try {
                                postMessage(worker, message, true);
                            } catch (err) {
                                logger.error({ msg: 'Failed to post state change to child', worker: worker.threadId, callPayload: message, err });
                            }
                        }
                }
                break;
        }

        switch (type) {
            case 'imap':
                return processImapWorkerMessage(worker, message);
        }
    });
};

function processImapWorkerMessage(worker, message) {
    if (!message || !message.cmd) {
        logger.debug({ msg: 'Unexpected message', type: 'imap', message });

        return;
    }

    switch (message.cmd) {
        case 'ready':
            availableIMAPWorkers.add(worker);
            // assign pending accounts
            assignAccounts().catch(err => logger.error({ msg: 'Failed to assign accounts', n: 2, err }));
            break;
    }
}

async function call(worker, message, transferList) {
    return new Promise((resolve, reject) => {
        let mid = `${Date.now()}:${++mids}`;

        let timer = setTimeout(() => {
            let err = new Error('Timeout waiting for command response [T1]');
            err.statusCode = 504;
            err.code = 'Timeout';
            err.payload = message;
            reject(err);
        }, message.timeout || EENGINE_TIMEOUT);

        callQueue.set(mid, { resolve, reject, timer });

        try {
            postMessage(
                worker,
                {
                    cmd: 'call',
                    mid,
                    message
                },
                false,
                transferList
            );
        } catch (err) {
            callQueue.delete(mid);
            return reject(err);
        }
    });
}

async function assignAccounts() {
    if (assigning) {
        return false;
    }
    assigning = true;
    try {
        if (!unassigned) {
            // first run
            // list all available accounts and assign to worker threads
            let accounts = await redis.smembers(`${REDIS_PREFIX}ia:accounts`);
            unassigned = new Set(accounts);
        }

        if (!availableIMAPWorkers.size || !unassigned.size) {
            // nothing to do here
            return;
        }

        logger.info({
            msg: 'Assigning connections',
            unassigned: unassigned.size,
            workersAvailable: availableIMAPWorkers.size,
            setupDelay: CONNECION_SETUP_DELAY
        });

        for (let account of unassigned) {
            if (!availableIMAPWorkers.size) {
                // out of workers
                break;
            }

            let worker = selectRendezvousNode(account, Array.from(availableIMAPWorkers));

            if (!workerAssigned.has(worker)) {
                workerAssigned.set(worker, new Set());
            }

            workerAssigned.get(worker).add(account);
            assigned.set(account, worker);
            unassigned.delete(account);

            await call(worker, {
                cmd: 'assign',
                account
            });

            if (CONNECION_SETUP_DELAY) {
                await new Promise(r => setTimeout(r, CONNECION_SETUP_DELAY));
            }
        }
    } finally {
        assigning = false;
    }
}

let licenseCheckTimer = false;
let checkingLicense = false;
let licenseCheckHandler = async opts => {
    if (checkingLicense) {
        return;
    }
    checkingLicense = true;
    clearTimeout(licenseCheckTimer);

    try {
        opts = opts || {};
        let { subscriptionCheckTimeout } = opts;
        let now = Date.now();
        subscriptionCheckTimeout = subscriptionCheckTimeout || SUBSCRIPTION_CHECK_TIMEOUT;

        let kv = await redis.hget(`${REDIS_PREFIX}settings`, 'kv');
        let checkKv = true;
        if (kv && typeof kv === 'string' && cv(packageData.version, Buffer.from(kv, 'hex').toString(), '<=')) {
            checkKv = false;
        }

        if (
            checkKv &&
            licenseInfo.active &&
            !(licenseInfo.details && licenseInfo.details.expires) &&
            (await redis.hUpdateBigger(`${REDIS_PREFIX}settings`, 'subcheck', now - subscriptionCheckTimeout, now))
        ) {
            // validate license
            try {
                let res = await fetchCmd(`https://postalsys.com/licenses/validate`, {
                    method: 'post',
                    headers: {
                        'User-Agent': `${packageData.name}/${packageData.version} (+${packageData.homepage})`,
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        key: licenseInfo.details.key,
                        version: packageData.version,
                        app: '@postalsys/emailengine-app'
                    })
                });

                let data = await res.json();

                if (!res.ok) {
                    if (data.invalidate) {
                        let res = await redis.hUpdateBigger(`${REDIS_PREFIX}settings`, 'subexp', now, now + SUBSCRIPTION_ALLOW_DELAY);
                        if (res === 2) {
                            // grace period over
                            logger.info({ msg: 'License not valid', license: licenseInfo.details, data });
                            await redis.multi().hdel(`${REDIS_PREFIX}settings`, 'license').hdel(`${REDIS_PREFIX}settings`, 'subexp').exec();
                            licenseInfo.active = false;
                            licenseInfo.details = false;
                            licenseInfo.type = packageData.license;
                        }
                    }
                } else {
                    await redis.hdel(`${REDIS_PREFIX}settings`, 'subexp');
                    await redis.hset(`${REDIS_PREFIX}settings`, 'kv', Buffer.from(packageData.version).toString('hex'));
                }
            } catch (err) {
                logger.error({ msg: 'Failed to validate license', err });
            }
        }

        if (licenseInfo.active && licenseInfo.details && licenseInfo.details.expires && new Date(licenseInfo.details.expires).getTime() < Date.now()) {
            // clear expired license

            logger.info({ msg: 'License expired', license: licenseInfo.details });

            licenseInfo.active = false;
            licenseInfo.details = false;
        }

        if (!licenseInfo.active && !suspendedWorkerTypes.size) {
            logger.info({ msg: 'No active license, shutting down workers after 15 minutes of activity' });

            for (let type of ['imap', 'submit', 'smtp', 'webhooks', 'imapProxy']) {
                suspendedWorkerTypes.add(type);
                if (workers.has(type)) {
                    for (let worker of workers.get(type).values()) {
                        worker.terminate();
                    }
                }
            }
        } else if (licenseInfo.active && suspendedWorkerTypes.size) {
            // re-enable missing workers
            for (let type of suspendedWorkerTypes) {
                suspendedWorkerTypes.delete(type);
                switch (type) {
                    case 'smtp':
                    case 'imapProxy':
                        {
                            let serverEnabled = await settings.get(`${type}ServerEnabled`);
                            if (serverEnabled) {
                                // single SMTP interface worker
                                await spawnWorker(type);
                            }
                        }
                        break;
                    default:
                        if (config.workers && config.workers[type]) {
                            for (let i = 0; i < config.workers[type]; i++) {
                                await spawnWorker(type);
                            }
                        }
                }
            }
        }
    } finally {
        checkingLicense = false;
        licenseCheckTimer = setTimeout(checkActiveLicense, LICENSE_CHECK_TIMEOUT);
        licenseCheckTimer.unref();
    }
};

function checkActiveLicense() {
    clearTimeout(licenseCheckTimer);
    licenseCheckHandler().catch(err => {
        logger.error('Failed to process license checker', err);
    });
}

let processCheckUpgrade = async () => {
    try {
        let updateInfo = await checkForUpgrade();
        if (updateInfo.canUpgrade) {
            logger.info({ msg: 'Found an upgrade for EmailEngine', updateInfo });

            updateInfo.checked = Date.now();
            await redis.hset(`${REDIS_PREFIX}settings`, 'upgrade', JSON.stringify(updateInfo));
        } else {
            await redis.hdel(`${REDIS_PREFIX}settings`, 'upgrade');
        }
    } catch (err) {
        logger.error({ msg: 'Failed to check updates', err });
    }
};

let upgradeCheckTimer = false;
let upgradeCheckHandler = async () => {
    let upgradeInfoExists = await redis.hexists(`${REDIS_PREFIX}settings`, 'upgrade');
    if (!upgradeInfoExists) {
        // nothing to do here
        return;
    }
    await processCheckUpgrade();
    upgradeCheckTimer = setTimeout(checkUpgrade, UPGRADE_CHECK_TIMEOUT);
    upgradeCheckTimer.unref();
};

function checkUpgrade() {
    clearTimeout(upgradeCheckTimer);
    upgradeCheckHandler().catch(err => {
        logger.error('Failed to process upgrade check', err);
    });
}

async function updateQueueCounters() {
    metrics.emailengineConfig.set({ version: 'v' + packageData.version }, 1);
    metrics.emailengineConfig.set({ config: 'uvThreadpoolSize' }, Number(process.env.UV_THREADPOOL_SIZE));
    metrics.emailengineConfig.set({ config: 'workersImap' }, config.workers.imap);
    metrics.emailengineConfig.set({ config: 'workersWebhooks' }, config.workers.webhooks);
    metrics.emailengineConfig.set({ config: 'workersSubmission' }, config.workers.submit);

    for (let queue of ['notify', 'submit', 'documents']) {
        const [resActive, resDelayed, resPaused, resWaiting] = await redis
            .multi()
            .llen(`${REDIS_PREFIX}bull:${queue}:active`)
            .zcard(`${REDIS_PREFIX}bull:${queue}:delayed`)
            .llen(`${REDIS_PREFIX}bull:${queue}:paused`)
            .llen(`${REDIS_PREFIX}bull:${queue}:wait`)
            .exec();
        if (resActive[0] || resDelayed[0] || resPaused[0] || resWaiting[0]) {
            // counting failed
            logger.error({ msg: 'Failed to count queue length', queue, active: resActive, delayed: resDelayed, paused: resPaused, waiting: resWaiting });
            return false;
        }

        metrics.queues.set({ queue: `${queue}`, state: `active` }, Number(resActive[1]) || 0);
        metrics.queues.set({ queue: `${queue}`, state: `delayed` }, Number(resDelayed[1]) || 0);
        metrics.queues.set({ queue: `${queue}`, state: `paused` }, Number(resPaused[1]) || 0);
        metrics.queues.set({ queue: `${queue}`, state: `waiting` }, Number(resWaiting[1]) || 0);
    }

    try {
        let redisInfo = await getRedisStats(redis);

        metrics.redisVersion.set({ version: 'v' + redisInfo.redis_version }, 1);

        metrics.redisUptimeInSeconds.set(Number(redisInfo.uptime_in_seconds) || 0);
        metrics.redisRejectedConnectionsTotal.set(Number(redisInfo.rejected_connections) || 0);
        metrics.redisConfigMaxclients.set(Number(redisInfo.maxclients) || 0);
        metrics.redisConnectedClients.set(Number(redisInfo.connected_clients) || 0);
        metrics.redisSlowlogLength.set(Number(redisInfo.slowlog_length) || 0);

        metrics.redisCommandsDurationSecondsTotal.set(Math.ceil((Number(redisInfo.cmdstat_total && redisInfo.cmdstat_total.usec) || 0) / 1000000));
        metrics.redisCommandsProcessedTotal.set(Number(redisInfo.cmdstat_total && redisInfo.cmdstat_total.calls) || 0);

        metrics.redisKeyspaceHitsTotal.set(Number(redisInfo.keyspace_hits) || 0);
        metrics.redisKeyspaceMissesTotal.set(Number(redisInfo.keyspace_misses) || 0);

        metrics.redisEvictedKeysTotal.set(Number(redisInfo.evicted_keys) || 0);

        metrics.redisMemoryUsedBytes.set(Number(redisInfo.used_memory) || 0);
        metrics.redisMemoryMaxBytes.set(Number(redisInfo.maxmemory) || Number(redisInfo.total_system_memory) || 0);

        metrics.redisMemFragmentationRatio.set(Number(redisInfo.mem_fragmentation_ratio) || 0);

        Object.keys(redisInfo).forEach(key => {
            if (/^db\d+$/.test(key)) {
                //redisKeyCount
                metrics.redisKeyCount.set({ db: key }, Number(redisInfo[key].keys) || 0);
            }

            if (key.indexOf('cmdstat_') === 0) {
                let cmd = key.substr('cmdstat_'.length);
                metrics.redisCommandRuns.set({ command: cmd }, Number(redisInfo[key].calls) || 0);

                if (redisInfo[key].failed_calls) {
                    metrics.redisCommandRunsFailed.set({ command: cmd, status: 'failed' }, Number(redisInfo[key].failed_calls) || 0);
                }

                if (redisInfo[key].rejected_calls) {
                    metrics.redisCommandRunsFailed.set({ command: cmd, status: 'rejected' }, Number(redisInfo[key].rejected_calls) || 0);
                }
            }
        });

        metrics.redisLastSaveTime.set(Number(redisInfo.rdb_last_save_time) || 0);
        metrics.redisOpsPerSec.set(Number(redisInfo.instantaneous_ops_per_sec) || 0);
    } catch (err) {
        logger.error({ msg: 'Failed to update query counters', err });
    }
}

async function onCommand(worker, message) {
    switch (message.cmd) {
        case 'metrics':
            await updateQueueCounters();
            return promClient.register.metrics();

        case 'structuredMetrics': {
            let connections = {};

            for (let key of Object.keys(metrics.imapConnections.hashMap)) {
                if (key.indexOf('status:') === 0) {
                    let metric = metrics.imapConnections.hashMap[key];
                    connections[metric.labels.status] = metric.value;
                }
            }

            return { connections };
        }

        case 'imapWorkerCount': {
            return { workers: availableIMAPWorkers.size };
        }

        case 'checkLicense':
            try {
                await licenseCheckHandler({
                    subscriptionCheckTimeout: 60 * 1000
                });
            } catch (err) {
                // ignore
            }
            return licenseInfo;

        case 'license':
            if (!licenseInfo.active && suspendedWorkerTypes.size) {
                return Object.assign({}, licenseInfo, { suspended: true });
            }
            return licenseInfo;

        case 'updateLicense': {
            try {
                const licenseFile = message.license;

                let licenseData = await checkLicense(licenseFile);
                if (!licenseData) {
                    throw new Error('Failed to verify provided license');
                }

                logger.info({ msg: 'Loaded license', license: licenseData, source: 'API' });

                await setLicense(licenseData, licenseFile);

                licenseInfo.active = true;
                licenseInfo.details = licenseData;
                licenseInfo.type = 'EmailEngine License';

                // re-enable workers
                checkActiveLicense();

                return licenseInfo;
            } catch (err) {
                logger.fatal({ msg: 'Failed to verify provided license', source: 'API', err });
                return false;
            }
        }

        case 'removeLicense': {
            try {
                await redis.multi().hdel(`${REDIS_PREFIX}settings`, 'license').hdel(`${REDIS_PREFIX}settings`, 'subexp').exec();

                licenseInfo.active = false;
                licenseInfo.details = false;
                licenseInfo.type = packageData.license;

                return licenseInfo;
            } catch (err) {
                logger.fatal({ msg: 'Failed to remove existing license', err });
                return false;
            }
        }

        case 'new':
            unassigned.add(message.account);
            assignAccounts()
                .then(sendWebhook(message.account, ACCOUNT_ADDED_NOTIFY, { account: message.account }))
                .catch(err => logger.error({ msg: 'Failed to assign accounts', n: 3, err }));
            return;

        case 'delete':
            unassigned.delete(message.account); // if set
            clearUnassignmentCounter(message.account);
            if (assigned.has(message.account)) {
                let assignedWorker = assigned.get(message.account);
                if (workerAssigned.has(assignedWorker)) {
                    workerAssigned.get(assignedWorker).delete(message.account);
                    if (!workerAssigned.get(assignedWorker).size) {
                        // last item in the worker accounts
                        workerAssigned.delete(assignedWorker);
                    }
                }

                call(assignedWorker, message)
                    .then(() => logger.debug('worker processed'))
                    .catch(err => logger.error({ msg: 'Failed to clean an assigned worker', err }));
            }
            sendWebhook(message.account, ACCOUNT_DELETED_NOTIFY, { account: message.account }).catch(err =>
                logger.error({ msg: 'Failed to send a deletion webhook', err })
            );
            return;

        case 'update':
        case 'sync':
            if (assigned.has(message.account)) {
                let assignedWorker = assigned.get(message.account);
                call(assignedWorker, message)
                    .then(() => logger.debug('worker processed'))
                    .catch(err => logger.error({ msg: 'Failed to call sync from a worker', err }));
            }
            return;

        case 'smtpReload':
        case 'imapProxyReload':
            {
                let type = message.cmd.replace(/Reload$/, '');
                let hasWorkers = workers.has(type) && workers.get(type).size;
                // reload (or kill) SMTP submission worker
                if (hasWorkers) {
                    for (let worker of workers.get(type).values()) {
                        worker.terminate();
                    }
                } else {
                    let serverEnabled = await settings.get(`${type}ServerEnabled`);
                    if (serverEnabled) {
                        // spawn a new worker
                        await spawnWorker(type);
                    }
                }
            }
            break;

        case 'listMessages':
        case 'getRawMessage':
        case 'getText':
        case 'getMessage':
        case 'updateMessage':
        case 'updateMessages':
        case 'listMailboxes':
        case 'moveMessage':
        case 'moveMessages':
        case 'deleteMessage':
        case 'deleteMessages':
        case 'createMailbox':
        case 'deleteMailbox':
        case 'submitMessage':
        case 'queueMessage':
        case 'uploadMessage':
        case 'getAttachment': {
            if (!assigned.has(message.account)) {
                return NO_ACTIVE_HANDLER_RESP;
            }

            let assignedWorker = assigned.get(message.account);

            let transferList = [];
            if (['getRawMessage', 'getAttachment'].includes(message.cmd) && message.port) {
                transferList.push(message.port);
            }

            if (['submitMessage', 'queueMessage'].includes(message.cmd) && typeof message.raw === 'object') {
                transferList.push(message.raw);
            }

            return await call(assignedWorker, message, transferList);
        }
    }
    return 999;
}

let metricsResult = {};
async function collectMetrics() {
    // reset all counters
    Object.keys(metricsResult || {}).forEach(key => {
        metricsResult[key] = 0;
    });

    if (workers.has('imap')) {
        let imapWorkers = workers.get('imap');
        for (let imapWorker of imapWorkers) {
            if (!availableIMAPWorkers.has(imapWorker)) {
                // worker not available yet
                continue;
            }

            try {
                let workerStats = await call(imapWorker, { cmd: 'countConnections' });
                Object.keys(workerStats || {}).forEach(status => {
                    if (!metricsResult[status]) {
                        metricsResult[status] = 0;
                    }
                    metricsResult[status] += Number(workerStats[status]) || 0;
                });
            } catch (err) {
                logger.error({ msg: 'Failed to count connections', err });
            }
        }
    }

    Object.keys(metricsResult).forEach(status => {
        metrics.imapConnections.set({ status }, metricsResult[status]);
    });
}

const closeQueues = cb => {
    let proms = [];
    if (notifyScheduler) {
        proms.push(notifyScheduler.close());
    }

    if (submitScheduler) {
        proms.push(submitScheduler.close());
    }

    if (documentsScheduler) {
        proms.push(documentsScheduler.close());
    }

    if (!proms.length) {
        return setImmediate(() => cb());
    }

    let returned;

    let closeTimeout = setTimeout(() => {
        clearTimeout(closeTimeout);
        if (returned) {
            return;
        }
        returned = true;
        cb();
    }, 2500);

    Promise.allSettled(proms).then(() => {
        clearTimeout(closeTimeout);
        if (returned) {
            return;
        }
        returned = true;
        cb();
    });
};

process.on('SIGTERM', () => {
    if (isClosing) {
        return;
    }
    isClosing = true;
    closeQueues(() => {
        process.exit();
    });
});

process.on('SIGINT', () => {
    if (isClosing) {
        return;
    }
    isClosing = true;
    closeQueues(() => {
        process.exit();
    });
});

// START APPLICATION

const startApplication = async () => {
    // process license
    if (config.licensePath) {
        try {
            let stat = await fs.stat(config.licensePath);
            if (!stat.isFile()) {
                throw new Error(`Provided license key is not a regular file`);
            }
            const licenseFile = await fs.readFile(config.licensePath, 'utf-8');
            let licenseData = await checkLicense(licenseFile);
            if (!licenseData) {
                throw new Error('Failed to verify provided license key');
            }
            logger.info({ msg: 'Loaded license key', license: licenseData, source: config.licensePath });

            await setLicense(licenseData, licenseFile);
        } catch (err) {
            logger.fatal({ msg: 'Failed to verify provided license key file', source: config.licensePath, err });
            return process.exit(13);
        }
    }

    const preparedLicenseString = readEnvValue('EENGINE_PREPARED_LICENSE') || config.preparedLicense;
    if (preparedLicenseString) {
        try {
            let imported = await settings.importLicense(preparedLicenseString, checkLicense);
            if (imported) {
                logger.info({ msg: 'Imported license key', source: 'import' });
            }
        } catch (err) {
            logger.fatal({ msg: 'Failed to verify provided license key data', source: 'import', err });
            return process.exit(13);
        }
    }

    let licenseFile = await redis.hget(`${REDIS_PREFIX}settings`, 'license');
    if (licenseFile) {
        try {
            let licenseData = await checkLicense(licenseFile);
            if (!licenseData) {
                throw new Error('Failed to verify provided license key');
            }
            licenseInfo.active = true;
            licenseInfo.details = licenseData;
            licenseInfo.type = 'EmailEngine License';
            if (!config.licensePath) {
                logger.info({ msg: 'Loaded license', license: licenseData, source: 'db' });
            }
        } catch (err) {
            logger.fatal({ msg: 'Failed to verify stored license key', content: licenseFile, err });
        }
    }

    if (!licenseInfo.active) {
        logger.fatal({ msg: 'No active license key provided. Running in limited mode.' });
    }

    // check for updates, run as a promise to not block other activities
    processCheckUpgrade().catch(err => {
        logger.error({ msg: 'Failed to process upgrade check', err });
    });

    if (preparedSettings) {
        // set up configuration
        logger.debug({ msg: 'Updating application settings', settings: preparedSettings });

        for (let key of Object.keys(preparedSettings)) {
            await settings.set(key, preparedSettings[key]);
        }
    }

    // prepare some required configuration values
    let existingSmtpEnabled = await settings.get('smtpServerEnabled');
    if (existingSmtpEnabled === null) {
        await settings.set('smtpServerEnabled', !!SMTP_ENABLED);
    }

    let existingSmtpSecret = await settings.get('smtpServerPassword');
    if (existingSmtpSecret === null) {
        await settings.set('smtpServerPassword', SMTP_SECRET || null);
    }

    let existingSmtpAuthEnabled = await settings.get('smtpServerAuthEnabled');
    if (existingSmtpAuthEnabled === null && (existingSmtpSecret || existingSmtpSecret === null)) {
        await settings.set('smtpServerAuthEnabled', true);
    }

    let existingSmtpPort = await settings.get('smtpServerPort');
    if (existingSmtpPort === null) {
        await settings.set('smtpServerPort', SMTP_PORT);
    }

    let existingSmtpHost = await settings.get('smtpServerHost');
    if (existingSmtpHost === null) {
        await settings.set('smtpServerHost', SMTP_HOST);
    }

    let existingSmtpProxy = await settings.get('smtpServerProxy');
    if (existingSmtpProxy === null) {
        await settings.set('smtpServerProxy', SMTP_PROXY);
    }

    let existingImapProxyEnabled = await settings.get('imapProxyServerEnabled');
    if (existingImapProxyEnabled === null) {
        await settings.set('imapProxyServerEnabled', !!IMAP_PROXY_ENABLED);
    }

    let existingImapProxySecret = await settings.get('imapProxyServerPassword');
    if (existingImapProxySecret === null) {
        await settings.set('imapProxyServerPassword', IMAP_PROXY_SECRET || null);
    }

    let existingImapProxyPort = await settings.get('imapProxyServerPort');
    if (existingImapProxyPort === null) {
        await settings.set('imapProxyServerPort', IMAP_PROXY_PORT);
    }

    let existingImapProxyHost = await settings.get('imapProxyServerHost');
    if (existingImapProxyHost === null) {
        await settings.set('imapProxyServerHost', IMAP_PROXY_HOST);
    }

    let existingImapProxyProxy = await settings.get('imapProxyServerProxy');
    if (existingImapProxyProxy === null) {
        await settings.set('imapProxyServerProxy', IMAP_PROXY_PROXY);
    }

    let existingEnableApiProxy = await settings.get('enableApiProxy');
    if (existingEnableApiProxy === null) {
        await settings.set('enableApiProxy', API_PROXY);
    }

    let existingServiceSecret = await settings.get('serviceSecret');
    if (existingServiceSecret === null) {
        await settings.set('serviceSecret', crypto.randomBytes(16).toString('hex'));
    }

    let existingQueueKeep = await settings.get('queueKeep');
    if (existingQueueKeep === null) {
        let QUEUE_KEEP = Math.max((readEnvValue('EENGINE_QUEUE_REMOVE_AFTER') && Number(readEnvValue('EENGINE_QUEUE_REMOVE_AFTER'))) || 0, 0);
        await settings.set('queueKeep', QUEUE_KEEP);
    }

    if (preparedToken) {
        try {
            let imported = await tokens.setRawData(preparedToken);
            if (imported) {
                logger.debug({ msg: 'Imported prepared token', token: preparedToken.id });
            } else {
                logger.debug({ msg: 'Skipped prepared token', token: preparedToken.id });
            }
        } catch (err) {
            logger.error({ msg: 'Failed to import token', token: preparedToken.id });
        }
    }

    if (preparedPassword) {
        try {
            let authData = await settings.get('authData');

            authData = authData || {};
            authData.user = authData.user || 'admin';
            authData.password = preparedPassword;

            await settings.set('authData', authData);
            logger.debug({ msg: 'Imported hashed password', hash: preparedPassword });
        } catch (err) {
            logger.error({ msg: 'Failed to import password', hash: preparedPassword });
        }
    }

    // renew encryiption secret, if needed
    await getSecret();

    // ensure password for cookie based auth
    let cookiePassword = await settings.get('cookiePassword');
    if (!cookiePassword) {
        cookiePassword = crypto.randomBytes(32).toString('base64');
        await settings.set('cookiePassword', cookiePassword);
    }

    // multiple IMAP connection handlers
    for (let i = 0; i < config.workers.imap; i++) {
        await spawnWorker('imap');
    }

    for (let i = 0; i < config.workers.webhooks; i++) {
        await spawnWorker('webhooks');
    }

    for (let i = 0; i < config.workers.submit; i++) {
        await spawnWorker('submit');
    }

    // single worker to process events in order
    await spawnWorker('documents');

    if (await settings.get('smtpServerEnabled')) {
        // single SMTP interface worker
        await spawnWorker('smtp');
    }

    if (await settings.get('imapProxyServerEnabled')) {
        // single IMAP proxy interface worker
        await spawnWorker('imapProxy');
    }

    // single worker for HTTP
    await spawnWorker('api');
};

startApplication()
    .then(() => {
        // start collecting metrics
        setInterval(() => {
            collectMetrics().catch(err => logger.error({ msg: 'Failed to collect metrics', err }));
        }, 1000).unref();

        licenseCheckTimer = setTimeout(checkActiveLicense, LICENSE_CHECK_TIMEOUT);
        licenseCheckTimer.unref();

        upgradeCheckTimer = setTimeout(checkUpgrade, UPGRADE_CHECK_TIMEOUT);
        upgradeCheckTimer.unref();

        notifyScheduler = new QueueScheduler('notify', Object.assign({}, queueConf));
        submitScheduler = new QueueScheduler('submit', Object.assign({}, queueConf));
        documentsScheduler = new QueueScheduler('documents', Object.assign({}, queueConf));
    })
    .catch(err => {
        logger.error({ msg: 'Failed to start application', err });
        process.exit(1);
    });
