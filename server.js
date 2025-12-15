'use strict';

/**
 * EmailEngine Main Server Module
 *
 * This is the main entry point for EmailEngine - a self-hosted email automation platform.
 * It manages worker threads for IMAP connections, webhooks, email submission, and various
 * proxy servers (SMTP, IMAP).
 *
 * @module server
 * @requires dotenv
 * @requires worker_threads
 * @requires @zone-eu/wild-config
 * @see {@link https://emailengine.app}
 */

// Load environment variables if not already loaded
if (!process.env.EE_ENV_LOADED) {
    require('dotenv').config({ quiet: true });
    process.env.EE_ENV_LOADED = 'true';
}

// Attempt to change working directory to script location
try {
    process.chdir(__dirname);
} catch (err) {
    // ignore - may fail in some containerized environments
}

// Set process title for easier identification in process lists
process.title = 'emailengine';

// Ensure Node.js version supports structuredClone (Node 17+)
try {
    structuredClone(true);
} catch (err) {
    console.error(`Node.js version ${process.version} is not supported. Please upgrade to Node.js 17 or later.`);
    process.exit(1);
}

const os = require('os');

// Set UV thread pool size for better async I/O performance
// Defaults to number of CPU cores (minimum 4)
process.env.UV_THREADPOOL_SIZE =
    process.env.UV_THREADPOOL_SIZE && !isNaN(process.env.UV_THREADPOOL_SIZE) ? Number(process.env.UV_THREADPOOL_SIZE) : Math.max(os.cpus().length, 4);

// Disable Tensorflow warnings
process.env.TF_CPP_MIN_LOG_LEVEL = '2';

// Cache command line arguments before @zone-eu/wild-config processes them
const argv = process.argv.slice(2);

const { Worker: WorkerThread, SHARE_ENV } = require('worker_threads');
const packageData = require('./package.json');
const config = require('@zone-eu/wild-config');
const logger = require('./lib/logger');

// Import utility functions
const {
    readEnvValue,
    hasEnvValue,
    download,
    getDuration,
    getByteSize,
    getBoolean,
    getWorkerCount,
    selectRendezvousNode,
    checkLicense,
    checkForUpgrade,
    setLicense,
    getRedisStats,
    threadStats,
    retryAgent
} = require('./lib/tools');
const MetricsCollector = require('./lib/metrics-collector');

// Import constants
const {
    MAX_DAYS_STATS,
    MESSAGE_NEW_NOTIFY,
    MESSAGE_DELETED_NOTIFY,
    CONNECT_ERROR_NOTIFY,
    REDIS_PREFIX,
    ACCOUNT_ADDED_NOTIFY,
    ACCOUNT_DELETED_NOTIFY,
    LIST_UNSUBSCRIBE_NOTIFY,
    LIST_SUBSCRIBE_NOTIFY
} = require('./lib/consts');

// Import core modules
const { webhooks: Webhooks } = require('./lib/webhooks');
const {
    generateSummary,
    generateEmbeddings,
    getChunkEmbeddings,
    embeddingsQuery,
    questionQuery,
    listModels: openAiListModels,
    DEFAULT_USER_PROMPT: openAiDefaultPrompt
} = require('@postalsys/email-ai-tools');
const { fetch: fetchCmd } = require('undici');

const bounceClassifier = require('@postalsys/bounce-classifier');

const v8 = require('node:v8');

// Initialize Bugsnag error tracking if API key is provided
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
    logger.notifyError = Bugsnag.notify.bind(Bugsnag);
}

// Import additional dependencies
const pathlib = require('path');
const { redis, queueConf } = require('./lib/db');
const promClient = require('prom-client');
const fs = require('fs').promises;
const crypto = require('crypto');
const { compare: cv } = require('compare-versions');
const Joi = require('joi');
const { settingsSchema } = require('./lib/schemas');
const settings = require('./lib/settings');
const tokens = require('./lib/tokens');

const { checkRateLimit } = require('./lib/rate-limit');

const { QueueEvents } = require('bullmq');

const getSecret = require('./lib/get-secret');

const msgpack = require('msgpack5')();

// Initialize default configuration values if not set
config.service = config.service || {};

// Default worker thread counts
config.workers = config.workers || {
    imap: 4, // IMAP connection handlers
    webhooks: 1, // Webhook processors
    submit: 1, // Email submission workers
    imapProxy: 1 // IMAP proxy server
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

// SMTP proxy server configuration
config.smtp = config.smtp || {
    enabled: false,
    port: 2525,
    host: '127.0.0.1',
    secret: '',
    proxy: false
};

// IMAP proxy server configuration
config['imap-proxy'] = config['imap-proxy'] || {
    enabled: false,
    port: 2993,
    host: '127.0.0.1',
    secret: '',
    proxy: false
};

// Application start timestamp
const NOW = Date.now();

// Initialize metrics collector (will be configured and started later)
let metricsCollector = null;

// Timeout configuration
const DEFAULT_EENGINE_TIMEOUT = 10 * 1000;
const EENGINE_TIMEOUT = getDuration(readEnvValue('EENGINE_TIMEOUT') || config.service.commandTimeout) || DEFAULT_EENGINE_TIMEOUT;

// Size limits
const DEFAULT_MAX_ATTACHMENT_SIZE = 5 * 1024 * 1024; // 5MB

// License check intervals
const SUBSCRIPTION_CHECK_TIMEOUT = 1 * 24 * 60 * 60 * 1000; // 24 hours
const SUBSCRIPTION_RECHECK_TIMEOUT = 1 * 60 * 60 * 1000; // 1 hour
const SUBSCRIPTION_ALLOW_DELAY = 28 * 24 * 60 * 60 * 1000; // 28 days grace period

// Delay between account connection setups (to avoid overwhelming the system)
const CONNECTION_SETUP_DELAY = getDuration(readEnvValue('EENGINE_CONNECTION_SETUP_DELAY') || config.service.setupDelay) || 0;

// Override configuration with environment variables
config.api.maxSize = getByteSize(readEnvValue('EENGINE_MAX_SIZE') || config.api.maxSize) || DEFAULT_MAX_ATTACHMENT_SIZE;
config.dbs.redis = readEnvValue('EENGINE_REDIS') || readEnvValue('REDIS_URL') || config.dbs.redis;

config.workers.imap = getWorkerCount(readEnvValue('EENGINE_WORKERS') || config.workers.imap) || 4;
config.workers.webhooks = Number(readEnvValue('EENGINE_WORKERS_WEBHOOKS')) || config.workers.webhooks || 1;
config.workers.submit = Number(readEnvValue('EENGINE_WORKERS_SUBMIT')) || config.workers.submit || 1;

config.api.port =
    (hasEnvValue('EENGINE_PORT') && Number(readEnvValue('EENGINE_PORT'))) || (hasEnvValue('PORT') && Number(readEnvValue('PORT'))) || config.api.port;
config.api.host = readEnvValue('EENGINE_HOST') || config.api.host;

config.log.level = readEnvValue('EENGINE_LOG_LEVEL') || config.log.level;

// Legacy SMTP configuration options (will be removed in future versions)
const SMTP_ENABLED = hasEnvValue('EENGINE_SMTP_ENABLED') ? getBoolean(readEnvValue('EENGINE_SMTP_ENABLED')) : getBoolean(config.smtp.enabled);
const SMTP_SECRET = readEnvValue('EENGINE_SMTP_SECRET') || config.smtp.secret;
const SMTP_PORT = (readEnvValue('EENGINE_SMTP_PORT') && Number(readEnvValue('EENGINE_SMTP_PORT'))) || Number(config.smtp.port) || 2525;
const SMTP_HOST = readEnvValue('EENGINE_SMTP_HOST') || config.smtp.host || '127.0.0.1';
const SMTP_PROXY = hasEnvValue('EENGINE_SMTP_PROXY') ? getBoolean(readEnvValue('EENGINE_SMTP_PROXY')) : getBoolean(config.smtp.proxy);

// IMAP proxy configuration
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

// Metrics collection interval - consider connections recent if started within 10 minutes
const METRIC_RECENT = 10 * 60 * 1000; // 10min

// API proxy configuration
const HAS_API_PROXY_SET = hasEnvValue('EENGINE_API_PROXY') || typeof config.api.proxy !== 'undefined';
const API_PROXY = hasEnvValue('EENGINE_API_PROXY') ? getBoolean(readEnvValue('EENGINE_API_PROXY')) : getBoolean(config.api.proxy);

// API authentication requirement configuration (default: true)
const REQUIRE_API_AUTH = hasEnvValue('EENGINE_REQUIRE_API_AUTH') ? getBoolean(readEnvValue('EENGINE_REQUIRE_API_AUTH')) : null;

// OAuth2 token access configuration
const ENABLE_OAUTH_TOKENS_API = hasEnvValue('EENGINE_ENABLE_OAUTH_TOKENS_API') ? getBoolean(readEnvValue('EENGINE_ENABLE_OAUTH_TOKENS_API')) : null;

// Log startup information
logger.info({
    msg: 'EmailEngine starting up',
    version: packageData.version,
    node: process.versions.node,
    uvThreadpoolSize: Number(process.env.UV_THREADPOOL_SIZE),
    workersImap: config.workers.imap,
    workersWebhooks: config.workers.webhooks,
    workersSubmission: config.workers.submit
});

// Standard response for when no active worker is available
const NO_ACTIVE_HANDLER_RESP_ERR = new Error('No active handler for requested account. Try again later.');
NO_ACTIVE_HANDLER_RESP_ERR.statusCode = 503;
NO_ACTIVE_HANDLER_RESP_ERR.code = 'WorkerNotAvailable';

// Update check intervals
const UPGRADE_CHECK_TIMEOUT = 1 * 24 * 3600 * 1000; // 24 hours
const LICENSE_CHECK_TIMEOUT = 20 * 60 * 1000; // 20 minutes
const MAX_LICENSE_CHECK_DELAY = 30 * 24 * 60 * 60 * 1000; // 30 days

/**
 * License information object
 * @typedef {Object} LicenseInfo
 * @property {boolean} active - Whether license is active
 * @property {Object|boolean} details - License details or false if no license
 * @property {string} type - License type description
 */
const licenseInfo = {
    active: false,
    details: false,
    type: packageData.license
};

/**
 * Human-readable thread type names for display
 * @const {Object<string, string>}
 */
const THREAD_NAMES = {
    main: 'Main thread',
    imap: 'Email worker',
    webhooks: 'Webhook worker',
    api: 'HTTP and API server',
    submit: 'Email sending worker',
    documents: 'Document store indexing worker',
    imapProxy: 'IMAP proxy server',
    smtp: 'SMTP proxy server'
};

/**
 * Configuration key-value mappings for different thread types
 * @const {Object<string, {key: string, value: number}>}
 */
const THREAD_CONFIG_VALUES = {
    imap: { key: 'EENGINE_WORKERS', value: config.workers.imap },
    submit: { key: 'EENGINE_WORKERS_SUBMIT', value: config.workers.submit },
    webhooks: { key: 'EENGINE_WORKERS_WEBHOOKS', value: config.workers.webhooks }
};

// Queue event handlers for different job queues
const queueEvents = {};

// Unique run index for this server instance
let runIndex;

// Prepared configuration handling
let preparedSettings = false;
const preparedSettingsString = readEnvValue('EENGINE_SETTINGS') || config.settings;
if (preparedSettingsString) {
    // Parse and validate pre-configured settings
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
        logger.error({ msg: 'Invalid settings configuration provided', input: preparedSettingsString, err });
        logger.flush(() => process.exit(1));
    }
}

// Prepared token handling for pre-configured API tokens
let preparedToken = false;
const preparedTokenString = readEnvValue('EENGINE_PREPARED_TOKEN') || config.preparedToken;
if (preparedTokenString) {
    try {
        preparedToken = msgpack.decode(Buffer.from(preparedTokenString, 'base64url'));
        if (!preparedToken || !/^[0-9a-f]{64}$/i.test(preparedToken.id)) {
            throw new Error('Token format is invalid');
        }
    } catch (err) {
        logger.error({ msg: 'Invalid API token provided', input: preparedTokenString, err });
        logger.flush(() => process.exit(1));
    }
}

// Prepared password handling for pre-configured admin passwords
let preparedPassword = false;
const preparedPasswordString = readEnvValue('EENGINE_PREPARED_PASSWORD') || config.preparedPassword;
if (preparedPasswordString) {
    try {
        preparedPassword = Buffer.from(preparedPasswordString, 'base64url').toString();
        if (!preparedPassword || preparedPassword.indexOf('$pbkdf2') !== 0) {
            throw new Error('Password format is invalid');
        }
    } catch (err) {
        logger.error({ msg: 'Invalid password hash provided', input: preparedPasswordString, err });
        logger.flush(() => process.exit(1));
    }
}

// Initialize Prometheus metrics collection
const collectDefaultMetrics = promClient.collectDefaultMetrics;
collectDefaultMetrics({});

/**
 * Prometheus metrics definitions for monitoring
 * @const {Object}
 */
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

    imapBytesSent: new promClient.Counter({
        name: 'imap_bytes_sent',
        help: 'IMAP bytes sent'
    }),

    imapBytesReceived: new promClient.Counter({
        name: 'imap_bytes_received',
        help: 'IMAP bytes received'
    }),

    oauth2TokenRefresh: new promClient.Counter({
        name: 'oauth2_token_refresh',
        help: 'OAuth2 access token refresh attempts',
        labelNames: ['status', 'provider', 'statusCode']
    }),

    oauth2ApiRequest: new promClient.Counter({
        name: 'oauth2_api_request',
        help: 'OAuth2 API requests (MS Graph, Gmail API)',
        labelNames: ['status', 'provider', 'statusCode']
    }),

    outlookSubscriptions: new promClient.Gauge({
        name: 'outlook_subscriptions',
        help: 'MS Graph webhook subscription states',
        labelNames: ['status']
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

    threads: new promClient.Gauge({
        name: 'threads',
        help: 'Worker Threads',
        labelNames: ['type', 'recent']
    }),

    unresponsiveWorkers: new promClient.Gauge({
        name: 'unresponsive_workers',
        help: 'Number of unresponsive worker threads'
    }),

    licenseDaysRemaining: new promClient.Gauge({
        name: 'license_days_remaining',
        help: 'Days until license expires (-1 for lifetime, 0 for no license)'
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

    redisPing: new promClient.Gauge({
        name: 'redis_latency',
        help: 'Redis latency in nanoseconds'
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

// Inter-thread communication tracking
let callQueue = new Map(); // Tracks pending cross-thread calls
let mids = 0; // Message ID counter

// Application state flags
let isClosing = false; // Is the application shutting down?
let assigning = false; // Is account assignment in progress?

// Account assignment tracking
let unassigned = false; // Set of unassigned accounts
let assigned = new Map(); // Map of account -> worker
let workerAssigned = new WeakMap(); // Map of worker -> Set of accounts
let onlineWorkers = new WeakSet(); // Set of workers that are online
let reassignmentTimer = null; // Timer for failsafe reassignment
let reassignmentPending = false; // Flag to track if reassignment is pending

// Worker management
let imapInitialWorkersLoaded = false; // Have all initial IMAP workers started?
let workers = new Map(); // Map of type -> Set of workers
let workersMeta = new WeakMap(); // Worker metadata
let availableIMAPWorkers = new Set(); // IMAP workers ready to accept accounts

// Worker health monitoring
let workerHeartbeats = new WeakMap(); // Map of worker -> last heartbeat timestamp
let workerHealthStatus = new WeakMap(); // Map of worker -> health status
const HEARTBEAT_TIMEOUT = 30 * 1000; // 30 seconds before marking unhealthy
const HEARTBEAT_RESTART_TIMEOUT = 60 * 1000; // 60 seconds before auto-restart

// Suspended worker types (when no license is active)
let suspendedWorkerTypes = new Set();

/**
 * Send a message to a worker thread with safety checks
 * @param {Worker} worker - The worker thread to send to
 * @param {Object} payload - Message payload
 * @param {boolean} ignoreOffline - Whether to ignore offline status
 * @param {Array} transferList - Transferable objects
 * @returns {boolean} Success status
 * @throws {Error} If worker is offline and ignoreOffline is false
 */
const postMessage = (worker, payload, ignoreOffline, transferList) => {
    // Check if worker is online
    if (!onlineWorkers.has(worker)) {
        if (ignoreOffline) {
            return false;
        }
        throw new Error('Worker thread is not available');
    }

    // Send the message
    let result = worker.postMessage(payload, transferList);

    // Update worker metadata
    let workerMeta = workersMeta.has(worker) ? workersMeta.get(worker) : {};
    workerMeta.called = workerMeta.called ? ++workerMeta.called : 1;
    workersMeta.set(worker, workerMeta);

    return result;
};

/**
 * Update server state in Redis and notify API workers
 * @param {string} type - Server type ('smtp' or 'imapProxy')
 * @param {string} state - New state
 * @param {Object} payload - Optional payload data
 * @returns {Promise<void>}
 */
let updateServerState = async (type, state, payload) => {
    // Store state in Redis
    await redis.hset(`${REDIS_PREFIX}${type}`, 'state', state);
    if (payload) {
        await redis.hset(`${REDIS_PREFIX}${type}`, 'payload', JSON.stringify(payload));
    }

    // Notify all API workers about the state change
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
                logger.error({ msg: 'Unable to notify worker about state change', worker: worker.threadId, callPayload, err });
            }
        }
    }
};

/**
 * Get detailed information about all threads
 * @returns {Promise<Array>} Array of thread information objects
 */
async function getThreadsInfo() {
    // Use metrics collector if available
    if (metricsCollector) {
        let threadsInfo = await metricsCollector.getThreadsInfo();

        // Add human-readable descriptions and configuration info
        threadsInfo.forEach(threadInfo => {
            threadInfo.description = THREAD_NAMES[threadInfo.type];
            if (THREAD_CONFIG_VALUES[threadInfo.type]) {
                threadInfo.config = THREAD_CONFIG_VALUES[threadInfo.type];
            }
        });

        return threadsInfo;
    }

    // Fallback to original implementation if collector not initialized
    // This should only happen during startup or if collector fails

    // Start with main thread info
    let threadsInfo = [Object.assign({ type: 'main', isMain: true, threadId: 0, online: NOW }, threadStats.usage())];

    // Define a short timeout for unresponsive workers (500ms)
    const WORKER_STATS_TIMEOUT = 500;

    // Collect info from all worker threads with timeout handling
    const workerPromises = [];
    const workerMetadata = [];

    for (let [type, workerSet] of workers) {
        if (workerSet && workerSet.size) {
            for (let worker of workerSet) {
                // Store metadata for later processing
                workerMetadata.push({ type, worker });

                // Use built-in timeout parameter of call function
                const workerPromise = call(worker, {
                    cmd: 'resource-usage',
                    timeout: WORKER_STATS_TIMEOUT
                }).catch(err => ({
                    // Return error info instead of throwing
                    resourceUsageError: {
                        error: err.message,
                        code: err.code || 'TIMEOUT',
                        unresponsive: err.code === 'Timeout'
                    }
                }));

                workerPromises.push(workerPromise);
            }
        }
    }

    // Wait for all workers to respond or timeout using allSettled
    const results = await Promise.allSettled(workerPromises);

    // Process results
    results.forEach((result, index) => {
        const { type, worker } = workerMetadata[index];
        const resourceUsage =
            result.status === 'fulfilled'
                ? result.value
                : {
                      resourceUsageError: {
                          error: result.reason?.message || 'Unknown error',
                          code: 'PROMISE_REJECTED',
                          unresponsive: true
                      }
                  };

        let threadData = Object.assign(
            {
                type,
                threadId: worker.threadId,
                resourceLimits: worker.resourceLimits
            },
            resourceUsage
        );

        // Add account count for IMAP workers
        if (workerAssigned.has(worker)) {
            threadData.accounts = workerAssigned.get(worker).size;
        }

        // Add health status
        threadData.healthStatus = workerHealthStatus.get(worker) || 'unknown';
        const lastHeartbeat = workerHeartbeats.get(worker);
        if (lastHeartbeat) {
            threadData.lastHeartbeat = lastHeartbeat;
            threadData.timeSinceHeartbeat = Date.now() - lastHeartbeat;
        }

        // Add worker metadata
        let workerMeta = workersMeta.has(worker) ? workersMeta.get(worker) : {};
        for (let key of Object.keys(workerMeta)) {
            threadData[key] = workerMeta[key];
        }

        threadsInfo.push(threadData);
    });

    // Add human-readable descriptions and configuration info
    threadsInfo.forEach(threadInfo => {
        threadInfo.description = THREAD_NAMES[threadInfo.type];
        if (THREAD_CONFIG_VALUES[threadInfo.type]) {
            threadInfo.config = THREAD_CONFIG_VALUES[threadInfo.type];
        }
    });

    return threadsInfo;
}

/**
 * Handle heartbeat from worker thread
 * @param {Worker} worker - The worker thread
 */
function handleWorkerHeartbeat(worker) {
    const now = Date.now();
    workerHeartbeats.set(worker, now);

    // Mark as healthy if it was previously unhealthy
    const previousStatus = workerHealthStatus.get(worker);
    if (previousStatus === 'unhealthy' || previousStatus === 'critical') {
        logger.info({
            msg: 'Worker recovered',
            threadId: worker.threadId,
            type: workersMeta.get(worker)?.type
        });
    }
    workerHealthStatus.set(worker, 'healthy');
}

/**
 * Check health of all worker threads
 * @returns {Promise<void>}
 */
async function checkWorkerHealth() {
    const now = Date.now();

    for (let [type, workerSet] of workers) {
        for (let worker of workerSet) {
            const lastHeartbeat = workerHeartbeats.get(worker);
            const currentStatus = workerHealthStatus.get(worker) || 'unknown';

            if (!lastHeartbeat) {
                // No heartbeat recorded yet, skip
                continue;
            }

            const timeSinceHeartbeat = now - lastHeartbeat;

            if (timeSinceHeartbeat > HEARTBEAT_RESTART_TIMEOUT && currentStatus !== 'restarting') {
                // Worker is critically unresponsive, restart it
                logger.error({
                    msg: 'Worker critically unresponsive, restarting',
                    threadId: worker.threadId,
                    type,
                    timeSinceHeartbeat: Math.round(timeSinceHeartbeat / 1000) + 's'
                });

                workerHealthStatus.set(worker, 'restarting');

                // Terminate the worker (this will trigger automatic restart)
                try {
                    await worker.terminate();
                } catch (err) {
                    logger.error({
                        msg: 'Failed to terminate unresponsive worker',
                        threadId: worker.threadId,
                        type,
                        err
                    });
                }
            } else if (timeSinceHeartbeat > HEARTBEAT_TIMEOUT && currentStatus === 'healthy') {
                // Worker is unhealthy but not critical yet
                logger.warn({
                    msg: 'Worker unhealthy - no heartbeat',
                    threadId: worker.threadId,
                    type,
                    timeSinceHeartbeat: Math.round(timeSinceHeartbeat / 1000) + 's'
                });

                workerHealthStatus.set(worker, 'unhealthy');
            }
        }
    }
}

/**
 * Start worker health monitoring
 */
function startHealthMonitoring() {
    // Check worker health every 5 seconds
    setInterval(() => {
        checkWorkerHealth().catch(err => {
            logger.error({ msg: 'Worker health check failed', err });
        });
    }, 5000);
}

/**
 * Send a webhook notification
 * @param {string} account - Account ID
 * @param {string} event - Event type
 * @param {Object} data - Event data
 * @returns {Promise<void>}
 */
async function sendWebhook(account, event, data) {
    let serviceUrl = (await settings.get('serviceUrl')) || null;

    let payload = {
        serviceUrl,
        account,
        date: new Date().toISOString()
    };

    if (event) {
        payload.event = event;
    }

    if (data) {
        payload.data = data;
    }

    await Webhooks.pushToQueue(event, await Webhooks.formatPayload(event, payload));
}

/**
 * Spawn a new worker thread of the specified type
 * @param {string} type - Worker type (imap, api, webhooks, submit, documents, smtp, imapProxy)
 * @returns {Promise<number|void>} Thread ID if successful
 */
let spawnWorker = async type => {
    // Don't spawn workers during shutdown
    if (isClosing) {
        return;
    }

    // Initialize worker set if needed
    if (!workers.has(type)) {
        workers.set(type, new Set());
    }

    // Check if worker type is suspended (no license)
    if (suspendedWorkerTypes.has(type)) {
        if (['smtp', 'imapProxy'].includes(type)) {
            await updateServerState(type, 'suspended', {});
        }
        return;
    }

    // Check if server type is enabled
    if (['smtp', 'imapProxy'].includes(type)) {
        let serverEnabled = await settings.get(`${type}ServerEnabled`);
        if (!serverEnabled) {
            await updateServerState(type, 'disabled', {});
            return;
        }

        await updateServerState(type, 'spawning');
    }

    // Create new worker thread
    let worker = new WorkerThread(pathlib.join(__dirname, 'workers', `${type.replace(/[A-Z]/g, c => `-${c.toLowerCase()}`)}.js`), {
        argv,
        env: SHARE_ENV,
        trackUnmanagedFds: true
    });
    metrics.threadStarts.inc();

    workers.get(type).add(worker);

    return new Promise((resolve, reject) => {
        let isOnline = false;
        let threadId = worker.threadId;

        // Handle worker coming online
        worker.on('online', () => {
            if (['smtp', 'imapProxy'].includes(type)) {
                updateServerState(type, 'initializing').catch(err => logger.error({ msg: `Unable to update ${type} server state`, err }));
            }
            onlineWorkers.add(worker);

            // Update worker metadata
            let workerMeta = workersMeta.has(worker) ? workersMeta.get(worker) : {};
            workerMeta.online = Date.now();
            workersMeta.set(worker, workerMeta);

            // Non-IMAP/API workers are ready immediately
            if (type !== 'imap' && type !== 'api') {
                isOnline = true;
                resolve(threadId);
            }
        });

        /**
         * Handle worker exit
         * @param {number} exitCode - Process exit code
         */
        let exitHandler = async exitCode => {
            onlineWorkers.delete(worker);
            metrics.threadStops.inc();

            workers.get(type).delete(worker);

            // Update server state for proxy servers
            if (['smtp', 'imapProxy'].includes(type)) {
                updateServerState(type, suspendedWorkerTypes.has(type) ? 'suspended' : 'exited');
            }

            // Handle IMAP worker cleanup
            if (type === 'imap') {
                availableIMAPWorkers.delete(worker);

                // Reassign accounts from dead worker
                if (workerAssigned.has(worker)) {
                    let accountList = workerAssigned.get(worker);
                    workerAssigned.delete(worker);

                    for (let account of accountList) {
                        assigned.delete(account);
                        unassigned.add(account);
                    }

                    logger.info({
                        msg: 'Worker exited, moving accounts to unassigned',
                        accounts: accountList.size,
                        exitCode
                    });
                } else if (exitCode === 0) {
                    // Worker exited cleanly (likely Redis reconnection) but we lost track of its accounts
                    // This can happen when Redis disconnects and reconnects
                    logger.warn({
                        msg: 'Worker exited cleanly but had no tracked accounts, checking for orphaned accounts',
                        exitCode,
                        availableWorkers: availableIMAPWorkers.size
                    });

                    // Check if all workers have exited (Redis reconnection scenario)
                    if (availableIMAPWorkers.size === 0) {
                        logger.info({
                            msg: 'All IMAP workers exited, reloading accounts from Redis for reassignment'
                        });

                        // Reload all accounts from Redis since we lost track
                        try {
                            let accounts = await redis.smembers(`${REDIS_PREFIX}ia:accounts`);
                            unassigned = new Set(accounts);
                            assigned.clear();
                            workerAssigned = new WeakMap();

                            logger.info({
                                msg: 'Reloaded accounts from Redis',
                                accountCount: accounts.length
                            });
                        } catch (err) {
                            logger.error({
                                msg: 'Failed to reload accounts from Redis',
                                err
                            });
                        }
                    }
                }

                // Don't reassign immediately - wait for the worker to restart
                if (unassigned && unassigned.size > 0) {
                    reassignmentPending = true;

                    // Clear any existing timer
                    if (reassignmentTimer) {
                        clearTimeout(reassignmentTimer);
                    }

                    // Set a failsafe timer - if worker doesn't restart in 10 seconds, reassign anyway
                    reassignmentTimer = setTimeout(() => {
                        if (reassignmentPending && unassigned && unassigned.size > 0) {
                            logger.warn({
                                msg: 'Failsafe reassignment triggered - worker restart timeout',
                                unassignedAccounts: unassigned.size,
                                currentWorkers: availableIMAPWorkers.size,
                                expectedWorkers: config.workers.imap
                            });
                            reassignmentPending = false;
                            assignAccounts().catch(err => logger.error({ msg: 'Unable to reassign accounts (failsafe)', err }));
                        }
                    }, 10000); // 10 second timeout

                    logger.info({
                        msg: 'Worker crashed, waiting for restart before reassignment',
                        accounts: unassigned.size,
                        expectedWorkers: config.workers.imap,
                        currentWorkers: availableIMAPWorkers.size
                    });
                }
            }

            if (isClosing) {
                return;
            }

            // Log worker exit
            if (suspendedWorkerTypes.has(type)) {
                logger.info({ msg: 'Worker thread terminated', exitCode, type });
            } else {
                logger.error({ msg: 'Worker unexpectedly exited', exitCode, type });
            }

            // Respawn worker after delay
            await new Promise(r => setTimeout(r, 1000));
            await spawnWorker(type);
        };

        // Handle worker exit
        worker.on('exit', exitCode => {
            if (!isOnline) {
                let error = new Error(`Unable to start ${type} worker thread`);

                error.workerType = type;
                error.exitCode = exitCode;
                error.threadId = threadId;

                reject(error);
            }

            exitHandler(exitCode).catch(err => {
                logger.error({ msg: 'Error handling worker exit', exitCode, type, worker: worker.threadId, err });
            });
        });

        // Handle messages from worker
        worker.on('message', message => {
            // Update message count
            let workerMeta = workersMeta.has(worker) ? workersMeta.get(worker) : {};
            workerMeta.messages = workerMeta.messages ? ++workerMeta.messages : 1;
            workersMeta.set(worker, workerMeta);

            if (!message) {
                return;
            }

            // Handle heartbeat from worker
            if (message.cmd === 'heartbeat') {
                handleWorkerHeartbeat(worker);
                return;
            }

            // Handle response to a call
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

            // Handle call from worker
            if (message.cmd === 'call' && message.mid) {
                return onCommand(worker, message.message)
                    .then(response => {
                        let transferList;
                        // Handle transferable objects
                        if (response && typeof response === 'object' && response._transfer === true) {
                            if (typeof response._response === 'object' && response._response && response._response.buffer) {
                                transferList = [response._response.buffer];
                            }
                            response = response._response;
                        }

                        let callPayload = {
                            cmd: 'resp',
                            mid: message.mid,
                            response
                        };

                        try {
                            postMessage(worker, callPayload, null, transferList);
                        } catch (err) {
                            // Log buffer info instead of full buffer
                            if (Buffer.isBuffer(callPayload.response)) {
                                callPayload.response = `Buffer <${callPayload.response.length}B>`;
                            }

                            logger.error({ msg: 'Unable to send response to worker', worker: worker.threadId, callPayload, err });
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
                            logger.error({ msg: 'Unable to send error response to worker', worker: worker.threadId, callPayload, err });
                        }
                    });
            }

            // Handle metrics messages
            switch (message.cmd) {
                case 'metrics': {
                    let statUpdateKey = false;
                    let accountUpdateKey = false;

                    let { account } = message.meta || {};

                    // Determine which metrics to update
                    switch (message.key) {
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
                            if (account) {
                                accountUpdateKey = `${message.key}:${event}`;
                            }

                            // Track specific events
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

                        case 'queuesProcessed': {
                            let { queue, status } = message.args[0] || {};
                            if (['submit'].includes(queue)) {
                                statUpdateKey = `${queue}:${status === 'completed' ? 'success' : 'fail'}`;
                            }
                            break;
                        }
                    }

                    // Update Redis counters for dashboard stats
                    if (statUpdateKey) {
                        let now = new Date();

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

                        let hkey = `${REDIS_PREFIX}stats:${statUpdateKey}:${dateStr}`;

                        let update = redis
                            .multi()
                            .hincrby(hkey, timeStr, 1)
                            .sadd(`${REDIS_PREFIX}stats:keys`, statUpdateKey)
                            .expire(hkey, MAX_DAYS_STATS + 1 * 24 * 3600); // Keep for configured days + 1

                        if (account && accountUpdateKey) {
                            // Update account-specific counter
                            let accountKey = `${REDIS_PREFIX}iad:${account}`;
                            update = update.hincrby(accountKey, `stats:count:${accountUpdateKey}`, 1);
                        }

                        update.exec().catch(() => false);
                    } else if (account && accountUpdateKey) {
                        // Update only account-specific counter
                        let accountKey = `${REDIS_PREFIX}iad:${account}`;
                        redis.hincrby(accountKey, `stats:count:${accountUpdateKey}`, 1).catch(() => false);
                    }

                    // Update Prometheus metrics
                    if (message.key && metrics[message.key] && typeof metrics[message.key][message.method] === 'function') {
                        metrics[message.key][message.method](...message.args);
                    }

                    return;
                }

                case 'settings':
                    // Forward settings changes to all IMAP workers
                    availableIMAPWorkers.forEach(worker => {
                        try {
                            postMessage(worker, message);
                        } catch (err) {
                            logger.error({ msg: 'Unable to forward settings to worker', worker: worker.threadId, callPayload: message, err });
                        }
                    });
                    return;

                case 'change':
                    // Handle state changes
                    switch (message.type) {
                        case 'smtpServerState':
                        case 'imapProxyServerState': {
                            let type = message.type.replace(/ServerState$/, '');
                            updateServerState(type, message.key, message.payload).catch(err =>
                                logger.error({ msg: `Unable to update ${type} server state`, err })
                            );
                            break;
                        }
                        default:
                            // Forward all other state changes to API workers
                            for (let worker of workers.get('api') || []) {
                                try {
                                    postMessage(worker, message, true);
                                } catch (err) {
                                    logger.error({ msg: 'Unable to forward state change to worker', worker: worker.threadId, callPayload: message, err });
                                }
                            }
                    }
                    break;
            }

            // Handle worker type specific messages
            switch (type) {
                case 'imap':
                    if (message.cmd === 'ready') {
                        // IMAP worker is ready to accept accounts
                        availableIMAPWorkers.add(worker);
                        isOnline = true;

                        // Initialize heartbeat tracking
                        workerHeartbeats.set(worker, Date.now());
                        workerHealthStatus.set(worker, 'healthy');

                        resolve(worker.threadId);

                        logger.info({
                            msg: 'IMAP worker ready',
                            threadId: worker.threadId,
                            currentWorkers: availableIMAPWorkers.size,
                            expectedWorkers: config.workers.imap,
                            unassignedCount: unassigned ? unassigned.size : 0,
                            assignedCount: assigned.size,
                            imapInitialWorkersLoaded,
                            reassignmentPending
                        });

                        if (imapInitialWorkersLoaded && reassignmentPending) {
                            // Check if we now have the expected number of workers
                            // This handles the case where a worker crashed and restarted
                            if (availableIMAPWorkers.size === config.workers.imap) {
                                // All workers are back - clear timer and reassign
                                if (reassignmentTimer) {
                                    clearTimeout(reassignmentTimer);
                                    reassignmentTimer = null;
                                }
                                reassignmentPending = false;

                                if (unassigned && unassigned.size > 0) {
                                    logger.info({
                                        msg: 'All expected workers ready, reassigning unassigned accounts',
                                        workers: availableIMAPWorkers.size,
                                        unassigned: unassigned.size
                                    });
                                    assignAccounts().catch(err => logger.error({ msg: 'Unable to assign accounts', n: 2, err }));
                                } else {
                                    logger.warn({
                                        msg: 'All workers ready but no unassigned accounts found',
                                        workers: availableIMAPWorkers.size
                                    });
                                }
                            } else if (unassigned && unassigned.size > 0) {
                                // Still waiting for more workers to restart
                                logger.info({
                                    msg: 'Worker ready, waiting for all workers before reassignment',
                                    currentWorkers: availableIMAPWorkers.size,
                                    expectedWorkers: config.workers.imap,
                                    unassignedAccounts: unassigned.size
                                });
                            }
                        }
                    }
                    break;

                case 'api':
                    if (message.cmd === 'ready') {
                        // API worker is ready
                        isOnline = true;

                        // Initialize heartbeat tracking
                        workerHeartbeats.set(worker, Date.now());
                        workerHealthStatus.set(worker, 'healthy');

                        resolve(worker.threadId);
                    }
                    break;

                default:
                    // For all other worker types
                    if (message.cmd === 'ready') {
                        isOnline = true;

                        // Initialize heartbeat tracking
                        workerHeartbeats.set(worker, Date.now());
                        workerHealthStatus.set(worker, 'healthy');

                        resolve(worker.threadId);
                    }
                    break;
            }
        });
    });
};

/**
 * Call a command on a worker thread and wait for response
 * @param {Worker} worker - Target worker thread
 * @param {Object} message - Message to send
 * @param {Array} transferList - Optional transferable objects
 * @returns {Promise<*>} Response from worker
 * @throws {Error} Timeout or communication error
 */
async function call(worker, message, transferList) {
    return new Promise((resolve, reject) => {
        // Generate unique message ID
        let mid = `${Date.now()}:${++mids}`;

        // Calculate timeout - use explicit timeout if provided, otherwise fall back to EENGINE_TIMEOUT
        let ttl = typeof message.timeout === 'number' && message.timeout > 0 ? message.timeout : EENGINE_TIMEOUT || 0;

        // Set timeout handler
        let timer = setTimeout(() => {
            let err = new Error('Request timed out');
            err.statusCode = 504;
            err.code = 'Timeout';
            err.ttl = ttl;
            err.command = message;

            callQueue.delete(mid);

            reject(err);
        }, ttl);

        // Store callback info
        callQueue.set(mid, {
            resolve: result => {
                clearTimeout(timer);
                resolve(result);
            },
            reject: err => {
                clearTimeout(timer);
                reject(err);
            },
            timer
        });

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
            // Clean up on error
            clearTimeout(timer);
            callQueue.delete(mid);
            return reject(err);
        }
    });
}

/**
 * Assign unassigned accounts to available IMAP workers
 * Uses load-aware distribution with round-robin for initial assignment
 * and rendezvous hashing for reassignments after worker failures
 * @returns {Promise<boolean>} Success status
 */
async function assignAccounts() {
    // Prevent concurrent assignment
    if (assigning) {
        return false;
    }

    assigning = true;
    try {
        if (!unassigned) {
            // First run - load all accounts from Redis
            let accounts = await redis.smembers(`${REDIS_PREFIX}ia:accounts`);
            unassigned = new Set(accounts);
        }

        if (!availableIMAPWorkers.size || !unassigned.size) {
            // Nothing to do
            return;
        }

        logger.info({
            msg: 'Starting account assignment',
            unassigned: unassigned.size,
            workersAvailable: availableIMAPWorkers.size,
            setupDelay: CONNECTION_SETUP_DELAY
        });

        // Create a sorted list of workers by current load (number of assigned accounts)
        let workerLoadMap = new Map();
        for (let worker of availableIMAPWorkers) {
            let accountCount = workerAssigned.has(worker) ? workerAssigned.get(worker).size : 0;
            workerLoadMap.set(worker, accountCount);
        }

        // Sort workers by load (ascending) for even distribution
        let sortedWorkers = Array.from(workerLoadMap.entries())
            .sort((a, b) => a[1] - b[1])
            .map(entry => entry[0]);

        // Calculate target accounts per worker for even distribution
        let totalAccounts = assigned.size + unassigned.size;
        let targetPerWorker = Math.ceil(totalAccounts / availableIMAPWorkers.size);

        // Assign each unassigned account
        for (let account of unassigned) {
            if (!availableIMAPWorkers.size) {
                // No more workers available
                break;
            }

            let worker;

            // Check if this is a reassignment after worker failure
            // This happens when we have fewer available workers than configured
            // or when reassignmentPending flag is set
            let isReassignment = reassignmentPending || (assigned.size > 0 && availableIMAPWorkers.size < config.workers.imap);

            if (isReassignment) {
                // Use rendezvous hashing for consistent reassignment after failures
                worker = selectRendezvousNode(account, Array.from(availableIMAPWorkers));
            } else {
                // Use load-aware round-robin for initial assignment
                // Find the least loaded worker that hasn't reached the target
                worker = sortedWorkers.find(w => {
                    let currentLoad = workerLoadMap.get(w) || 0;
                    return currentLoad < targetPerWorker;
                });

                // If all workers reached target, use the least loaded one
                if (!worker) {
                    worker = sortedWorkers[0];
                }

                // Update the load map for next iteration
                workerLoadMap.set(worker, (workerLoadMap.get(worker) || 0) + 1);
                // Re-sort workers by updated load
                sortedWorkers = Array.from(workerLoadMap.entries())
                    .sort((a, b) => a[1] - b[1])
                    .map(entry => entry[0]);
            }

            // Track assignment
            if (!workerAssigned.has(worker)) {
                workerAssigned.set(worker, new Set());
            }

            workerAssigned.get(worker).add(account);
            assigned.set(account, worker);
            unassigned.delete(account);

            // Notify worker of assignment
            await call(worker, {
                cmd: 'assign',
                account,
                runIndex
            });

            // Add delay between assignments to avoid overwhelming the system
            if (CONNECTION_SETUP_DELAY) {
                await new Promise(r => setTimeout(r, CONNECTION_SETUP_DELAY));
            }
        }

        // Log final distribution for monitoring
        let distribution = [];
        for (let worker of availableIMAPWorkers) {
            let count = workerAssigned.has(worker) ? workerAssigned.get(worker).size : 0;
            distribution.push({ threadId: worker.threadId, accounts: count });
        }
        logger.info({
            msg: 'Account assignment completed',
            distribution,
            totalAssigned: assigned.size
        });
    } finally {
        assigning = false;
    }
}

// License checking state
let licenseCheckTimer = false;
let checkingLicense = false;

/**
 * Check and validate license status
 * @param {Object} opts - Options
 * @param {number} opts.subscriptionCheckTimeout - Timeout for subscription check
 * @returns {Promise<void>}
 */
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

        // Check if we need to validate the license
        let kv = await redis.hget(`${REDIS_PREFIX}settings`, 'kv');
        let checkKv = true;
        if (kv && typeof kv === 'string' && cv(packageData.version, Buffer.from(kv, 'hex').toString(), '<=')) {
            checkKv = false;
        }

        let ks = await redis.hget(`${REDIS_PREFIX}settings`, 'ks');
        if (ks && typeof ks === 'string') {
            let ksDate = new Date(parseInt(ks, 16));
            if (ksDate < now) {
                checkKv = true;
            }
        } else {
            checkKv = true;
        }

        // Clean up for lifetime licenses
        if (licenseInfo.details.lt) {
            await redis.hdel(`${REDIS_PREFIX}settings`, 'subexp');
        }

        // Validate subscription license
        if (
            checkKv &&
            licenseInfo.active &&
            !(licenseInfo.details && licenseInfo.details.expires) &&
            !licenseInfo.details.lt &&
            (await redis.hUpdateBigger(`${REDIS_PREFIX}settings`, 'subcheck', now - subscriptionCheckTimeout, now))
        ) {
            try {
                // Call license validation API
                let res = await fetchCmd(`https://postalsys.com/licenses/validate`, {
                    method: 'post',
                    headers: {
                        'User-Agent': `${packageData.name}/${packageData.version} (+${packageData.homepage})`,
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        key: licenseInfo.details.key,
                        version: packageData.version,
                        app: '@postalsys/emailengine-app',
                        instance: (await settings.get('serviceId')) || ''
                    }),
                    dispatcher: retryAgent
                });

                let data = await res.json();

                if (!res.ok) {
                    if (data.invalidate) {
                        // License validation failed - start grace period
                        let res = await redis.hUpdateBigger(`${REDIS_PREFIX}settings`, 'subexp', now, now + SUBSCRIPTION_ALLOW_DELAY);
                        if (res === 2) {
                            // Grace period expired
                            logger.info({ msg: 'License validation failed', license: licenseInfo.details, data });
                            await redis.multi().hdel(`${REDIS_PREFIX}settings`, 'license').hdel(`${REDIS_PREFIX}settings`, 'subexp').exec();
                            licenseInfo.active = false;
                            licenseInfo.details = false;
                            licenseInfo.type = packageData.license;
                        } else {
                            // Still in grace period - check again soon
                            let nextCheck = now + SUBSCRIPTION_RECHECK_TIMEOUT;
                            await redis.hset(`${REDIS_PREFIX}settings`, 'ks', new Date(nextCheck).getTime().toString(16));
                        }
                    }
                } else {
                    // License validated successfully
                    await redis.hdel(`${REDIS_PREFIX}settings`, 'subexp');
                    await redis.hset(`${REDIS_PREFIX}settings`, 'kv', Buffer.from(packageData.version).toString('hex'));
                    if (data.validatedUntil) {
                        let validatedUntil = new Date(data.validatedUntil);
                        let nextCheck = Math.min(now + MAX_LICENSE_CHECK_DELAY, validatedUntil.getTime());
                        await redis.hset(`${REDIS_PREFIX}settings`, 'ks', new Date(nextCheck).getTime().toString(16));
                    }
                }
            } catch (err) {
                logger.error({ msg: 'License validation error', err });
            }
        }

        // Check if license has expired
        if (licenseInfo.active && licenseInfo.details && licenseInfo.details.expires && new Date(licenseInfo.details.expires).getTime() < Date.now()) {
            logger.info({ msg: 'License has expired', license: licenseInfo.details });

            licenseInfo.active = false;
            licenseInfo.details = false;
        }

        // Handle no active license - suspend workers
        if (!licenseInfo.active && !suspendedWorkerTypes.size) {
            logger.info({ msg: 'No active license. Workers will be suspended after 15 minutes of inactivity.' });

            // Suspend all worker types except API
            for (let type of ['imap', 'submit', 'smtp', 'webhooks', 'imapProxy']) {
                suspendedWorkerTypes.add(type);
                if (workers.has(type)) {
                    for (let worker of workers.get(type).values()) {
                        worker.terminate();
                    }
                }
            }
        } else if (licenseInfo.active && suspendedWorkerTypes.size) {
            // Re-enable workers after license activated
            for (let type of suspendedWorkerTypes) {
                suspendedWorkerTypes.delete(type);
                switch (type) {
                    case 'smtp':
                    case 'imapProxy':
                        {
                            let serverEnabled = await settings.get(`${type}ServerEnabled`);
                            if (serverEnabled) {
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

/**
 * Schedule next license check
 */
function checkActiveLicense() {
    clearTimeout(licenseCheckTimer);
    licenseCheckHandler().catch(err => {
        logger.error('License check error', err);
    });
}

/**
 * Check for available EmailEngine updates
 * @returns {Promise<void>}
 */
let processCheckUpgrade = async () => {
    try {
        let updateInfo = await checkForUpgrade();
        if (updateInfo.canUpgrade) {
            logger.info({ msg: 'EmailEngine update available', updateInfo });

            updateInfo.checked = Date.now();
            await redis.hset(`${REDIS_PREFIX}settings`, 'upgrade', JSON.stringify(updateInfo));
        } else {
            await redis.hdel(`${REDIS_PREFIX}settings`, 'upgrade');
        }
    } catch (err) {
        logger.error({ msg: 'Update check failed', err });
    }
};

// Upgrade checking state
let upgradeCheckTimer = false;

/**
 * Periodic upgrade check handler
 * @returns {Promise<void>}
 */
let upgradeCheckHandler = async () => {
    let upgradeInfoExists = await redis.hexists(`${REDIS_PREFIX}settings`, 'upgrade');
    if (!upgradeInfoExists) {
        // No upgrade info stored
        return;
    }
    await processCheckUpgrade();
    upgradeCheckTimer = setTimeout(checkUpgrade, UPGRADE_CHECK_TIMEOUT);
    upgradeCheckTimer.unref();
};

/**
 * Schedule next upgrade check
 */
function checkUpgrade() {
    clearTimeout(upgradeCheckTimer);
    upgradeCheckHandler().catch(err => {
        logger.error('Update check error', err);
    });
}

// Redis ping monitoring
let redisPingCounter = [];

/**
 * Calculate average Redis ping latency
 * @returns {number|null} Average latency in nanoseconds
 */
function getRedisPing() {
    if (!redisPingCounter.length) {
        return null;
    }

    // Get recent entries and sort
    let entries = []
        .concat(redisPingCounter)
        .slice(-34)
        .sort((a, b) => a - b);

    // Remove outliers (2 highest and lowest)
    for (let i = 0; i < 2; i++) {
        if (entries.length > 4) {
            entries.shift();
            entries.pop();
        }
    }

    // Calculate average
    let sum = 0;
    for (let entry of entries) {
        sum += entry;
    }

    return Math.round(sum / entries.length);
}

const REDIS_PING_TIMEOUT = 10 * 1000;
let redisPingTimer = false;

/**
 * Measure current Redis ping latency
 * @returns {Promise<number>} Latency in nanoseconds
 */
const getCurrentRedisPing = async () => {
    try {
        // Warm up connection
        await redis.ping();

        // Measure actual ping
        let startTime = process.hrtime.bigint();
        await redis.ping();
        let endTime = process.hrtime.bigint();

        let duration = Number(endTime - startTime);

        return duration;
    } catch (err) {
        logger.error({ msg: 'Redis ping measurement failed', err });
    }
    return 0;
};

/**
 * Process and store Redis ping measurement
 * @returns {Promise<number>} Current ping duration
 */
const processRedisPing = async () => {
    try {
        let duration = await getCurrentRedisPing();
        redisPingCounter.push(duration);
        // Keep last 300 measurements
        if (redisPingCounter.length > 300) {
            redisPingCounter = redisPingCounter.slice(0, 150);
        }
        return duration;
    } catch (err) {
        logger.error({ msg: 'Redis ping processing failed', err });
    }
};

/**
 * Periodic Redis ping handler
 * @returns {Promise<void>}
 */
const redisPingHandler = async () => {
    await processRedisPing();
    redisPingTimer = setTimeout(checkRedisPing, REDIS_PING_TIMEOUT);
    redisPingTimer.unref();
};

/**
 * Schedule next Redis ping check
 */
function checkRedisPing() {
    clearTimeout(redisPingTimer);
    redisPingHandler().catch(err => {
        logger.error('Redis ping check error', err);
    });
}

/**
 * Update Prometheus metrics for queues and Redis
 * @returns {Promise<void>}
 */
async function updateQueueCounters() {
    // Update EmailEngine configuration metrics
    metrics.emailengineConfig.set({ version: 'v' + packageData.version }, 1);
    metrics.emailengineConfig.set({ config: 'uvThreadpoolSize' }, Number(process.env.UV_THREADPOOL_SIZE));
    metrics.emailengineConfig.set({ config: 'workersImap' }, config.workers.imap);
    metrics.emailengineConfig.set({ config: 'workersWebhooks' }, config.workers.webhooks);
    metrics.emailengineConfig.set({ config: 'workersSubmission' }, config.workers.submit);

    // Update license days remaining metric
    if (licenseInfo.active && licenseInfo.details) {
        if (licenseInfo.details.lt) {
            // Lifetime license
            metrics.licenseDaysRemaining.set(-1);
        } else if (licenseInfo.details.expires) {
            // Time-limited license
            let expiresAt = new Date(licenseInfo.details.expires).getTime();
            let daysRemaining = Math.max(0, Math.ceil((expiresAt - Date.now()) / (24 * 60 * 60 * 1000)));
            metrics.licenseDaysRemaining.set(daysRemaining);
        } else {
            // Subscription license (no fixed expiry)
            metrics.licenseDaysRemaining.set(-1);
        }
    } else {
        // No active license
        metrics.licenseDaysRemaining.set(0);
    }

    // Update thread metrics
    let threadsInfo = await getThreadsInfo();

    let now = Date.now();

    let threadCounts = new Map();
    let unresponsiveCount = 0;
    for (let workerThreadInfo of threadsInfo || []) {
        let key = workerThreadInfo.type;
        let metricKey = `${key}_total`;

        // Check if thread is recent (started within METRIC_RECENT)
        let recent = now - workerThreadInfo.online < METRIC_RECENT;
        if (recent) {
            metricKey = `${key}_recent`;
        }

        if (!threadCounts.has(metricKey)) {
            threadCounts.set(metricKey, 1);
        } else {
            threadCounts.set(metricKey, threadCounts.get(metricKey) + 1);
        }

        // Count unresponsive workers
        if (workerThreadInfo.resourceUsageError && workerThreadInfo.resourceUsageError.unresponsive) {
            unresponsiveCount++;
        }
    }

    // Set thread count metrics
    for (let [key, value] of threadCounts.entries()) {
        let [type, age] = key.split('_');
        metrics.threads.set({ type, recent: age === 'recent' ? 'yes' : 'no' }, value || 0);
    }

    // Set unresponsive workers metric
    metrics.unresponsiveWorkers.set(unresponsiveCount);

    // Update queue metrics
    for (let queue of ['notify', 'submit', 'documents']) {
        const [resActive, resDelayed, resPaused, resWaiting] = await redis
            .multi()
            .llen(`${REDIS_PREFIX}bull:${queue}:active`)
            .zcard(`${REDIS_PREFIX}bull:${queue}:delayed`)
            .llen(`${REDIS_PREFIX}bull:${queue}:paused`)
            .llen(`${REDIS_PREFIX}bull:${queue}:wait`)
            .exec();
        if (resActive[0] || resDelayed[0] || resPaused[0] || resWaiting[0]) {
            // Counting failed
            logger.error({ msg: 'Queue length count failed', queue, active: resActive, delayed: resDelayed, paused: resPaused, waiting: resWaiting });
            return false;
        }

        metrics.queues.set({ queue: `${queue}`, state: `active` }, Number(resActive[1]) || 0);
        metrics.queues.set({ queue: `${queue}`, state: `delayed` }, Number(resDelayed[1]) || 0);
        metrics.queues.set({ queue: `${queue}`, state: `paused` }, Number(resPaused[1]) || 0);
        metrics.queues.set({ queue: `${queue}`, state: `waiting` }, Number(resWaiting[1]) || 0);
    }

    // Update Redis metrics
    try {
        let redisInfo = await getRedisStats(redis);

        if (redisInfo.redis_version) {
            metrics.redisVersion.set({ version: 'v' + redisInfo.redis_version }, 1);
        }

        metrics.redisUptimeInSeconds.set(Number(redisInfo.uptime_in_seconds) || 0);

        metrics.redisPing.set((await getCurrentRedisPing()) || 0);

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

        // Update per-database metrics
        Object.keys(redisInfo).forEach(key => {
            if (/^db\d+$/.test(key)) {
                metrics.redisKeyCount.set({ db: key }, Number(redisInfo[key].keys) || 0);
            }

            // Update command stats
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
        logger.error({ msg: 'Metrics update failed', err });
    }
}

/**
 * Handle commands from worker threads
 * @param {Worker} worker - Source worker
 * @param {Object} message - Command message
 * @returns {Promise<*>} Command result
 */
async function onCommand(worker, message) {
    switch (message.cmd) {
        case 'metrics':
            // Return Prometheus metrics
            await updateQueueCounters();
            return promClient.register.metrics();

        case 'structuredMetrics': {
            // Return structured metrics for API
            let connections = {};

            for (let key of Object.keys(metrics.imapConnections.hashMap)) {
                if (key.indexOf('status:') === 0) {
                    let metric = metrics.imapConnections.hashMap[key];
                    connections[metric.labels.status] = metric.value;
                }
            }

            return { connections, redisPing: await getRedisPing() };
        }

        case 'imapWorkerCount': {
            // Return number of available IMAP workers
            return { workers: availableIMAPWorkers.size };
        }

        case 'checkLicense':
            // Force license check
            try {
                await licenseCheckHandler({
                    subscriptionCheckTimeout: 60 * 1000
                });
            } catch (err) {
                // ignore
            }
            return licenseInfo;

        case 'license':
            // Return license info with suspension status
            if (!licenseInfo.active && suspendedWorkerTypes.size) {
                return Object.assign({}, licenseInfo, { suspended: true });
            }
            return licenseInfo;

        case 'updateLicense': {
            // Update license from API
            try {
                const licenseFile = message.license;

                let licenseData = await checkLicense(licenseFile);
                if (!licenseData) {
                    throw new Error('Invalid license provided');
                }

                logger.info({ msg: 'License updated', license: licenseData, source: 'API' });

                await setLicense(licenseData, licenseFile);

                licenseInfo.active = true;
                licenseInfo.details = licenseData;
                licenseInfo.type = 'EmailEngine License';

                // Re-enable workers
                checkActiveLicense();

                return licenseInfo;
            } catch (err) {
                logger.fatal({ msg: 'License update failed', source: 'API', err });
                return false;
            }
        }

        case 'removeLicense': {
            // Remove existing license
            try {
                await redis.multi().hdel(`${REDIS_PREFIX}settings`, 'license').hdel(`${REDIS_PREFIX}settings`, 'subexp').exec();

                licenseInfo.active = false;
                licenseInfo.details = false;
                licenseInfo.type = packageData.license;

                return licenseInfo;
            } catch (err) {
                logger.fatal({ msg: 'License removal failed', err });
                return false;
            }
        }

        case 'kill-thread': {
            // Terminate a specific thread
            for (let [, workerSet] of workers) {
                if (workerSet && workerSet.size) {
                    for (let worker of workerSet) {
                        if (worker.threadId === message.thread) {
                            logger.info({ msg: 'Thread termination requested', thread: message.thread });
                            return await worker.terminate();
                        }
                    }
                }
            }

            return false;
        }

        case 'snapshot-thread': {
            // Get heap snapshot for debugging
            if (message.thread === 0) {
                // Main thread only - V8 operations should be done in main thread
                try {
                    logger.info({ msg: 'Heap snapshot requested', thread: message.thread });
                    const stream = v8.getHeapSnapshot();
                    if (stream) {
                        return { _transfer: true, _response: await download(stream) };
                    }
                } catch (err) {
                    logger.error({ msg: 'Failed to generate heap snapshot', thread: message.thread, err });
                }
                return false;
            }

            // Worker thread - use worker's built-in method which is safer
            for (let [, workerSet] of workers) {
                if (workerSet && workerSet.size) {
                    for (let worker of workerSet) {
                        if (worker.threadId === message.thread) {
                            try {
                                logger.info({ msg: 'Heap snapshot requested', thread: message.thread });
                                // Use worker's built-in getHeapSnapshot method instead of V8 API
                                const stream = await worker.getHeapSnapshot({ exposeInternals: true, exposeNumericValues: true });
                                if (stream) {
                                    return { _transfer: true, _response: await download(stream) };
                                }
                            } catch (err) {
                                logger.error({ msg: 'Failed to generate heap snapshot for worker', thread: message.thread, err });
                            }
                            return false;
                        }
                    }
                }
            }

            return false;
        }

        case 'bounceClassify':
            // Classify bounce response message
            try {
                return await bounceClassifier.classify(message.data.message);
            } catch (err) {
                // ignore
                logger.error({
                    msg: 'Failed to classify bounce response',
                    bounceResponse: message.data.message,
                    err
                });
            }
            return false;

        // OpenAI integration commands - run in main process to avoid memory overhead
        case 'generateSummary': {
            let requestOpts = {
                verbose: getBoolean(process.env.EE_OPENAPI_VERBOSE)
            };

            let openAiAPIKey = message.data.openAiAPIKey || (await settings.get('openAiAPIKey'));

            if (!openAiAPIKey) {
                throw new Error(`OpenAI API key is not configured`);
            }

            let openAiModel = message.data.openAiModel || (await settings.get('openAiModel'));
            if (openAiModel) {
                requestOpts.gptModel = openAiModel;
            }

            let openAiAPIUrl = message.data.openAiAPIUrl || (await settings.get('openAiAPIUrl'));
            if (openAiAPIUrl) {
                requestOpts.baseApiUrl = openAiAPIUrl;
            }

            let openAiTemperature = message.data.openAiTemperature || (await settings.get('openAiTemperature'));
            if (openAiTemperature) {
                requestOpts.temperature = openAiTemperature;
            }

            let openAiTopP = message.data.openAiTopP || (await settings.get('openAiTopP'));
            if (openAiTopP) {
                requestOpts.topP = openAiTopP;
            }

            let openAiMaxTokens = message.data.openAiMaxTokens || (await settings.get('openAiMaxTokens'));
            if (openAiMaxTokens) {
                requestOpts.maxTokens = openAiMaxTokens;
            } else {
                // Set max tokens based on model
                switch (openAiModel.substring(0, 5)) {
                    case 'gpt-3':
                        requestOpts.maxTokens = 3000;
                        break;
                    case 'gpt-4':
                        requestOpts.maxTokens = 6500;
                        break;
                    case 'gpt-5':
                    default:
                        requestOpts.maxTokens = 18000;
                        break;
                }
            }

            requestOpts.user = message.data.account;

            let userPrompt = message.data.openAiPrompt || ((await settings.get('openAiPrompt')) || '').toString();
            if (userPrompt.trim()) {
                requestOpts.userPrompt = userPrompt;
            }

            return await generateSummary(message.data.message, openAiAPIKey, requestOpts);
        }

        case 'generateEmbeddings': {
            let requestOpts = {
                verbose: getBoolean(process.env.EE_OPENAPI_VERBOSE)
            };

            let openAiAPIKey = message.data.openAiAPIKey || (await settings.get('openAiAPIKey'));

            if (!openAiAPIKey) {
                throw new Error(`OpenAI API key is not configured`);
            }

            let openAiAPIUrl = message.data.openAiAPIUrl || (await settings.get('openAiAPIUrl'));
            if (openAiAPIUrl) {
                requestOpts.baseApiUrl = openAiAPIUrl;
            }

            requestOpts.user = message.data.account;

            const embeddings = await generateEmbeddings(message.data.message, openAiAPIKey, requestOpts);
            if (!Array.isArray(embeddings?.embeddings)) {
                return false;
            }

            // Clean internal properties
            for (let value of embeddings.embeddings) {
                for (const key of Object.keys(value)) {
                    if (/^_/.test(key)) {
                        delete value[key];
                    }
                }
            }

            return embeddings;
        }

        case 'embeddingsQuery': {
            let requestOpts = {
                verbose: getBoolean(process.env.EE_OPENAPI_VERBOSE)
            };

            let openAiAPIKey = message.data.openAiAPIKey || (await settings.get('openAiAPIKey'));

            if (!openAiAPIKey) {
                throw new Error(`OpenAI API key is not configured`);
            }

            let openAiAPIUrl = message.data.openAiAPIUrl || (await settings.get('openAiAPIUrl'));
            if (openAiAPIUrl) {
                requestOpts.baseApiUrl = openAiAPIUrl;
            }

            let openAiModel = message.data.openAiModel || (await settings.get('documentStoreChatModel')) || (await settings.get('openAiModel'));
            if (openAiModel) {
                requestOpts.gptModel = openAiModel;
            }

            // Set max tokens based on model
            switch (openAiModel.substring(0, 5)) {
                case 'gpt-3':
                    requestOpts.maxTokens = 3000;
                    break;
                case 'gpt-4':
                    requestOpts.maxTokens = 6500;
                    break;
                case 'gpt-5':
                default:
                    requestOpts.maxTokens = 18000;
                    break;
            }

            requestOpts.user = message.data.account;
            requestOpts.temperature = 0.4;

            requestOpts.question = message.data.question;
            requestOpts.contextChunks = message.data.contextChunks;
            requestOpts.userData = message.data.userData;

            let response = await embeddingsQuery(openAiAPIKey, requestOpts);

            // Clean and format response
            if (response?.['Message-ID']) {
                response.messageId = response?.['Message-ID'];
                delete response?.['Message-ID'];
            }
            if (response?.messageId) {
                response.messageId = [].concat(response?.messageId || []).map(value => (value || '').toString().trim().replace(/^<?/, '<').replace(/>?$/, '>'));
            }

            if (response?.answer) {
                if (typeof response.answer === 'object') {
                    response.answer = JSON.stringify(response.answer);
                } else {
                    response.answer = response.answer.toString();
                }
            }

            // Clean internal properties
            for (const key of Object.keys(response)) {
                if (/^_/.test(key)) {
                    delete response[key];
                }
            }

            return response;
        }

        case 'questionQuery': {
            let requestOpts = {
                verbose: getBoolean(process.env.EE_OPENAPI_VERBOSE)
            };

            let openAiAPIKey = message.data.openAiAPIKey || (await settings.get('openAiAPIKey'));

            if (!openAiAPIKey) {
                throw new Error(`OpenAI API key is not configured`);
            }

            let openAiAPIUrl = message.data.openAiAPIUrl || (await settings.get('openAiAPIUrl'));
            if (openAiAPIUrl) {
                requestOpts.baseApiUrl = openAiAPIUrl;
            }

            let openAiModel = message.data.openAiModel || 'gpt-3.5-turbo-instruct';
            if (openAiModel) {
                requestOpts.gptModel = openAiModel;
            }

            requestOpts.user = message.data.account;

            let response = await questionQuery(message.data.question, openAiAPIKey, requestOpts);

            // Clean internal properties
            for (const key of Object.keys(response)) {
                if (/^_/.test(key)) {
                    delete response[key];
                }
            }

            return response;
        }

        case 'generateChunkEmbeddings': {
            let requestOpts = {
                verbose: getBoolean(process.env.EE_OPENAPI_VERBOSE)
            };

            let openAiAPIKey = message.data.openAiAPIKey || (await settings.get('openAiAPIKey'));

            if (!openAiAPIKey) {
                throw new Error(`OpenAI API key is not configured`);
            }

            let openAiAPIUrl = message.data.openAiAPIUrl || (await settings.get('openAiAPIUrl'));
            if (openAiAPIUrl) {
                requestOpts.baseApiUrl = openAiAPIUrl;
            }

            requestOpts.user = message.data.account;

            const data = await getChunkEmbeddings(message.data.message, openAiAPIKey, requestOpts);

            return data;
        }

        case 'openAiListModels': {
            let requestOpts = {
                verbose: getBoolean(process.env.EE_OPENAPI_VERBOSE)
            };

            let openAiAPIKey = message.data.openAiAPIKey || (await settings.get('openAiAPIKey'));

            if (!openAiAPIKey) {
                throw new Error(`OpenAI API key is not configured`);
            }

            let openAiAPIUrl = message.data.openAiAPIUrl || (await settings.get('openAiAPIUrl'));
            if (openAiAPIUrl) {
                requestOpts.baseApiUrl = openAiAPIUrl;
            }

            requestOpts.user = message.data.account;

            const data = await openAiListModels(openAiAPIKey, requestOpts);

            return data;
        }

        case 'openAiDefaultPrompt': {
            return openAiDefaultPrompt;
        }

        case 'threads': {
            return await getThreadsInfo();
        }

        case 'worker-accounts': {
            // Get accounts assigned to a specific worker thread
            const { threadId, page = 1, pageSize = 20 } = message;
            const accounts = [];

            // Find worker by threadId and get its assigned accounts
            for (const [account, worker] of assigned) {
                if (worker.threadId === threadId) {
                    accounts.push(account);
                }
            }

            // Sort accounts for consistent ordering
            accounts.sort((a, b) => a.localeCompare(b));

            // Paginate
            const totalAccounts = accounts.length;
            const totalPages = Math.ceil(totalAccounts / pageSize) || 1;
            const currentPage = Math.min(Math.max(1, page), totalPages);
            const start = (currentPage - 1) * pageSize;
            const pagedAccounts = accounts.slice(start, start + pageSize);

            return {
                accounts: pagedAccounts,
                total: totalAccounts,
                page: currentPage,
                pageSize,
                pages: totalPages
            };
        }

        case 'rate-limit': {
            return await checkRateLimit(message.key, message.count, message.allowed, message.windowSize);
        }

        case 'unsubscribe':
            // Handle list unsubscribe
            sendWebhook(message.account, LIST_UNSUBSCRIBE_NOTIFY, message.payload).catch(err => logger.error({ msg: 'Unsubscribe webhook failed', err }));
            return;

        case 'subscribe':
            // Handle list subscribe
            sendWebhook(message.account, LIST_SUBSCRIBE_NOTIFY, message.payload).catch(err => logger.error({ msg: 'Subscribe webhook failed', err }));
            return;

        case 'new':
            // Handle new account
            unassigned.add(message.account);
            assignAccounts()
                .then(() => sendWebhook(message.account, ACCOUNT_ADDED_NOTIFY, { account: message.account }))
                .catch(err => logger.error({ msg: 'Account assignment failed', n: 3, err }));
            return;

        case 'delete':
            // Handle account deletion
            unassigned.delete(message.account); // if set
            if (assigned.has(message.account)) {
                let assignedWorker = assigned.get(message.account);
                if (workerAssigned.has(assignedWorker)) {
                    workerAssigned.get(assignedWorker).delete(message.account);
                    if (!workerAssigned.get(assignedWorker).size) {
                        // Last account on this worker
                        workerAssigned.delete(assignedWorker);
                    }
                }

                // Notify worker to clean up
                call(assignedWorker, message)
                    .then(() => logger.debug('Account cleanup completed'))
                    .catch(err => logger.error({ msg: 'Account cleanup failed', err }));
            }
            sendWebhook(message.account, ACCOUNT_DELETED_NOTIFY, { account: message.account }).catch(err =>
                logger.error({ msg: 'Account deletion webhook failed', err })
            );
            return;

        case 'runIndex': {
            return runIndex;
        }

        case 'update':
        case 'sync':
        case 'pause':
        case 'resume':
        case 'reconnect':
            // Forward to assigned worker
            if (assigned.has(message.account)) {
                let assignedWorker = assigned.get(message.account);
                call(assignedWorker, message)
                    .then(() => logger.debug('Worker command completed'))
                    .catch(err => logger.error({ msg: 'Worker command failed', err }));
            }
            return;

        case 'smtpReload':
        case 'imapProxyReload':
            {
                // Reload proxy server
                let type = message.cmd.replace(/Reload$/, '');
                let hasWorkers = workers.has(type) && workers.get(type).size;
                if (hasWorkers) {
                    // Kill existing workers
                    for (let worker of workers.get(type).values()) {
                        worker.terminate();
                    }
                } else {
                    // Spawn new worker if enabled
                    let serverEnabled = await settings.get(`${type}ServerEnabled`);
                    if (serverEnabled) {
                        await spawnWorker(type);
                    }
                }
            }
            break;

        // IMAP operations - forward to assigned worker
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
        case 'getQuota':
        case 'createMailbox':
        case 'modifyMailbox':
        case 'deleteMailbox':
        case 'submitMessage':
        case 'queueMessage':
        case 'uploadMessage':
        case 'getAttachment':
        case 'listSignatures': {
            if (!assigned.has(message.account)) {
                throw NO_ACTIVE_HANDLER_RESP_ERR;
            }

            let assignedWorker = assigned.get(message.account);

            let transferList = [];
            // Handle transferable objects
            if (['getRawMessage', 'getAttachment'].includes(message.cmd) && message.port) {
                transferList.push(message.port);
            }

            if (['submitMessage', 'queueMessage'].includes(message.cmd) && typeof message.raw === 'object') {
                transferList.push(message.raw);
            }

            return await call(assignedWorker, message, transferList);
        }

        case 'subconnections': {
            // Get submission connections
            if (!assigned.has(message.account)) {
                return [];
            }

            let assignedWorker = assigned.get(message.account);
            return await call(assignedWorker, message, []);
        }

        case 'googlePubSub': {
            // Notify all webhook workers about PubSub app
            for (let worker of workers.get('webhooks')) {
                await call(worker, message);
            }
            return true;
        }

        case 'externalNotify': {
            // External notification (e.g., Google Push)
            for (let account of message.accounts) {
                if (!assigned.has(account)) {
                    continue;
                }

                let assignedWorker = assigned.get(account);
                try {
                    await call(assignedWorker, { cmd: 'externalNotify', account, historyId: message.historyId });
                } catch (err) {
                    logger.error({ msg: 'External notification failed', cmd: 'externalNotify', account, historyId: message.historyId, err });
                }
            }
            return true;
        }
    }

    return 999;
}

// Metrics collection results
let metricsResult = {};

/**
 * Collect IMAP connection metrics from all workers
 * @returns {Promise<void>}
 */
async function collectMetrics() {
    // Reset counters
    Object.keys(metricsResult || {}).forEach(key => {
        metricsResult[key] = 0;
    });

    // Subscription state counters
    let subscriptionResults = { valid: 0, expired: 0, unset: 0, failed: 0, pending: 0 };

    // Collect from each IMAP worker
    if (workers.has('imap')) {
        let imapWorkers = workers.get('imap');
        for (let imapWorker of imapWorkers) {
            if (!availableIMAPWorkers.has(imapWorker)) {
                // Worker not ready yet
                continue;
            }

            try {
                let workerStats = await call(imapWorker, { cmd: 'countConnections' });

                // Handle connection states
                let connectionStats = workerStats?.connections || workerStats || {};
                Object.keys(connectionStats).forEach(status => {
                    if (!metricsResult[status]) {
                        metricsResult[status] = 0;
                    }
                    metricsResult[status] += Number(connectionStats[status]) || 0;
                });

                // Handle subscription states (MS Graph)
                if (workerStats?.subscriptions) {
                    Object.keys(workerStats.subscriptions).forEach(status => {
                        if (subscriptionResults[status] !== undefined) {
                            subscriptionResults[status] += Number(workerStats.subscriptions[status]) || 0;
                        }
                    });
                }
            } catch (err) {
                logger.error({ msg: 'Connection count failed', err });
            }
        }
    }

    // Add unassigned accounts to disconnected count
    metricsResult.disconnected = (Number(metricsResult.disconnected) || 0) + (unassigned ? unassigned.size : 0);

    // Update Prometheus metrics for connections
    Object.keys(metricsResult).forEach(status => {
        metrics.imapConnections.set({ status }, metricsResult[status]);
    });

    // Update Prometheus metrics for MS Graph subscriptions
    Object.keys(subscriptionResults).forEach(status => {
        metrics.outlookSubscriptions.set({ status }, subscriptionResults[status]);
    });
}

/**
 * Close all queue connections gracefully
 * @param {Function} cb - Callback when complete
 */
const closeQueues = cb => {
    let proms = [];
    if (queueEvents.notify) {
        proms.push(queueEvents.notify.close());
    }

    if (queueEvents.submit) {
        proms.push(queueEvents.submit.close());
    }

    if (queueEvents.documents) {
        proms.push(queueEvents.documents.close());
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

// Handle graceful shutdown
process.on('SIGTERM', () => {
    logger.info({ msg: 'Shutdown signal received', signal: 'SIGTERM', isClosing });
    if (isClosing) {
        return;
    }
    isClosing = true;
    closeQueues(() => {
        logger.flush(() => process.exit());
    });
});

process.on('SIGINT', () => {
    logger.info({ msg: 'Shutdown signal received', signal: 'SIGINT', isClosing });
    if (isClosing) {
        return;
    }
    isClosing = true;
    closeQueues(() => {
        logger.flush(() => process.exit());
    });
});

// START APPLICATION

/**
 * Main application startup
 * @returns {Promise<void>}
 */
const startApplication = async () => {
    // Generate unique run index
    runIndex = await redis.hincrby(`${REDIS_PREFIX}settings`, 'run', 1);

    // Process license file if provided
    if (config.licensePath) {
        try {
            let stat = await fs.stat(config.licensePath);
            if (!stat.isFile()) {
                throw new Error(`License file is not accessible`);
            }
            const licenseFile = await fs.readFile(config.licensePath, 'utf-8');
            let licenseData = await checkLicense(licenseFile);
            if (!licenseData) {
                throw new Error('Invalid license key');
            }
            logger.info({ msg: 'License loaded', license: licenseData, source: config.licensePath });

            await setLicense(licenseData, licenseFile);
        } catch (err) {
            logger.fatal({ msg: 'License verification failed', source: config.licensePath, err });
            return logger.flush(() => process.exit(13));
        }
    }

    // Process prepared license
    const preparedLicenseString = readEnvValue('EENGINE_PREPARED_LICENSE') || config.preparedLicense;
    if (preparedLicenseString) {
        try {
            let imported = await settings.importLicense(preparedLicenseString, checkLicense);
            if (imported) {
                logger.info({ msg: 'License imported', source: 'import' });
            }
        } catch (err) {
            logger.fatal({ msg: 'License import failed', source: 'import', err });
            return logger.flush(() => process.exit(13));
        }
    }

    // Load license from database
    let licenseFile = await redis.hget(`${REDIS_PREFIX}settings`, 'license');
    if (licenseFile) {
        try {
            let licenseData = await checkLicense(licenseFile);
            if (!licenseData) {
                throw new Error('Invalid license key');
            }
            licenseInfo.active = true;
            licenseInfo.details = licenseData;
            licenseInfo.type = 'EmailEngine License';
            if (!config.licensePath) {
                logger.info({ msg: 'License loaded', license: licenseData, source: 'db' });
            }
        } catch (err) {
            logger.fatal({ msg: 'Stored license verification failed', content: licenseFile, err });
        }
    }

    if (!licenseInfo.active) {
        logger.fatal({ msg: 'No active license. Running in limited mode.' });
    }

    // Check for updates
    processCheckUpgrade().catch(err => {
        logger.error({ msg: 'Update check failed', err });
    });

    // Apply prepared settings
    if (preparedSettings) {
        logger.debug({ msg: 'Applying configuration', settings: preparedSettings });

        for (let key of Object.keys(preparedSettings)) {
            await settings.set(key, preparedSettings[key]);
        }
    }

    // Initialize required settings
    let existingServiceId = await settings.get('serviceId');
    if (existingServiceId === null) {
        await settings.set('serviceId', crypto.randomBytes(16).toString('hex'));
    }

    // SMTP server settings
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

    // IMAP proxy settings
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

    // API proxy settings
    let existingEnableApiProxy = await settings.get('enableApiProxy');
    if (existingEnableApiProxy === null) {
        await settings.set('enableApiProxy', HAS_API_PROXY_SET ? API_PROXY : true);
    }

    // Service settings
    let existingServiceSecret = await settings.get('serviceSecret');
    if (existingServiceSecret === null) {
        await settings.set('serviceSecret', crypto.randomBytes(16).toString('hex'));
    }

    let existingQueueKeep = await settings.get('queueKeep');
    if (existingQueueKeep === null) {
        let QUEUE_KEEP = Math.max((readEnvValue('EENGINE_QUEUE_REMOVE_AFTER') && Number(readEnvValue('EENGINE_QUEUE_REMOVE_AFTER'))) || 0, 0);
        await settings.set('queueKeep', QUEUE_KEEP);
    }

    // Webhook settings
    let existingNotifyText = await settings.get('notifyText');
    if (existingNotifyText === null) {
        await settings.set('notifyText', true);
    }

    let existingNotifyTextSize = await settings.get('notifyTextSize');
    if (existingNotifyTextSize === null) {
        await settings.set('notifyTextSize', 2 * 1024 * 1024); // 2MB default
    }

    // Script settings
    let existingScriptEnv = await settings.get('scriptEnv');
    if (existingScriptEnv === null) {
        await settings.set('scriptEnv', {}); // empty object
    }

    // OAuth2 token access settings
    let existingEnableOAuthTokensApi = await settings.get('enableOAuthTokensApi');
    if (existingEnableOAuthTokensApi === null && ENABLE_OAUTH_TOKENS_API !== null) {
        await settings.set('enableOAuthTokensApi', ENABLE_OAUTH_TOKENS_API);
    }

    // API authentication requirement settings
    let existingDisableTokens = await settings.get('disableTokens');
    if (existingDisableTokens === null && REQUIRE_API_AUTH !== null) {
        // disableTokens is the inverse of REQUIRE_API_AUTH
        await settings.set('disableTokens', !REQUIRE_API_AUTH);
    }

    // Import prepared token
    if (preparedToken) {
        try {
            let imported = await tokens.setRawData(preparedToken);
            if (imported) {
                logger.debug({ msg: 'Token imported', token: preparedToken.id });
            } else {
                logger.debug({ msg: 'Token already exists', token: preparedToken.id });
            }
        } catch (err) {
            logger.error({ msg: 'Token import failed', token: preparedToken.id });
        }
    }

    // Import prepared password
    if (preparedPassword) {
        try {
            let authData = await settings.get('authData');

            authData = authData || {};
            authData.user = authData.user || 'admin';
            authData.password = preparedPassword;
            authData.passwordVersion = Date.now();

            await settings.set('authData', authData);
            logger.debug({ msg: 'Password imported', hash: preparedPassword });
        } catch (err) {
            logger.error({ msg: 'Password import failed', hash: preparedPassword });
        }
    }

    // Renew encryption secret if needed
    await getSecret();

    // Ensure cookie password
    let cookiePassword = await settings.get('cookiePassword');
    if (!cookiePassword) {
        cookiePassword = crypto.randomBytes(32).toString('base64');
        await settings.set('cookiePassword', cookiePassword);
    }

    // Redis reconnection is now handled by workers themselves
    // Workers will exit when Redis reconnects after disconnection,
    // and the server will automatically restart them

    // -- START WORKER THREADS

    // Start API server first for health checks
    await spawnWorker('api');

    // Small delay to allow API to start
    await new Promise(r => setTimeout(r, 100));

    // Start IMAP workers
    let workerPromises = [];
    for (let i = 0; i < config.workers.imap; i++) {
        workerPromises.push(spawnWorker('imap'));
    }
    let threadIds = await Promise.all(workerPromises);
    logger.info({ msg: 'IMAP workers started', workers: config.workers.imap, threadIds });

    // Mark that initial workers are loaded BEFORE assignment
    // This prevents race conditions where late-ready workers trigger redundant assignments
    imapInitialWorkersLoaded = true;

    // Wait a brief moment to ensure all workers have sent their 'ready' messages
    await new Promise(r => setTimeout(r, 100));

    // Assign accounts to workers after all are ready
    try {
        await assignAccounts();
    } catch (err) {
        logger.error({ msg: 'Initial account assignment failed', n: 4, err });
    }

    // Start webhook workers
    for (let i = 0; i < config.workers.webhooks; i++) {
        await spawnWorker('webhooks');
    }

    // Start submission workers
    for (let i = 0; i < config.workers.submit; i++) {
        await spawnWorker('submit');
    }

    // Start document processing worker
    await spawnWorker('documents');

    // Start SMTP proxy if enabled
    if (await settings.get('smtpServerEnabled')) {
        await spawnWorker('smtp');
    }

    // Start IMAP proxy if enabled
    if (await settings.get('imapProxyServerEnabled')) {
        await spawnWorker('imapProxy');
    }

    // Initialize and start the metrics collector after all workers are ready
    metricsCollector = new MetricsCollector({
        logger,
        cacheInterval: 10 * 1000, // 10 seconds
        workerTimeout: 500, // 500ms timeout per worker
        delayBetweenWorkers: 50, // 50ms delay between worker queries
        startTime: NOW,

        // Provide callbacks to access server state
        getWorkers: () => workers,
        callWorker: (worker, message) => call(worker, message),
        getWorkerMetadata: worker => {
            const metadata = {};

            // Add account count for IMAP workers
            if (workerAssigned.has(worker)) {
                metadata.accounts = workerAssigned.get(worker).size;
            }

            // Add health status
            metadata.healthStatus = workerHealthStatus.get(worker) || 'unknown';
            const lastHeartbeat = workerHeartbeats.get(worker);
            if (lastHeartbeat) {
                metadata.lastHeartbeat = lastHeartbeat;
                metadata.timeSinceHeartbeat = Date.now() - lastHeartbeat;
            }

            // Add worker metadata
            let workerMeta = workersMeta.has(worker) ? workersMeta.get(worker) : {};
            for (let key of Object.keys(workerMeta)) {
                metadata[key] = workerMeta[key];
            }

            return metadata;
        }
    });

    // Start the background collection
    metricsCollector.start();

    logger.info({ msg: 'Background metrics collector initialized and started' });
};

// Start the application
startApplication()
    .then(bounceClassifier.initialize)
    .then(() => {
        // Start periodic metric collection
        setInterval(() => {
            collectMetrics().catch(err => logger.error({ msg: 'Metrics collection failed', err }));
        }, 1000).unref();

        // Schedule periodic checks
        licenseCheckTimer = setTimeout(checkActiveLicense, LICENSE_CHECK_TIMEOUT);
        licenseCheckTimer.unref();

        upgradeCheckTimer = setTimeout(checkUpgrade, UPGRADE_CHECK_TIMEOUT);
        upgradeCheckTimer.unref();

        redisPingTimer = setTimeout(checkRedisPing, REDIS_PING_TIMEOUT);
        redisPingTimer.unref();

        // Start worker health monitoring
        startHealthMonitoring();

        // Initialize queue event listeners
        queueEvents.notify = new QueueEvents('notify', Object.assign({}, queueConf));
        queueEvents.submit = new QueueEvents('submit', Object.assign({}, queueConf));
        queueEvents.documents = new QueueEvents('documents', Object.assign({}, queueConf));
    })
    .catch(err => {
        logger.fatal({ msg: 'Application startup failed', err });
        logger.flush(() => process.exit(1));
    });
