'use strict';

// The Prometheus metrics the main thread keeps, and the client library behind them. server.js
// creates them once; test/metrics-test.js pins their names, types, help texts and labels, which are
// what dashboards and alerts are written against.

const promClient = require('@prometheus-io/client');

/**
 * Prometheus metrics definitions for monitoring. Each call registers them on the default registry,
 * so it is called once per process.
 *
 * @returns {Object}
 */
function createMetrics() {
    return {
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

        // Labelled by route, not by status: the counter above already splits by status, and a latency
        // series per status code would multiply the route count for little an operator can act on
        apiCallDuration: new promClient.Histogram({
            name: 'api_call_duration_seconds',
            help: 'Duration of API calls, from receiving the request to sending the response',
            labelNames: ['method', 'route'],
            buckets: [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60]
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

        outlookMissedRecovery: new promClient.Counter({
            name: 'outlook_missed_recovery',
            help: 'MS Graph missed-notification recovery passes, by what asked for them and whether they found unannounced messages',
            labelNames: ['reason', 'outcome']
        }),

        outlookMissedRecoveredMessages: new promClient.Counter({
            name: 'outlook_missed_recovered_messages',
            help: 'New messages announced by MS Graph missed-notification recovery instead of by a change notification',
            labelNames: ['reason']
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

        aiRequests: new promClient.Counter({
            name: 'ai_requests',
            help: 'AI summary requests',
            labelNames: ['model', 'status']
        }),

        aiTokens: new promClient.Counter({
            name: 'ai_tokens',
            help: 'Tokens billed for AI summary requests',
            labelNames: ['model', 'type']
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

        queueFailed: new promClient.Gauge({
            name: 'queue_failed_jobs',
            help: 'Failed jobs a queue still retains (deliveries that were given up on)',
            labelNames: ['queue']
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

        threadEventLoopDelayMax: new promClient.Gauge({
            name: 'thread_event_loop_delay_max_seconds',
            help: 'Longest event loop delay of a thread over the last collection window (15s)',
            labelNames: ['type', 'thread']
        }),

        threadEventLoopDelayP99: new promClient.Gauge({
            name: 'thread_event_loop_delay_p99_seconds',
            help: '99th percentile event loop delay of a thread over the last collection window (15s)',
            labelNames: ['type', 'thread']
        }),

        threadHeapUsed: new promClient.Gauge({
            name: 'thread_heap_used_bytes',
            help: 'V8 heap in use by a thread, as of the last collection (15s)',
            labelNames: ['type', 'thread']
        }),

        threadHeapTotal: new promClient.Gauge({
            name: 'thread_heap_total_bytes',
            help: 'V8 heap allocated by a thread, as of the last collection (15s)',
            labelNames: ['type', 'thread']
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
}

/**
 * Starts the default Node.js process metrics and creates the EmailEngine ones.
 *
 * @returns {Object} The metrics, as createMetrics() returns them
 */
function setupMetrics() {
    promClient.collectDefaultMetrics({});
    return createMetrics();
}

/**
 * The current IMAP connection counts by status, read through the gauge's public get().
 *
 * @param {Object} gauge metrics.imapConnections
 * @returns {Promise<Object>} { [status]: count }
 */
async function connectionCounts(gauge) {
    let connections = {};
    for (let { labels, value } of (await gauge.get()).values) {
        if (labels && labels.status !== undefined) {
            connections[labels.status] = value;
        }
    }
    return connections;
}

module.exports = { promClient, setupMetrics, connectionCounts };
