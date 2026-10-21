'use strict';

// Dashboard warnings about how Redis manages its memory, derived from INFO. Pure, so the decisions
// can be tested without a Redis to put into each state.
//
// EmailEngine uses Redis as a database, not a cache. Any eviction silently drops sync state, which
// makes already-synced messages look new and triggers duplicate webhooks. With the required
// noeviction policy the failure is the other one: once used memory reaches maxmemory, Redis refuses
// every write with an OOM reply, and sync, delivery and webhooks stop together. Neither eviction
// warning fires for that, so a separate one says how close to the limit Redis is.

const { humanSize } = require('./queue-browser/format');

// Share of maxmemory at which the dashboard starts warning, and at which the warning turns red
const MEMORY_WARNING_RATIO = 0.8;
const MEMORY_DANGER_RATIO = 0.95;

/**
 * Warning about eviction, either already happened or allowed by the configured policy
 * @param {Object} redisInfo - Parsed INFO output
 * @returns {Object|null} Warning entry, or null
 */
function evictionWarning(redisInfo) {
    let maxmemoryPolicy = typeof redisInfo.maxmemory_policy === 'string' ? redisInfo.maxmemory_policy : null;
    let maxmemory = Number(redisInfo.maxmemory) || 0;
    let evictedKeys = Number(redisInfo.evicted_keys) || 0;

    if (evictedKeys > 0) {
        // Definitive: Redis has already evicted keys
        return {
            key: 'evicted-keys',
            color: 'danger',
            title: 'Redis eviction detected',
            details: [
                `Redis has evicted ${evictedKeys.toLocaleString('en-US')} key${evictedKeys === 1 ? '' : 's'} after reaching its memory limit.`,
                'EmailEngine uses Redis as its primary database, not a cache. Evicted keys cause already-synced messages to be reprocessed - generating duplicate webhooks - and can lead to data loss.',
                'Set the Redis "maxmemory-policy" to "noeviction" and provision enough memory so Redis never reaches its limit.'
            ]
        };
    }

    if (maxmemoryPolicy && maxmemoryPolicy !== 'noeviction') {
        // Latent risk: an eviction policy is configured but nothing has been evicted yet
        return {
            key: 'maxmemory-policy',
            color: maxmemory > 0 ? 'danger' : 'warning',
            title: 'Unsafe Redis eviction policy',
            details: [
                `The Redis "maxmemory-policy" is set to "${maxmemoryPolicy}", but EmailEngine requires "noeviction".`,
                'With any other policy, Redis can delete EmailEngine sync state under memory pressure, causing already-synced messages to be reprocessed - generating duplicate webhooks - and possible data loss.',
                'Set "maxmemory-policy noeviction" and make sure Redis has enough memory for your workload.'
            ]
        };
    }

    return null;
}

/**
 * Warning about used memory approaching maxmemory. Without a maxmemory there is no limit for
 * Redis to refuse writes at, so nothing is reported
 * @param {Object} redisInfo - Parsed INFO output
 * @returns {Object|null} Warning entry, or null
 */
function memoryLimitWarning(redisInfo) {
    let maxmemory = Number(redisInfo.maxmemory) || 0;
    let usedMemory = Number(redisInfo.used_memory) || 0;
    if (maxmemory <= 0 || usedMemory <= 0) {
        return null;
    }

    let ratio = usedMemory / maxmemory;
    if (ratio < MEMORY_WARNING_RATIO) {
        return null;
    }

    return {
        key: 'memory-limit',
        color: ratio >= MEMORY_DANGER_RATIO ? 'danger' : 'warning',
        title: 'Redis is close to its memory limit',
        details: [
            `Redis is using ${humanSize(usedMemory)} of its ${humanSize(maxmemory)} "maxmemory" limit (${Math.min(Math.round(ratio * 100), 100)}%).`,
            'Once the limit is reached Redis refuses every write, and syncing, sending and webhook delivery stop until memory is freed.',
            'Raise "maxmemory", or find what is growing: a webhook backlog for a receiver that is down, account logs, or failed queue entries.'
        ]
    };
}

/**
 * All memory warnings for the dashboard, in display order
 * @param {Object} redisInfo - Parsed INFO output
 * @returns {Object[]} Warning entries
 */
function redisMemoryWarnings(redisInfo) {
    redisInfo = redisInfo || {};
    return [evictionWarning(redisInfo), memoryLimitWarning(redisInfo)].filter(Boolean);
}

module.exports = { redisMemoryWarnings };
