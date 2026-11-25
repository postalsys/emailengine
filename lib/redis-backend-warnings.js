'use strict';

// Dashboard warnings about the kind of Redis server EmailEngine is connected to, derived from INFO.
// Pure, so the decisions can be tested without a Redis in each configuration.
//
// Redis Cluster is refused outright: EmailEngine's queues and Lua scripts touch keys in different hash
// slots, which a cluster rejects with CROSSSLOT, and a cluster refuses SELECT for any database but 0.
// That also covers Amazon MemoryDB and ElastiCache with cluster mode or the durability option, which
// always run as a cluster.
//
// Amazon ElastiCache without cluster mode works, but a node that has no replica does not reload its
// snapshot when AWS replaces it: the new node starts empty and every account is gone until someone
// restores a backup by hand. A primary with a connected replica fails over instead and keeps its data,
// so only the replica-less setup is flagged. Multi-AZ failover itself is not visible in INFO.

/**
 * Warning about a Redis Cluster backend
 * @param {Object} redisInfo - Parsed INFO output
 * @returns {Object|null} Warning entry, or null
 */
function clusterWarning(redisInfo) {
    if (!(Number(redisInfo.cluster_enabled) > 0)) {
        return null;
    }

    return {
        key: 'cluster',
        color: 'danger',
        title: 'Redis compatibility warning',
        details: ['EmailEngine is incompatible with a Redis Cluster setup.', 'Please switch to a standard Redis primary instance.']
    };
}

/**
 * Warning about an Amazon ElastiCache primary that has no replica to fail over to
 * @param {Object} redisInfo - Parsed INFO output
 * @returns {Object|null} Warning entry, or null
 */
function elastiCacheWarning(redisInfo) {
    if (!/Amazon ElastiCache/i.test(redisInfo.os || '') || Number(redisInfo.cluster_enabled) > 0) {
        // not ElastiCache, or a cluster, which clusterWarning() already refuses
        return null;
    }

    if (redisInfo.role !== 'master' || Number(redisInfo.connected_slaves) > 0) {
        return null;
    }

    return {
        key: 'elasticache',
        color: 'danger',
        title: 'Amazon ElastiCache without a replica',
        details: [
            'This ElastiCache node has no replica. When AWS replaces a node without one, the new node starts empty, and EmailEngine loses every account until a backup is restored by hand.',
            'Add at least one replica and enable Multi-AZ automatic failover, or switch to a standard Redis instance with persistence enabled.'
        ]
    };
}

/**
 * All backend warnings for the dashboard, in display order
 * @param {Object} redisInfo - Parsed INFO output
 * @returns {Object[]} Warning entries
 */
function redisBackendWarnings(redisInfo) {
    redisInfo = redisInfo || {};
    return [elastiCacheWarning(redisInfo), clusterWarning(redisInfo)].filter(Boolean);
}

module.exports = { redisBackendWarnings };
