'use strict';

// What the stats endpoint and the dashboard say about the cluster. Pure: built from the instance
// records the coordinator last read (lib/cluster/store.js listLive()).

/**
 * Connection counts summed over every live instance, and a summary of each instance. Addresses are
 * left out: they are only for the instances themselves
 * @param {Object[]} members - Live instance records
 * @param {string} selfId - This instance, whose counts are taken fresh from `localConnections`
 * @param {Object} localConnections - This instance's counts by connection state
 * @returns {{ connections: Object, instances: Object[] }}
 */
function summarizeFleet(members, selfId, localConnections) {
    const connections = {};
    const add = counts => {
        for (const [state, count] of Object.entries(counts || {})) {
            const value = Number(count) || 0;
            connections[state] = (connections[state] || 0) + value;
        }
    };

    let sawSelf = false;
    const instances = [];
    for (const member of [...members].sort((a, b) => (a.id < b.id ? -1 : 1))) {
        const self = member.id === selfId;
        sawSelf = sawSelf || self;
        const counts = self ? localConnections : member.connections;
        add(counts);
        instances.push({
            id: member.id,
            self,
            version: member.version || null,
            ready: !!member.ready,
            accounts: Number(member.owned) || 0,
            started: member.started ? new Date(member.started).toISOString() : null,
            lastHeartbeat: member.heartbeat ? new Date(member.heartbeat).toISOString() : null,
            connections: Object.assign({}, counts || {})
        });
    }

    // Not registered (yet, or any more): its own counts still describe what it serves
    if (!sawSelf) {
        add(localConnections);
    }

    return { connections, instances };
}

/**
 * Rows of the Instances card on the Workers page: one per instance, this one first
 * @param {Object[]} instances - summarizeFleet().instances, as the clusterInstances command returns it
 * @returns {Object[]}
 */
function instanceRows(instances) {
    return (Array.isArray(instances) ? instances : [])
        .map(instance =>
            Object.assign({}, instance, {
                statusVariant: instance.ready ? 'success' : 'warning',
                statusLabel: instance.ready ? 'Serving' : 'Not taking accounts',
                connected: Number((instance.connections || {}).connected) || 0,
                heartbeatTime: instance.lastHeartbeat || null
            })
        )
        .sort((a, b) => {
            if (a.self !== b.self) {
                return a.self ? -1 : 1;
            }
            return a.id < b.id ? -1 : 1;
        });
}

/**
 * The Instances card's part of the Workers page view: `instances` only when several instances share
 * the Redis (a lone instance has nothing to compare), and the id of the one serving the page
 * @param {Function} call - RPC to the main thread
 * @param {Object} logger
 * @returns {Promise<{ instances: Object[]|false, selfInstance: string|null }>}
 */
async function loadFleetView(call, logger) {
    let rows = [];
    try {
        rows = instanceRows(await call({ cmd: 'clusterInstances' }));
    } catch (err) {
        logger.warn({ msg: 'Failed to list cluster instances', err });
    }
    return {
        instances: rows.length > 1 ? rows : false,
        selfInstance: (rows.find(row => row.self) || {}).id || null
    };
}

module.exports = { summarizeFleet, instanceRows, loadFleetView };
