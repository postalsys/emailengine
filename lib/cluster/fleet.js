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

module.exports = { summarizeFleet };
