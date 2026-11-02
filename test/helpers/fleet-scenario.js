'use strict';

// What the multi-instance tier (test/multi/helpers.js) and the load and chaos runners
// (test/multi/load/workload.js) both need around a fleet of EmailEngine processes: how an account is
// registered, who owns what, how long IDLE takes to settle, and an instance's Redis behind a proxy
// that can fail its calls (redis-fault-gate.js).

const { REDIS_URL } = require('./instance-fleet');
const { startLatencyProxy } = require('./latency-proxy');

// ImapFlow starts IDLE after 15 seconds of quiet, and only an idling session hears about a new
// message at once. A message injected sooner is still found, just at the next command
const IDLE_SETTLE = 17000;

/**
 * The POST /v1/account payload of a fleet account
 * @param {string} account
 * @param {Object} imap - IMAP settings from the farm
 * @param {Object} [opts]
 * @param {string} [opts.name]
 * @param {number} [opts.smtpPort] - A capture server (capture-smtp.js), which speaks no TLS
 * @returns {Object}
 */
function accountPayload(account, imap, { name = account, smtpPort } = {}) {
    const payload = { account, name, email: `${account}@example.com`, imap };
    if (smtpPort) {
        payload.smtp = { host: '127.0.0.1', port: smtpPort, secure: false, requireTLS: false, auth: { user: account, pass: 'pass' } };
    }
    return payload;
}

/**
 * The instance id recorded as each account's owner
 * @param {Object} redis - A client of the fleet database
 * @param {string[]} accounts
 * @returns {Promise<Map<string, string|null>>}
 */
async function readOwners(redis, accounts) {
    const values = accounts.length ? await redis.mget(accounts.map(account => `cluster:own:${account}`)) : [];
    return new Map(accounts.map((account, i) => [account, values[i]]));
}

/**
 * Points an instance (not started yet) at the fleet Redis through its own proxy, one that can fail
 * chosen commands (proxy.setFaults())
 * @param {Object} instance - A FleetInstance
 * @returns {Promise<Object>} The proxy
 */
async function redisProxyFor(instance) {
    const target = new URL(REDIS_URL);
    const proxy = await startLatencyProxy({ port: Number(target.port) || 6379, resp: true });
    target.port = String(proxy.port);
    instance.redisUrl = target.toString();
    return proxy;
}

module.exports = { IDLE_SETTLE, accountPayload, readOwners, redisProxyFor };
