'use strict';

// Shared setup for the multi-instance tier (test/multi/*-test.js). Not a test file: the runner only
// executes *-test.js.

const Redis = require('ioredis');
const { startFleet, REDIS_URL } = require('../helpers/instance-fleet');
const { startFarm } = require('../helpers/imapkit-farm');
const { startLedger } = require('../helpers/webhook-ledger');
const { IDLE_SETTLE, accountPayload, readOwners } = require('../helpers/fleet-scenario');

const assert = require('node:assert').strict;

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

// One owner opens one session per account against the farm
const SESSIONS_PER_OWNER = 1;

/** Polls `check` until it returns something truthy, returning that value */
async function waitUntil(check, { timeout = 60000, interval = 250, label = 'condition' } = {}) {
    const deadline = Date.now() + timeout;
    let lastError;
    while (Date.now() < deadline) {
        try {
            const value = await check();
            if (value) {
                return value;
            }
        } catch (err) {
            lastError = err;
        }
        await sleep(interval);
    }
    throw new Error(`Timed out after ${timeout}ms waiting for ${label}${lastError ? `: ${lastError.message}` : ''}`);
}

function accountIds(count, prefix = 'acc') {
    return Array.from({ length: count }, (_, i) => `${prefix}${String(i).padStart(4, '0')}`);
}

/**
 * Starts a farm, a ledger and a fleet, and registers the accounts through instance 0
 * @param {Object} opts
 * @param {number} opts.instances
 * @param {number} opts.accounts
 * @param {number} [opts.servers] - ImapKit servers, one per account by default
 * @param {Object} [opts.fleet] - Extra startFleet() options
 * @returns {Promise<Object>} `{ fleet, farm, ledger, accounts, redis, stop() }`
 */
async function startScenario(opts) {
    const accounts = accountIds(opts.accounts, opts.prefix);
    const farm = await startFarm({ accounts, servers: opts.servers });
    const ledger = await startLedger();
    const fleet = await startFleet(Object.assign({ size: opts.instances, webhookUrl: ledger.url }, opts.fleet));
    const redis = new Redis(REDIS_URL);

    const scenario = {
        fleet,
        farm,
        ledger,
        accounts,
        redis,

        async createAccounts(list = accounts) {
            const via = fleet.instances[0];
            for (const account of list) {
                const payload = accountPayload(account, farm.imapSettings(account), { name: `Fleet ${account}`, smtpPort: opts.smtpPort });
                const res = await via.request('POST', '/v1/account', payload);
                if (res.status !== 200) {
                    throw new Error(`Creating ${account} failed with ${res.status}: ${JSON.stringify(res.body)}`);
                }
            }
        },

        /** Waits until every listed account reports connected through `via` */
        async waitConnected(list = accounts, { via, timeout = 120000 } = {}) {
            await waitUntil(
                async () => {
                    const target = via || fleet.pick(0);
                    for (const account of list) {
                        const res = await target.request('GET', `/v1/account/${account}`);
                        if (res.status !== 200 || res.body.state !== 'connected') {
                            return false;
                        }
                    }
                    return true;
                },
                { timeout, label: `${list.length} accounts to connect` }
            );
        },

        /** Instance id currently recorded as each account's owner */
        async owners(list = accounts) {
            return await readOwners(redis, list);
        },

        /** Accounts with more IMAP sessions on the farm than one owner opens */
        overConnected(list = accounts, perOwner = SESSIONS_PER_OWNER) {
            return list.map(account => ({ account, sessions: farm.sessionsFor(account).length })).filter(entry => entry.sessions > perOwner);
        },

        /** Injects one ledger-tagged message per account, returning the injections */
        injectAll(list = accounts, label) {
            return list.map(account => {
                const token = ledger.newToken();
                const { injectedAt } = farm.inject(account, { subject: ledger.subjectFor(token, label) });
                return { account, token, injectedAt };
            });
        },

        async stop() {
            await fleet.stopAll().catch(() => false);
            await farm.stop().catch(() => false);
            await ledger.stop().catch(() => false);
            await redis.quit().catch(() => false);
        }
    };

    await scenario.createAccounts();

    return scenario;
}

/** Waits for every injection to be delivered, then asserts none was delivered twice */
async function assertDeliveredOnce(scenario, injections, timeout = 60000) {
    await scenario.ledger.waitFor(() => scenario.ledger.reconcile(injections).missing.length === 0, timeout, `${injections.length} messageNew webhooks`);
    // Duplicates arrive after the first copy; give a second owner time to show itself
    await sleep(3000);
    const { duplicates, missing } = scenario.ledger.reconcile(injections);
    assert.deepEqual(missing, [], 'every injected message is delivered');
    assert.deepEqual(duplicates, [], 'no message is delivered twice');
}

module.exports = { startScenario, waitUntil, sleep, accountIds, assertDeliveredOnce, IDLE_SETTLE, SESSIONS_PER_OWNER };
