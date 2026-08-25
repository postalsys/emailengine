'use strict';

// Drives BaseClient's auth-failure safety net, which switches an account off after a run of
// authentication failures older than MAX_IMAP_AUTH_FAILURE_TIME.
//
// Shared across tiers: the unit tier exercises the writer's own decisions, and the integration tier
// needs the same park set up before it reads it back over HTTP. The fake receiver below is a
// standing contract with BaseClient's collaborator set, and two hand-maintained copies of it would
// silently drift the next time setErrorState()/disableAfterAuthFailures() grows a dependency -
// which is the whole reason it inherits the prototype rather than listing the methods under test.

const { BaseClient } = require('../../lib/email-client/base-client');
const { REDIS_PREFIX, DEFAULT_MAX_IMAP_AUTH_FAILURE_TIME } = require('../../lib/consts');

const noopLogger = { trace() {}, debug() {}, info() {}, warn() {}, error() {}, fatal() {}, child: () => noopLogger };

const accountKeyFor = account => `${REDIS_PREFIX}iad:${account}`;

/**
 * A BaseClient stand-in bound to one account hash. setErrorState() reaches `redis`,
 * `getAccountKey()`, `setStateVal()`, `logger`, `account`, `state` and `close()`; everything else it
 * needs comes from the real prototype.
 *
 * @param {Object} opts
 * @param {Object} opts.redis - ioredis client
 * @param {String} opts.account - Account id
 * @param {Object} [opts.logger] - Logger, silent by default
 * @returns {Object} The receiver, carrying a `closeCalls` counter
 */
function createErrorStateClient({ redis, account, logger }) {
    return Object.assign(Object.create(BaseClient.prototype), {
        account,
        redis,
        logger: logger || noopLogger,
        state: 'connected',
        closeCalls: 0,
        getAccountKey: () => accountKeyFor(account),
        setStateVal: async () => {},
        close() {
            this.closeCalls++;
        }
    });
}

/**
 * Ages an account's error counters past the disable threshold, so the next matching failure trips
 * the safety net instead of the test waiting three days for it.
 *
 * @param {Object} redis - ioredis client
 * @param {String} account - Account id
 * @param {Object} [opts]
 * @param {String} [opts.code] - serverResponseCode the run is attributed to
 * @param {Number} [opts.count] - Failures counted so far
 * @returns {Promise<void>}
 */
async function seedExpiredErrorRun(redis, account, { code = 'AUTH', count = 5 } = {}) {
    const accountKey = accountKeyFor(account);
    await redis.hset(accountKey, {
        lastErrorState: JSON.stringify({ serverResponseCode: code }),
        'lastError:errorCount': String(count),
        'lastError:first': new Date(Date.now() - DEFAULT_MAX_IMAP_AUTH_FAILURE_TIME - 3600 * 1000).toISOString()
    });
}

// close() is scheduled with setImmediate, so a caller asserting on it has to yield first
const drainSetImmediate = () => new Promise(resolve => setImmediate(resolve));

module.exports = { createErrorStateClient, seedExpiredErrorRun, accountKeyFor, drainSetImmediate, noopLogger };
