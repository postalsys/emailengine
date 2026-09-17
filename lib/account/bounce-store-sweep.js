'use strict';

// One-time sweep of the store behind the retired `bounces` response field: the per-account hash
// `iar:b:<account>` every detected bounce used to append to, which nothing trimmed and nothing reads
// or writes any more. The accounts are walked rather than the keyspace scanned, because the store
// only ever existed for an account in the set (deleting the account unlinked it). A completion key
// makes the sweep run once; delete SWEEP_KEY and restart to re-arm it.

const { redis } = require('../db');
const logger = require('../logger');
const { REDIS_PREFIX } = require('../consts');

// Marks the sweep as done for this Redis. Value is the ISO time of the run.
const SWEEP_KEY = `${REDIS_PREFIX}migration:bounceStoreRemoved`;

// Accounts unlinked per pipeline, matching the chunking of the auth-failure backfill
const CHUNK_SIZE = 500;

/**
 * Deletes every account's bounce store, once.
 *
 * @param {Object} [opts] - Overrides for tests; the defaults are the shared clients
 * @param {Object} [opts.redis] - ioredis client
 * @param {Object} [opts.logger] - Logger
 * @returns {Promise<Number>} How many stores were deleted
 */
async function sweepBounceStore(opts = {}) {
    const { redis: client = redis, logger: log = logger } = opts;

    // The common case is an instance that has already swept, and this is the whole cost for it
    if (await client.exists(SWEEP_KEY)) {
        return 0;
    }

    const accounts = await client.smembers(`${REDIS_PREFIX}ia:accounts`);

    // Counted from the replies: UNLINK answers 1 only for a key that existed. A failed reply throws
    // before the completion key is written, so the next startup runs the sweep again
    let deleted = 0;
    for (let i = 0; i < accounts.length; i += CHUNK_SIZE) {
        const req = client.pipeline();
        for (const account of accounts.slice(i, i + CHUNK_SIZE)) {
            req.unlink(`${REDIS_PREFIX}iar:b:${account}`);
        }
        for (const [err, count] of await req.exec()) {
            if (err) {
                throw err;
            }
            deleted += count ? 1 : 0;
        }
    }

    // Written last, so a crash mid-sweep re-enters and finishes it
    await client.set(SWEEP_KEY, new Date().toISOString());

    if (deleted) {
        log.info({ msg: 'Deleted the bounce store of earlier versions', accounts: deleted });
    }

    return deleted;
}

module.exports = { sweepBounceStore, SWEEP_KEY };
