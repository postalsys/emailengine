'use strict';

// Redis operations of the instance cluster: membership records, account ownership and the shared
// signing secret. Every function takes the ioredis client (lib/db.js, which defines the cluster
// scripts) so the coordinator and the tests drive the same code.

const crypto = require('crypto');
const { clusterKeys } = require('./keys');

// Owner records are read and claimed in batches of this many accounts per round trip
const BATCH_SIZE = 500;

// Fields of an instance record that are numbers
const NUMERIC_FIELDS = new Set(['started', 'runIndex', 'pid', 'owned', 'protocol', 'heartbeat']);

/** Flattens a record object into the field, value list the scripts take */
function recordArgs(record) {
    const args = [];
    for (const [key, value] of Object.entries(record || {})) {
        if (value === undefined || value === null) {
            continue;
        }
        args.push(key, typeof value === 'object' ? JSON.stringify(value) : String(value));
    }
    return args;
}

function parseRecord(id, hash) {
    if (!hash || !hash.token) {
        return null;
    }
    const record = { id };
    for (const [key, value] of Object.entries(hash)) {
        if (key === 'token') {
            continue;
        }
        if (NUMERIC_FIELDS.has(key)) {
            record[key] = Number(value) || 0;
        } else if (key === 'ready' || key === 'starting') {
            record[key] = value === '1';
        } else if (key === 'connections') {
            try {
                record.connections = JSON.parse(value);
            } catch (err) {
                record.connections = null;
            }
        } else {
            record[key] = value;
        }
    }
    return record;
}

/**
 * Registers a run of an instance
 * @returns {Promise<boolean>} false when a live run of another process holds the id
 */
async function register(redis, { id, token, ttl, record }) {
    const result = await redis.clusterRegister(clusterKeys.instance(id), clusterKeys.instances, id, token, ttl, ...recordArgs(record));
    return result === 1;
}

/**
 * Renews the heartbeat of a run and updates its record
 * @returns {Promise<boolean>} false when the record is gone or belongs to another run
 */
async function renew(redis, { id, token, ttl, record }) {
    const result = await redis.clusterRenew(clusterKeys.instance(id), clusterKeys.instances, id, token, ttl, ...recordArgs(record));
    return result === 1;
}

/** Removes the record of a run that is shutting down */
async function leave(redis, { id, token }) {
    return (await redis.clusterLeave(clusterKeys.instance(id), clusterKeys.instances, id, token)) === 1;
}

/**
 * Every live instance, keyed by id. Ids whose record expired are pruned from the member set
 * @returns {Promise<Map<string, Object>>}
 */
async function listLive(redis) {
    const ids = await redis.smembers(clusterKeys.instances);
    const live = new Map();
    if (!ids.length) {
        return live;
    }

    const pipeline = redis.pipeline();
    for (const id of ids) {
        pipeline.hgetall(clusterKeys.instance(id));
    }
    const results = await pipeline.exec();

    const expired = [];
    ids.forEach((id, i) => {
        const [err, hash] = results[i] || [];
        if (err) {
            throw err;
        }
        const record = parseRecord(id, hash);
        if (record) {
            live.set(id, record);
        } else {
            expired.push(id);
        }
    });

    if (expired.length) {
        const prune = redis.pipeline();
        for (const id of expired) {
            prune.clusterPrune(clusterKeys.instance(id), clusterKeys.instances, id);
        }
        await prune.exec();
    }

    return live;
}

/**
 * Recorded owners of a list of accounts
 * @returns {Promise<Map<string, string|null>>}
 */
async function readOwners(redis, accounts) {
    const batches = [];
    for (let i = 0; i < accounts.length; i += BATCH_SIZE) {
        batches.push(accounts.slice(i, i + BATCH_SIZE));
    }
    // Sent together, so a large account list costs about one round trip rather than one per batch
    const results = await Promise.all(batches.map(batch => redis.mget(batch.map(account => clusterKeys.owner(account)))));
    const owners = new Map();
    batches.forEach((batch, i) => batch.forEach((account, j) => owners.set(account, results[i][j] || null)));
    return owners;
}

/** The recorded owner of one account, null when it has none */
async function readOwner(redis, account) {
    return (await redis.get(clusterKeys.owner(account))) || null;
}

/**
 * Claims accounts for an instance
 * @param {Object} redis
 * @param {Array<{account: string, expected: string}>} claims
 * @param {string} owner - The claiming instance
 * @param {number} ownerRun - Its run index
 * @returns {Promise<{claimed: string[], lost: Array<{account: string, owner: string}>, gone: string[]}>}
 *   claimed: now owned; lost: another instance changed the record first; gone: the account was deleted
 */
async function claim(redis, claims, owner, ownerRun) {
    const outcome = { claimed: [], lost: [], gone: [] };
    for (let i = 0; i < claims.length; i += BATCH_SIZE) {
        const batch = claims.slice(i, i + BATCH_SIZE);
        const pipeline = redis.pipeline();
        for (const { account, expected } of batch) {
            pipeline.clusterClaim(
                clusterKeys.owner(account),
                clusterKeys.account(account),
                clusterKeys.instance(expected || owner),
                expected || '',
                owner,
                String(ownerRun || 0)
            );
        }
        const results = await pipeline.exec();
        batch.forEach(({ account }, j) => {
            const [err, reply] = results[j] || [];
            if (err) {
                // One failed claim is retried by the next pass; it must not fail the others
                outcome.lost.push({ account, owner: null, err });
                return;
            }
            const [status, current] = reply || [];
            if (status === 1) {
                outcome.claimed.push(account);
            } else if (status === -1) {
                outcome.gone.push(account);
            } else {
                outcome.lost.push({ account, owner: current || null });
            }
        });
    }
    return outcome;
}

/**
 * Releases accounts an instance owns
 * @returns {Promise<string[]>} The accounts that were released (the others had another owner already)
 */
async function release(redis, accounts, owner) {
    const released = [];
    for (let i = 0; i < accounts.length; i += BATCH_SIZE) {
        const batch = accounts.slice(i, i + BATCH_SIZE);
        const pipeline = redis.pipeline();
        for (const account of batch) {
            pipeline.clusterRelease(clusterKeys.owner(account), owner);
        }
        const results = await pipeline.exec();
        batch.forEach((account, j) => {
            const [err, reply] = results[j] || [];
            if (!err && reply === 1) {
                released.push(account);
            }
        });
    }
    return released;
}

/**
 * The key cluster calls are signed with, created by whichever instance asks first
 * @returns {Promise<Buffer>}
 */
async function ensureSecret(redis) {
    let value = await redis.get(clusterKeys.secret);
    if (!value) {
        await redis.set(clusterKeys.secret, crypto.randomBytes(32).toString('hex'), 'NX');
        value = await redis.get(clusterKeys.secret);
    }
    return Buffer.from(value, 'hex');
}

module.exports = { register, renew, leave, listLive, readOwners, readOwner, claim, release, ensureSecret, parseRecord, recordArgs };
