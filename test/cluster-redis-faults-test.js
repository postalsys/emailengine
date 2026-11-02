'use strict';

// Two cluster coordinators whose Redis calls fail at random, each through its own fault proxy
// (test/helpers/redis-fault-gate.js). A cut Redis connection never fails a call (ioredis sends it
// again), so error replies are how Redis trouble reaches the ownership code: renewals, claims,
// releases, owner reads and the fence recovery all meet them here, in every combination.
//
// The rule checked throughout is the one the design rests on: an account may stay connected on two
// members for a moment while one of them is fenced, but never on two that both hold a valid lease,
// since the lease is what lets an announcement out. Once Redis behaves again, every account is
// served by exactly one member and recorded as owned by it.

const test = require('node:test');
const assert = require('node:assert').strict;

// Set before anything opens a connection, so these keys cannot collide with another suite's
process.env.EENGINE_REDIS_PREFIX = 'test_cluster_faults';

const { redis } = require('../lib/db');
const { REDIS_PREFIX } = require('../lib/consts');
const { clusterKeys } = require('../lib/cluster/keys');
const { ClusterCoordinator } = require('../lib/cluster/coordinator');
const { startLatencyProxy } = require('./helpers/latency-proxy');
// Seeded, so a failing run can be replayed with the same faults (EE_FAULT_SEED)
const { createRandom } = require('./helpers/property');
const registerRedisTeardown = require('./helpers/redis-teardown');

const TTL = 2000;
const ACCOUNTS = 30;
const logger = { info() {}, warn() {}, error() {}, debug() {}, trace() {} };
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

const cleanups = [];

async function cleanup() {
    const keys = await redis.keys(`${REDIS_PREFIX}*`);
    if (keys.length) {
        await redis.del(keys);
    }
}

registerRedisTeardown(redis, async () => {
    for (const fn of cleanups.reverse()) {
        await fn().catch(() => false);
    }
    await cleanup();
});

/** A client of the test Redis that goes through `proxy`, with the scripts lib/db.js defines */
function clientThrough(proxy) {
    const client = redis.duplicate({ host: '127.0.0.1', port: proxy.port });
    for (const [name, script] of Object.entries(redis.scriptsSet)) {
        client.defineCommand(name, { numberOfKeys: script.numberOfKeys, lua: script.lua });
    }
    return client;
}

async function seedAccounts() {
    const list = Array.from({ length: ACCOUNTS }, (_, i) => `acc${i}`);
    for (const account of list) {
        await redis.hset(clusterKeys.account(account), { account, state: 'init' });
    }
    await redis.sadd(clusterKeys.accounts, list);
    return list;
}

async function startMember(id) {
    const proxy = await startLatencyProxy({ port: redis.options.port || 6379, resp: true });
    const client = clientThrough(proxy);
    const subscriber = clientThrough(proxy);
    const served = new Set();
    const stopped = [];
    const member = new ClusterCoordinator({
        redis: client,
        subscriber,
        logger,
        instanceId: id,
        address: null,
        ttl: TTL,
        runIndex: Math.floor(Math.random() * 1000) + 1,
        version: 'test',
        hooks: {
            serve(accounts) {
                for (const account of accounts) {
                    served.add(account);
                }
                setImmediate(() => member.backlogDrained());
            },
            async stopServing(account) {
                served.delete(account);
                stopped.push(account);
                return true;
            },
            async handleCall() {
                return { response: null };
            },
            onBroadcast() {}
        }
    });
    await member.start(null);
    member.setReady(true);
    const entry = { id, member, served, stopped, proxy };
    cleanups.push(async () => {
        await member.leave().catch(() => false);
        await member.close().catch(() => false);
        client.disconnect();
        subscriber.disconnect();
        await proxy.stop();
    });
    return entry;
}

test('ownership under Redis calls that fail at random', async () => {
    await cleanup();
    const list = await seedAccounts();

    const members = [await startMember('a'), await startMember('b')];
    const deadline = Date.now() + 20000;
    while (!list.every(account => members.some(entry => entry.served.has(account)))) {
        assert.ok(Date.now() < deadline, 'the accounts were split before the faults');
        await sleep(50);
    }

    // A third of every kind of call fails for a while, then all of them for longer than the
    // heartbeat lives (every member fences), then half, so the fences recover while their own
    // registrations, owner reads and releases keep failing
    const random = createRandom(Number(process.env.EE_FAULT_SEED) || 7);
    const violations = [];
    let samples = 0;
    let injected = 0;
    for (const [rate, ms] of [
        [0.3, TTL * 2],
        [1, TTL * 1.5],
        [0.5, TTL * 2]
    ]) {
        for (const entry of members) {
            entry.proxy.setFaults({ rate, kind: 'any', random });
        }
        const until = Date.now() + ms;
        while (Date.now() < until) {
            for (const account of list) {
                const announcing = members.filter(entry => entry.served.has(account) && entry.member.lease.isValid()).map(entry => entry.id);
                if (announcing.length > 1) {
                    violations.push({ account, announcing, at: Date.now() });
                }
            }
            samples++;
            await sleep(20);
        }
        for (const entry of members) {
            injected += entry.proxy.setFaults({ rate: 0 });
        }
    }

    assert.ok(injected > 20, `faults were injected (${injected})`);
    assert.ok(samples > 50);
    assert.ok(
        members.every(entry => entry.member.stats.fences > 0),
        'every member fenced while its calls were failing'
    );
    assert.deepEqual(violations.slice(0, 5), [], 'two members never announce for one account');

    // Settles once Redis behaves: one member per account, the one Redis records
    const settleBy = Date.now() + TTL * 15;
    let last;
    for (;;) {
        const owners = await redis.mget(list.map(account => clusterKeys.owner(account)));
        last = list.map((account, i) => ({ account, owner: owners[i], serving: members.filter(entry => entry.served.has(account)).map(entry => entry.id) }));
        const settled = last.every(({ owner, serving }) => serving.length === 1 && serving[0] === owner);
        if (settled && members.every(entry => entry.member.registered && entry.member.lease.isValid())) {
            break;
        }
        assert.ok(
            Date.now() < settleBy,
            `did not settle: ${JSON.stringify(last.filter(({ owner, serving }) => serving.length !== 1 || serving[0] !== owner).slice(0, 5))}`
        );
        await sleep(100);
    }
});

test('a member whose owner read fails after another took its accounts drops what it held back for them', async () => {
    // The member that lost its heartbeat registers again, and reading who owns its accounts fails
    // for longer than the fence retries it. A fence that only logged that failure let the next
    // renewal resume the lease with every account still connected and nothing dropped, so what it
    // had held back for the accounts the other member took (and announced) went out a second time
    for (const fn of cleanups.splice(0).reverse()) {
        await fn().catch(() => false);
    }
    await cleanup();
    const list = await seedAccounts();

    const [a, b] = [await startMember('a'), await startMember('b')];
    const deadline = Date.now() + 20000;
    while (!list.every(account => a.served.has(account) || b.served.has(account)) || !a.served.size) {
        assert.ok(Date.now() < deadline, 'the accounts were split');
        await sleep(50);
    }
    const ofA = [...a.served];
    const generation = a.member.lease.generation();

    // a is cut off from Redis until b has taken its accounts
    a.proxy.setFaults({ rate: 1, kind: 'any' });
    const takenBy = Date.now() + TTL * 6;
    while (!ofA.every(account => b.served.has(account))) {
        assert.ok(Date.now() < takenBy, 'b took the accounts of a');
        await sleep(20);
    }
    assert.equal(a.member.lease.isValid(), false, 'a holds its announcements back meanwhile');
    // a gets Redis back, apart from the owner read
    a.proxy.setFaults({ rate: 1, kind: 'any', only: new Set(['MGET']) });

    const resumedBy = Date.now() + TTL * 6;
    while (!a.member.lease.isValid()) {
        assert.ok(Date.now() < resumedBy, 'a resumes its lease');
        await sleep(10);
    }
    // The moment a may announce again: every account b took is either closed on a, or what a held
    // back was dropped with the lease generation
    const stillHeld = ofA.filter(account => !a.stopped.includes(account));
    assert.ok(
        !stillHeld.length || a.member.lease.generation() > generation,
        `a resumed with ${stillHeld.length} taken accounts and its held-back announcements intact`
    );
    a.proxy.setFaults({ rate: 0 });
});
