'use strict';

// Two cluster coordinators (lib/cluster/coordinator.js) against a real Redis, with the worker side
// replaced by a record of what each was told to serve. Covers the ownership life cycle end to end:
// the split, a crashed member, fencing, a scale-up handoff, a graceful leave and forwarding.

const test = require('node:test');
const assert = require('node:assert').strict;
const net = require('node:net');

// Set before anything opens a connection, so these keys cannot collide with another suite's
process.env.EENGINE_REDIS_PREFIX = 'test_cluster_coord';

const { redis } = require('../lib/db');
const { REDIS_PREFIX } = require('../lib/consts');
const { clusterKeys } = require('../lib/cluster/keys');
const { ClusterCoordinator, resolveAddress, resolveInstanceId } = require('../lib/cluster/coordinator');
const { desiredOwner } = require('../lib/cluster/placement');
const registerRedisTeardown = require('./helpers/redis-teardown');

const TTL = 2000;
const logger = { info() {}, warn() {}, error() {}, debug() {}, trace() {} };
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

const subscribers = [];

async function cleanup() {
    const keys = await redis.keys(`${REDIS_PREFIX}*`);
    if (keys.length) {
        await redis.del(keys);
    }
}

registerRedisTeardown(redis, async () => {
    await cleanup();
    for (const subscriber of subscribers) {
        subscriber.disconnect();
    }
});

function freePort() {
    return new Promise(resolve => {
        const server = net.createServer();
        server.listen(0, '127.0.0.1', () => {
            const { port } = server.address();
            server.close(() => resolve(port));
        });
    });
}

async function waitUntil(check, timeout = 15000, label = 'condition') {
    const deadline = Date.now() + timeout;
    while (Date.now() < deadline) {
        if (await check()) {
            return;
        }
        await sleep(50);
    }
    throw new Error(`Timed out waiting for ${label}`);
}

async function createAccounts(count) {
    const list = Array.from({ length: count }, (_, i) => `acc${i}`);
    for (const account of list) {
        await redis.hset(clusterKeys.account(account), { account, state: 'init' });
    }
    if (list.length) {
        await redis.sadd(clusterKeys.accounts, list);
    }
    return list;
}

/** A coordinator whose "workers" are a set of served accounts, with a log of what happened */
async function startMember(id, { listen = true, ready = true, backlog, drain = false } = {}) {
    const port = listen ? await freePort() : 0;
    const subscriber = redis.duplicate();
    subscribers.push(subscriber);
    const served = new Set();
    const events = [];
    const member = new ClusterCoordinator({
        redis,
        subscriber,
        logger,
        instanceId: id,
        address: port ? `127.0.0.1:${port}` : null,
        ttl: TTL,
        runIndex: Math.floor(Math.random() * 1000) + 1,
        version: 'test',
        hooks: {
            serve(accounts) {
                for (const account of accounts) {
                    assert.equal(served.has(account), false, `${id} was told to serve ${account} twice`);
                    served.add(account);
                }
                events.push(['serve', accounts.length, Date.now()]);
                if (drain) {
                    // The workers take the accounts at once
                    setImmediate(() => member.backlogDrained());
                }
            },
            async stopServing(account, opts = {}) {
                served.delete(account);
                events.push(['stop', account, !!opts.lost]);
                return true;
            },
            async handleCall(message) {
                events.push(['call', message.cmd, message.account]);
                if (!served.has(message.account)) {
                    const err = new Error('not here');
                    err.code = 'NotOwnedHere';
                    err.statusCode = 503;
                    throw err;
                }
                return { response: { by: id, cmd: message.cmd } };
            },
            onBroadcast(type, data, from) {
                events.push(['broadcast', type, data, from]);
            },
            backlog
        }
    });
    await member.start(port ? { port, host: '127.0.0.1' } : null);
    if (ready) {
        member.setReady(true);
    }
    return { id, member, served, events };
}

/** The batches a member was told to serve, as `{ count, at }` */
function serveBatches(entry) {
    return entry.events.filter(event => event[0] === 'serve').map(event => ({ count: event[1], at: event[2] }));
}

/**
 * Holds the next heartbeat of a member until the returned function is called, the way a renewal
 * waits in the client's queue while Redis cannot be reached
 */
function holdHeartbeat(entry) {
    const tick = entry.member.tick.bind(entry.member);
    let release;
    const gate = new Promise(resolve => {
        release = resolve;
    });
    entry.member.tick = async () => {
        await gate;
        entry.member.tick = tick;
        return await tick();
    };
    return release;
}

/** Stops a member the way a crash would: no leave, no further heartbeats */
async function crash(entry) {
    entry.member.closing = true;
    clearTimeout(entry.member.tickTimer);
    if (entry.member.rpcServer) {
        await entry.member.rpcServer.close();
    }
    await entry.member.close();
}

async function stopAll(...entries) {
    for (const entry of entries) {
        await entry.member.stopListening().catch(() => false);
        await entry.member.leave().catch(() => false);
        await entry.member.close().catch(() => false);
    }
}

/** Every account served by exactly one of the members, and recorded as owned by that one */
async function assertSingleOwners(list, members) {
    const owners = await redis.mget(list.map(account => clusterKeys.owner(account)));
    list.forEach((account, i) => {
        const serving = members.filter(entry => entry.served.has(account)).map(entry => entry.id);
        assert.equal(serving.length, 1, `${account} is served by ${JSON.stringify(serving)}`);
        assert.equal(owners[i], serving[0], `${account} is recorded as owned by ${owners[i]}`);
    });
}

const allServed = (list, members) => () => list.every(account => members.some(entry => entry.served.has(account)));

test('resolveInstanceId() and resolveAddress()', () => {
    assert.equal(resolveInstanceId('pod/1 a'), 'pod-1-a');
    assert.match(resolveInstanceId(''), /-[0-9a-f]{6}$/);
    assert.notEqual(resolveInstanceId(''), resolveInstanceId(''));

    assert.equal(resolveAddress({ port: 0 }), null);
    assert.equal(resolveAddress({ configured: 'ee-1.ee.svc', port: 3001 }), 'ee-1.ee.svc:3001');
    assert.equal(resolveAddress({ configured: '10.1.2.3:4000', port: 3001 }), '10.1.2.3:4000');
    assert.equal(resolveAddress({ configured: 'fd00::1', port: 3001 }), '[fd00::1]:3001');
    assert.equal(
        resolveAddress({
            port: 3001,
            interfaces: { lo: [{ address: '127.0.0.1', family: 'IPv4', internal: true }], eth0: [{ address: '10.0.0.7', family: 'IPv4', internal: false }] }
        }),
        '10.0.0.7:3001'
    );
});

test('a failed forward warns once per owner and error, and never for an account moving', () => {
    const member = new ClusterCoordinator({ redis, subscriber: redis, logger, instanceId: 'x', ttl: TTL, runIndex: 1, version: 'test', hooks: {} });
    assert.equal(member.forwardFailureLevel('a', 'NotOwnedHere'), 'debug');
    assert.equal(member.forwardFailureLevel('a', 'ClusterUnreachable'), 'warn');
    assert.equal(member.forwardFailureLevel('a', 'ClusterUnreachable'), 'debug', 'the same failure again');
    assert.equal(member.forwardFailureLevel('b', 'ClusterUnreachable'), 'warn', 'another owner');
    assert.equal(member.forwardFailureLevel('a', 'ClusterAuthFailed'), 'warn', 'another error');
    member.forwardWarnedAt.set('a:ClusterUnreachable', Date.now() - 60 * 1000);
    assert.equal(member.forwardFailureLevel('a', 'ClusterUnreachable'), 'warn', 'once the window has passed');
});

test('the broadcast channel names the Redis database', async () => {
    // Pub/sub spans every database of a server, so a deployment in database 12 used to receive the
    // change events and account deletions of one in database 11 sharing its key prefix
    assert.notEqual(clusterKeys.bus(11), clusterKeys.bus(12));
    assert.equal(clusterKeys.bus(undefined), clusterKeys.bus(0), 'no database given is database 0');

    const member = new ClusterCoordinator({ redis, subscriber: redis, logger, instanceId: 'x', ttl: TTL, runIndex: 1, version: 'test', hooks: {} });
    assert.equal(member.bus.channel, clusterKeys.bus(redis.options.db));
    assert.equal(member.bus.channel, `${REDIS_PREFIX}cluster:bus:${redis.options.db}`);

    // And the isolation holds on a real server: a message published for another database's channel
    // does not reach this one's subscriber
    const subscriber = redis.duplicate();
    subscribers.push(subscriber);
    const received = [];
    subscriber.on('messageBuffer', channel => received.push(channel.toString()));
    await subscriber.subscribe(member.bus.channel);
    await redis.publish(clusterKeys.bus(Number(redis.options.db) + 1), 'other deployment');
    await redis.publish(member.bus.channel, 'this deployment');
    await waitUntil(() => received.length > 0, 2000, 'the own message');
    await sleep(50);
    assert.deepEqual(received, [member.bus.channel]);
});

test('ownership life cycle', async t => {
    t.beforeEach(cleanup);

    await t.test('two members split the accounts, each served exactly once', async () => {
        const list = await createAccounts(40);
        const a = await startMember('a');
        const b = await startMember('b');
        try {
            await waitUntil(allServed(list, [a, b]), 15000, 'every account served');
            await sleep(TTL);
            await assertSingleOwners(list, [a, b]);
            assert.ok(a.served.size > 5 && b.served.size > 5, `split ${a.served.size}/${b.served.size}`);
            assert.ok(a.member.isReady() && b.member.isReady());
        } finally {
            await stopAll(a, b);
        }
    });

    await t.test('a scale-up hands the new member its share, stopping each account before releasing it', async () => {
        const list = await createAccounts(40);
        const a = await startMember('a');
        await waitUntil(() => a.served.size === list.length, 15000, 'a serves everything');
        const b = await startMember('b');
        try {
            await waitUntil(() => b.served.size > 5 && a.served.size + b.served.size === list.length, 15000, 'b takes its share');
            await sleep(TTL);
            await assertSingleOwners(list, [a, b]);
            assert.ok(
                a.events.some(([kind]) => kind === 'stop'),
                'a stopped the accounts it handed over'
            );
        } finally {
            await stopAll(a, b);
        }
    });

    await t.test('a large handoff goes on in paced batches, not one batch per full pass', async () => {
        // Over twice the per-pass budget moves to the new member
        const list = await createAccounts(500);
        const a = await startMember('a');
        await waitUntil(() => a.served.size === list.length, 20000, 'a serves everything');
        const b = await startMember('b');
        try {
            const started = Date.now();
            await waitUntil(() => a.served.size + b.served.size === list.length && b.served.size > 200, 20000, 'b takes its share');
            const took = Date.now() - started;
            // A full pass every five seconds would need at least ten for three batches
            assert.ok(took < a.member.fullPassInterval * 1.5, `the handoff took ${took} ms`);
            await sleep(TTL);
            await assertSingleOwners(list, [a, b]);
        } finally {
            await stopAll(a, b);
        }
    });

    await t.test('the accounts of a crashed member are taken over once its heartbeat expires', async () => {
        const list = await createAccounts(30);
        const a = await startMember('a');
        const b = await startMember('b');
        try {
            await waitUntil(allServed(list, [a, b]), 15000, 'every account served');
            const lost = [...a.served];
            await crash(a);
            const crashedAt = Date.now();
            await waitUntil(() => lost.every(account => b.served.has(account)), 20000, 'b takes over');
            const took = Date.now() - crashedAt;
            // the heartbeat TTL, plus a pass, never instantly
            assert.ok(took >= TTL - 1000, `taken over after ${took}ms`);
            assert.ok(took < TTL * 4 + 2000, `taken over after ${took}ms`);
        } finally {
            await stopAll(b);
        }
    });

    await t.test('a member that loses its heartbeat keeps the accounts nobody took over', async () => {
        const list = await createAccounts(20);
        const a = await startMember('a');
        try {
            await waitUntil(() => a.served.size === list.length, 15000, 'a serves everything');
            const generation = a.member.lease.generation();
            // The record expiring (a Redis stall, a frozen process) looks like this from inside
            await redis.del(clusterKeys.instance('a'));
            await waitUntil(() => a.member.stats.fences === 1 && !a.member.fencing, 10000, 'fencing');
            assert.equal(a.served.size, list.length, 'nothing was taken over, so nothing was closed');
            assert.equal(a.member.lease.generation(), generation, 'held back announcements go out');
            assert.equal(a.member.lease.isValid(), true);
            assert.equal(
                a.events.some(([kind]) => kind === 'stop'),
                false
            );
        } finally {
            await stopAll(a);
        }
    });

    await t.test('after a lost heartbeat, accounts another member took over are closed as lost', async () => {
        const list = await createAccounts(20);
        const a = await startMember('a');
        try {
            await waitUntil(() => a.served.size === list.length, 15000, 'a serves everything');
            const takenOver = list.slice(0, 5);
            // While a was frozen another member claimed some of its accounts
            await redis.del(clusterKeys.instance('a'));
            for (const account of takenOver) {
                await redis.set(clusterKeys.owner(account), 'b');
            }
            await waitUntil(() => a.member.stats.fences === 1 && !a.member.fencing, 10000, 'fencing');
            assert.deepEqual(a.events.filter(([kind]) => kind === 'stop').sort(), takenOver.map(account => ['stop', account, true]).sort());
            assert.equal(a.served.size, 15);
            assert.ok(takenOver.every(account => !a.served.has(account)));
        } finally {
            for (const account of list.slice(0, 5)) {
                await redis.del(clusterKeys.owner(account));
            }
            await stopAll(a);
        }
    });

    await t.test('a failed owner read while rejoining is retried, not skipped', async () => {
        const list = await createAccounts(10);
        const a = await startMember('a');
        const store = require('../lib/cluster/store');
        const readOwners = store.readOwners;
        try {
            await waitUntil(() => a.served.size === list.length, 15000, 'a serves everything');
            const generation = a.member.lease.generation();
            let failures = 0;
            store.readOwners = async (...args) => {
                if (a.member.fencing && failures < 1) {
                    failures++;
                    throw new Error('Redis went away');
                }
                return readOwners(...args);
            };
            await redis.del(clusterKeys.instance('a'));
            await redis.set(clusterKeys.owner(list[0]), 'b');
            await waitUntil(() => a.member.stats.fences === 1 && !a.member.fencing, 10000, 'fencing');
            assert.equal(failures, 1);
            assert.deepEqual(
                a.events.filter(([kind]) => kind === 'stop'),
                [['stop', list[0], true]],
                'the account taken over was closed before the lease resumed'
            );
            assert.equal(a.member.lease.generation(), generation);
            assert.equal(a.member.lease.isValid(), true);
        } finally {
            store.readOwners = readOwners;
            await redis.del(clusterKeys.owner(list[0]));
            await stopAll(a);
        }
    });

    await t.test('an owner read that keeps failing while rejoining gives up every account', async () => {
        // Before, the failure was only logged and the next renewal resumed the lease with every
        // account still connected, including the ones another member had taken
        const list = await createAccounts(10);
        const a = await startMember('a');
        const store = require('../lib/cluster/store');
        const readOwners = store.readOwners;
        try {
            await waitUntil(() => a.served.size === list.length, 15000, 'a serves everything');
            const generation = a.member.lease.generation();
            let failing = true;
            store.readOwners = async (...args) => {
                if (failing && a.member.fencing) {
                    throw new Error('Redis went away');
                }
                return readOwners(...args);
            };
            await redis.del(clusterKeys.instance('a'));
            await waitUntil(() => a.member.stats.fences === 1 && !a.member.fencing, 10000, 'fencing');
            failing = false;
            assert.equal(a.events.filter(([kind, , lost]) => kind === 'stop' && lost).length, list.length, 'every account closed as lost');
            assert.equal(a.member.lease.generation(), generation + 1, 'what was held back is dropped');
            assert.equal(a.member.registered, true, 'the record it registered is kept');
            // The next passes claim the accounts back
            await waitUntil(() => a.served.size === list.length, 20000, 'a serves everything again');
        } finally {
            store.readOwners = readOwners;
            await stopAll(a);
        }
    });

    await t.test('a member that cannot rejoin gives up every account', async () => {
        const list = await createAccounts(10);
        const a = await startMember('a');
        try {
            await waitUntil(() => a.served.size === list.length, 15000, 'a serves everything');
            const generation = a.member.lease.generation();
            // Another live process registered with the same id meanwhile
            await redis.del(clusterKeys.instance('a'));
            await redis.hset(clusterKeys.instance('a'), { token: 'someone-else' });
            await redis.pexpire(clusterKeys.instance('a'), TTL * 4);
            await waitUntil(() => a.events.filter(([kind]) => kind === 'stop').length === list.length, TTL * 4, 'giving up');
            assert.ok(
                a.events.filter(([kind]) => kind === 'stop').every(([, , lost]) => lost),
                'every account closed as lost'
            );
            assert.equal(a.member.lease.generation(), generation + 1, 'what was held back is dropped');
            assert.equal(a.served.size, 0);
            // Once the other record is gone it registers and claims again
            await redis.del(clusterKeys.instance('a'));
            await waitUntil(() => a.served.size === list.length, 20000, 'a serves everything again');
        } finally {
            await stopAll(a);
        }
    });

    await t.test('a graceful leave hands everything over at once', async () => {
        const list = await createAccounts(30);
        const a = await startMember('a');
        const b = await startMember('b');
        try {
            await waitUntil(allServed(list, [a, b]), 15000, 'every account served');
            const leaving = [...a.served];
            a.served.clear();
            await a.member.stopListening();
            await a.member.leave();
            const leftAt = Date.now();
            await waitUntil(() => leaving.every(account => b.served.has(account)), 10000, 'b takes over');
            assert.ok(Date.now() - leftAt < TTL, 'faster than waiting out the heartbeat');
        } finally {
            await a.member.close();
            await stopAll(b);
        }
    });

    await t.test('a steady stream of pass requests does not starve the heartbeat', async () => {
        const list = await createAccounts(5);
        const a = await startMember('a');
        try {
            await waitUntil(() => a.served.size === list.length, 15000, 'a serves everything');
            // Claim hints arriving faster than the debounce, for three heartbeat periods
            const until = Date.now() + TTL * 3;
            while (Date.now() < until) {
                a.member.requestPass(['acc0']);
                await sleep(20);
            }
            assert.equal(a.member.stats.fences, 0, 'the heartbeat kept being renewed');
            assert.equal(a.member.lease.isValid(), true);
        } finally {
            await stopAll(a);
        }
    });

    await t.test('the accounts of a live instance of another protocol are left to it', async () => {
        const list = await createAccounts(10);
        // A newer release running next to this one during a rolling deploy: it owns every account
        const store = require('../lib/cluster/store');
        const record = { protocol: 99, ready: 1, address: '127.0.0.1:1' };
        assert.ok(await store.register(redis, { id: 'next', token: 'n', ttl: TTL, record }));
        await store.claim(
            redis,
            list.map(account => ({ account, expected: '' })),
            'next',
            1
        );
        const renew = setInterval(() => store.renew(redis, { id: 'next', token: 'n', ttl: TTL, record }).catch(() => false), TTL / 4);
        const a = await startMember('a');
        try {
            await sleep(TTL * 4);
            assert.equal(a.served.size, 0, 'nothing of the live instance was claimed');
            assert.equal(await a.member.peer('next'), null, 'and no call is forwarded to it');
        } finally {
            clearInterval(renew);
            await stopAll(a);
        }
    });

    await t.test('on a cold start the first ready member takes only its own share', async () => {
        const list = await createAccounts(60);
        const a = await startMember('a', { ready: false });
        const b = await startMember('b', { ready: false });
        const c = await startMember('c', { ready: false });
        try {
            a.member.setReady(true);
            // Well within the orphan grace (two TTLs): b and c are starting, so their share waits
            await sleep(TTL / 2);
            assert.ok(a.served.size > 5 && a.served.size < 40, `a took ${a.served.size} of ${list.length}`);
            assert.equal(a.events.filter(([kind]) => kind === 'stop').length, 0, 'nothing had to be handed on');

            b.member.setReady(true);
            c.member.setReady(true);
            await waitUntil(allServed(list, [a, b, c]), 15000, 'every account served');
            await sleep(TTL);
            await assertSingleOwners(list, [a, b, c]);

            // Only a cold start: an instance that has been running takes a crashed member's
            // accounts at once, whoever else happens to be starting then
            const d = await startMember('d', { ready: false });
            try {
                await a.member.refreshLive();
                assert.deepEqual(a.member.starting(), ['d'], 'reserved while a is young');
                a.member.coldStartUntil = Date.now() - 1;
                assert.deepEqual(a.member.starting(), [], 'not once a has been running a while');
            } finally {
                await stopAll(d);
            }
        } finally {
            await stopAll(a, b, c);
        }
    });

    await t.test('a member that is not ready takes nothing and is not handed anything', async () => {
        const list = await createAccounts(20);
        const a = await startMember('a');
        const b = await startMember('b', { ready: false });
        try {
            await waitUntil(() => a.served.size === list.length, 15000, 'a serves everything');
            await sleep(TTL);
            assert.equal(b.served.size, 0);
            assert.equal(b.member.isReady(), false);
        } finally {
            await stopAll(a, b);
        }
    });
});

test('forwarding and the bus', async t => {
    t.beforeEach(cleanup);

    await t.test('a command for an account another member serves runs there', async () => {
        const list = await createAccounts(20);
        const a = await startMember('a');
        const b = await startMember('b');
        try {
            await waitUntil(allServed(list, [a, b]), 15000, 'every account served');
            const remote = [...b.served][0];
            assert.deepEqual(await a.member.forward({ cmd: 'listMailboxes', account: remote }), { by: 'b', cmd: 'listMailboxes' });
            assert.ok(b.events.some(([kind, cmd, account]) => kind === 'call' && cmd === 'listMailboxes' && account === remote));
        } finally {
            await stopAll(a, b);
        }
    });

    await t.test('an account nobody owns is WorkerNotAvailable, or the fallback the caller gives', async () => {
        await createAccounts(1);
        const a = await startMember('a', { ready: false });
        try {
            await assert.rejects(
                a.member.forward({ cmd: 'listMailboxes', account: 'acc0' }),
                err => err.code === 'WorkerNotAvailable' && err.statusCode === 503
            );
            assert.equal(await a.member.forward({ cmd: 'teardown', account: 'acc0' }, { unowned: false }), false);
        } finally {
            await stopAll(a);
        }
    });

    await t.test('an owner that no longer serves the account is asked again, then WorkerNotAvailable', async () => {
        const list = await createAccounts(10);
        const a = await startMember('a');
        const b = await startMember('b');
        try {
            await waitUntil(allServed(list, [a, b]), 15000, 'every account served');
            const remote = [...b.served][0];
            b.served.delete(remote);
            await assert.rejects(a.member.forward({ cmd: 'getText', account: remote }), err => err.code === 'WorkerNotAvailable');
            assert.equal(b.events.filter(([kind, , account]) => kind === 'call' && account === remote).length, 2, 'one retry');
        } finally {
            await stopAll(a, b);
        }
    });

    await t.test('an instance checks that its advertised address leads back to it', async () => {
        const a = await startMember('a');
        try {
            assert.equal(await a.member.checkOwnAddress(), true);
            const advertised = a.member.address;
            // An address nothing listens on, as a wrong EENGINE_CLUSTER_ADDRESS would give
            a.member.address = `127.0.0.1:${await freePort()}`;
            assert.equal(await a.member.checkOwnAddress(), false);
            a.member.address = advertised;
        } finally {
            await stopAll(a);
        }
    });

    await t.test('an owner without a call listener is WorkerNotAvailable', async () => {
        const list = await createAccounts(10);
        const a = await startMember('a');
        const b = await startMember('b', { listen: false });
        try {
            await waitUntil(allServed(list, [a, b]), 15000, 'every account served');
            const remote = [...b.served][0];
            await assert.rejects(a.member.forward({ cmd: 'getText', account: remote }), err => err.code === 'WorkerNotAvailable');
        } finally {
            await stopAll(a, b);
        }
    });

    await t.test('broadcasts reach the other members, not the sender', async () => {
        const a = await startMember('a');
        const b = await startMember('b');
        try {
            a.member.broadcast('settings', { logs: { all: true } });
            await waitUntil(() => b.events.some(([kind, type]) => kind === 'broadcast' && type === 'settings'), 5000, 'broadcast delivery');
            const delivered = b.events.find(([kind, type]) => kind === 'broadcast' && type === 'settings');
            assert.deepEqual(delivered.slice(2), [{ logs: { all: true } }, 'a']);
            assert.equal(
                a.events.some(([kind, type]) => kind === 'broadcast' && type === 'settings'),
                false
            );
        } finally {
            await stopAll(a, b);
        }
    });

    await t.test('a new account is claimed by the member placement picks, through the bus', async () => {
        const a = await startMember('a');
        const b = await startMember('b');
        try {
            await sleep(TTL);
            const list = await createAccounts(12);
            for (const account of list) {
                // Announced on one member, whichever it is placed on
                a.member.accountAdded(account);
            }
            // Well before the periodic full pass would find them
            await waitUntil(allServed(list, [a, b]), 4000, 'new accounts served');
            await assertSingleOwners(list, [a, b]);
        } finally {
            await stopAll(a, b);
        }
    });
});

test('claim hints', async t => {
    t.beforeEach(cleanup);

    // Account records only, left out of the account set: no full pass finds them, so whatever claims
    // them was told to by a hint
    async function hintOnlyAccounts(count, prefix) {
        const list = Array.from({ length: count }, (_, i) => `${prefix}${i}`);
        for (const account of list) {
            await redis.hset(clusterKeys.account(account), { account, state: 'init' });
        }
        return list;
    }

    function recordPublished(entry) {
        const published = [];
        const publish = entry.member.bus.publish.bind(entry.member.bus);
        entry.member.bus.publish = (type, data) => {
            published.push([type, data]);
            return publish(type, data);
        };
        return () => published.filter(([type]) => type === 'claim').map(([, data]) => data);
    }

    const ownersOf = async list => await redis.mget(list.map(account => clusterKeys.owner(account)));

    await t.test('every member plans a hint with its own view, and only the one placement picks claims', async () => {
        const a = await startMember('a');
        const b = await startMember('b');
        const c = await startMember('c');
        try {
            await sleep(TTL);
            const list = (await hintOnlyAccounts(60, 'hint')).filter(account => desiredOwner(account, ['a', 'b', 'c']) === 'c').slice(0, 4);
            const claims = recordPublished(a);

            // Added through a, whatever a knows about the members: the hint names no member
            for (const account of list) {
                a.member.accountAdded(account);
            }
            assert.deepEqual(
                claims(),
                list.map(account => ({ accounts: [account] }))
            );

            await waitUntil(async () => (await ownersOf(list)).every(owner => owner === 'c'), 2000, 'c to claim the accounts');
            assert.ok(list.every(account => c.served.has(account) && !a.served.has(account) && !b.served.has(account)));
        } finally {
            await stopAll(a, b, c);
        }
    });
});

test('Redis outages and claim pacing', async t => {
    t.beforeEach(cleanup);

    await t.test("after an outage that expired every record, the member back first takes no other member's accounts", async () => {
        const list = await createAccounts(60);
        const a = await startMember('a', { listen: false });
        const b = await startMember('b', { listen: false });
        const c = await startMember('c', { listen: false });
        try {
            await waitUntil(allServed(list, [a, b, c]), 15000, 'every account served');
            await sleep(TTL);
            const before = new Map([a, b, c].map(entry => [entry.id, new Set(entry.served)]));

            const releases = [a, b, c].map(holdHeartbeat);
            await sleep(TTL * 1.5);
            await redis.del([a, b, c].map(entry => clusterKeys.instance(entry.id)));

            // Redis is back: a reconnects first, b a while later, c never (it died meanwhile)
            releases[0]();
            const aBack = Date.now();
            await sleep(TTL * 0.75);
            assert.deepEqual([...a.served].sort(), [...before.get('a')].sort(), 'a took nothing while the others reconnect');
            releases[1]();
            await sleep(TTL * 0.5);
            await crash(c);
            assert.deepEqual([...b.served].sort(), [...before.get('b')].sort(), 'b kept its accounts');
            assert.deepEqual([...a.served].sort(), [...before.get('a')].sort(), 'a still took nothing');

            // The accounts of the member that did not come back move once the grace has passed
            await waitUntil(allServed(list, [a, b]), 15000, 'the dead member accounts taken over');
            assert.ok(Date.now() - aBack >= TTL * 2 - 500, `taken over ${Date.now() - aBack} ms after a was back`);
            await assertSingleOwners(list, [a, b]);
        } finally {
            await stopAll(a, b);
        }
    });

    await t.test('claims are paced by the accounts still waiting for a worker', async () => {
        const list = await createAccounts(1500);
        // 700 waiting leaves room for 300 more claims per pass
        const a = await startMember('a', { listen: false, backlog: () => 700 });
        try {
            await waitUntil(() => a.served.size === list.length, 20000, 'every account served');
            const batches = serveBatches(a).map(batch => batch.count);
            assert.ok(batches.length >= 5, `claimed in ${JSON.stringify(batches)}`);
            assert.ok(
                batches.every(count => count <= 300),
                `claimed in ${JSON.stringify(batches)}`
            );
        } finally {
            await stopAll(a);
        }
    });

    await t.test('claims left over follow early when the workers took the earlier ones', async () => {
        const list = await createAccounts(3000);
        // Each resumed batch reads the claims left over, not the whole account list again
        let listReads = 0;
        const smembers = redis.smembers;
        redis.smembers = function (key, ...args) {
            if (key === clusterKeys.accounts) {
                listReads++;
            }
            return smembers.call(this, key, ...args);
        };
        // A thousand claims per pass; without the drain each further batch waits a whole CLAIM_PAUSE
        const a = await startMember('a', { listen: false, drain: true });
        try {
            await waitUntil(() => a.served.size === list.length, 20000, 'every account served');
            const batches = serveBatches(a);
            assert.ok(batches.length >= 3, `claimed in ${JSON.stringify(batches)}`);
            const spread = batches[batches.length - 1].at - batches[0].at;
            assert.ok(spread < 1500, `the batches were ${spread} ms apart in all`);
            assert.equal(listReads, 1, 'one full pass');
        } finally {
            redis.smembers = smembers;
            await stopAll(a);
        }
    });
});

test('the signing key mixes in the encryption secret', async () => {
    await cleanup();
    const keyOf = async localSecret => {
        const member = new ClusterCoordinator({
            redis,
            subscriber: redis,
            logger,
            instanceId: 'k',
            address: null,
            runIndex: 1,
            version: 'test',
            localSecret,
            hooks: {}
        });
        const key = await member.getSecret();
        await member.rpcClient.close();
        return key.toString('hex');
    };
    const stored = await keyOf(undefined);
    assert.equal(stored, await redis.get(clusterKeys.secret), 'without one the stored key is used as it is');
    assert.notEqual(await keyOf('one'), stored, 'the stored key alone does not sign a call');
    assert.equal(await keyOf('one'), await keyOf('one'));
    assert.notEqual(await keyOf('one'), await keyOf('two'));
});
