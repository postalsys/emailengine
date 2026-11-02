#!/usr/bin/env node
'use strict';

// Chaos runner for the multi-instance setup (npm run test:chaos). Runs a fleet under steady
// background traffic (API reads, new messages, submissions) and puts it through failures one after
// another while an invariant checker watches:
//
//   - no message is announced twice, ever (checked every two seconds)
//   - no account goes without a live owner for longer than the failover allows
//   - no instance exits unless the runner made it
//   - no thread of any instance dies of an uncaught exception or an unhandled rejection
//   - no instance holds more than twice its share while Redis comes back after an outage
//   - at the end, every message that arrived during the run was announced
//
// Every instance's Redis and cluster port go through TCP proxies, so Redis can be slowed or cut and
// an instance can be partitioned from its peers without Docker.
//
//   npm run test:chaos -- --experiments all --mix-minutes 10 --seed 7
//
// Options: --instances N --accounts N --servers N --ttl DURATION --experiments LIST|all
// --mix-minutes N (a seeded random schedule after the experiments) --seed N --label TEXT
// --log-level LEVEL (of the instances, warn by default)

process.env.NODE_ENV = process.env.NODE_ENV || 'test';

const fs = require('node:fs');
const path = require('node:path');

const { setupWorkload, traffic, submissionReport, Recorder, sleep, licenseNote } = require('./workload');
const { summarize } = require('./metrics');
// Seeded, so a failing schedule can be replayed
const { createRandom } = require('../../helpers/property');

// "6s", "500ms", "1m"; lib/tools is not loaded here, it would open Redis connections of its own
function getDuration(value) {
    const match = /^(\d+(?:\.\d+)?)(ms|s|m)?$/.exec(String(value).trim());
    if (!match) {
        throw new Error(`Invalid duration ${value}`);
    }
    return Number(match[1]) * { ms: 1, s: 1000, m: 60000 }[match[2] || 'ms'];
}

const RESULTS_DIR = path.join(__dirname, '..', 'results');

function parseArgs(argv) {
    const opts = { instances: 3, accounts: 120, servers: 40, ttl: '6s', experiments: 'all', mixMinutes: 0, seed: 1, label: '', logLevel: 'warn' };
    for (let i = 0; i < argv.length; i++) {
        const key = argv[i].replace(/^--/, '').replace(/-([a-z])/g, (m, c) => c.toUpperCase());
        if (!(key in opts)) {
            throw new Error(`Unknown option ${argv[i]}`);
        }
        opts[key] = typeof opts[key] === 'number' ? Number(argv[i + 1]) : argv[i + 1];
        i++;
    }
    return opts;
}

/** Ids of the instances whose heartbeat record is alive */
async function liveInstances(redis) {
    const live = new Set();
    for (const id of await redis.smembers('cluster:instances')) {
        if (await redis.exists(`cluster:inst:${id}`)) {
            live.add(id);
        }
    }
    return live;
}

async function main() {
    const opts = parseArgs(process.argv.slice(2));
    const ttl = getDuration(opts.ttl);
    const random = createRandom(opts.seed);
    // Which Redis calls fail draws from its own sequence, so the schedule replays whatever the
    // traffic was
    const faultRandom = createRandom(opts.seed + 7919);
    const startedAt = new Date();
    console.log(`chaos: instances=${opts.instances} accounts=${opts.accounts} ttl=${opts.ttl} seed=${opts.seed}`);

    const workload = await setupWorkload({
        instances: opts.instances,
        accounts: opts.accounts,
        servers: opts.servers,
        ttl: opts.ttl,
        logLevel: opts.logLevel,
        seed: true,
        redisProxies: true,
        peerProxies: true,
        prefix: 'chaos'
    });
    const { fleet, host, redis, accounts } = workload;
    console.log(`${accounts.length} accounts connected in ${workload.connectSeconds}s, logs in ${fleet.logDir}`);
    const license = licenseNote(workload.licensed);

    const runStartedAt = Date.now();
    const recorder = new Recorder();
    let running = true;
    const load = traffic(workload, recorder, () => running);
    const background = Promise.all([load.readers(4), load.events(2), load.submits(1)]);

    // Exits the runner caused; anything else is a violation
    const expectedExits = new Set();
    // Injection times during which a duplicate is measured rather than a violation: an experiment
    // that fails deletes and reads too makes a step after a queued webhook fail, and repeating the
    // webhook is the price of not losing it (at least once)
    const toleranceWindows = [];
    const toleratedKeys = new Set();
    const isTolerated = duplicate => toleranceWindows.some(([from, to]) => duplicate.injectedAt >= from && duplicate.injectedAt <= to);
    const reportDuplicate = duplicate => {
        if (isTolerated(duplicate)) {
            toleratedKeys.add(`${duplicate.account}\n${duplicate.token}`);
            return;
        }
        if (!violations.some(v => v.kind === 'duplicate' && v.token === duplicate.token && v.account === duplicate.account)) {
            violate('duplicate', duplicate);
        }
    };
    const violations = [];
    const violate = (kind, details) => {
        violations.push(Object.assign({ at: Date.now() - runStartedAt, kind }, details));
        console.error(`VIOLATION ${kind}`, JSON.stringify(details));
    };

    // An error that reached a global handler ends the thread it happened in (an IMAP worker, say)
    // without ending the instance, so it is counted from the log, where lib/logger.js writes it
    const fatalSeen = new Map();
    const checkFatal = () => {
        for (const instance of fleet.instances) {
            const entries = [...instance.logEntries('uncaughtException'), ...instance.logEntries('unhandledRejection')];
            const seen = fatalSeen.get(instance) || 0;
            for (const entry of entries.slice(seen)) {
                violate('uncaught', { instance: instance.id, msg: entry.msg, error: entry.err && entry.err.message, stack: entry.err && entry.err.stack });
            }
            fatalSeen.set(instance, entries.length);
        }
    };

    // Invariant checker
    const unownedSince = new Map();
    let maxUnowned = 0;
    const UNOWNED_LIMIT = ttl * 4 + 15000;
    let checking = false;
    const checker = setInterval(async () => {
        if (checking) {
            return;
        }
        checking = true;
        try {
            const events = await host.call('reconcile', { since: runStartedAt });
            for (const duplicate of events.duplicates) {
                reportDuplicate(duplicate);
            }

            const live = await liveInstances(redis);
            const owners = await workload.refreshOwners();
            const now = Date.now();
            for (const account of accounts) {
                const owner = owners.get(account);
                if (owner && live.has(owner)) {
                    unownedSince.delete(account);
                    continue;
                }
                if (!unownedSince.has(account)) {
                    unownedSince.set(account, now);
                }
                const unowned = now - unownedSince.get(account);
                maxUnowned = Math.max(maxUnowned, unowned);
                if (unowned > UNOWNED_LIMIT && !violations.some(v => v.kind === 'unowned' && v.account === account)) {
                    violate('unowned', { account, owner, ms: unowned });
                }
            }

            checkFatal();
            for (const instance of fleet.instances) {
                if (!instance.running && instance.lastExit && !expectedExits.has(instance.lastExit.at)) {
                    expectedExits.add(instance.lastExit.at);
                    violate('unexpected exit', { instance: instance.id, exit: instance.lastExit });
                }
            }
        } catch (err) {
            console.error('checker failed', err.message);
        } finally {
            checking = false;
        }
    }, 2000);

    // What an instance owns right now
    const ownedBy = async id => {
        const owners = await workload.refreshOwners();
        return accounts.filter(account => owners.get(account) === id);
    };
    const pickVictim = () => {
        const candidates = fleet.instances.filter(instance => instance.running && !instance.frozen && !instance.outOfRotation);
        return candidates[Math.floor(random() * candidates.length)];
    };
    const waitFor = async (check, timeout, label) => {
        const deadline = Date.now() + timeout;
        while (Date.now() < deadline) {
            if (await check()) {
                return Date.now();
            }
            await sleep(250);
        }
        throw new Error(`Timed out after ${timeout}ms waiting for ${label}`);
    };
    // Accounts served by an instance other than `id`, by live owners
    const movedAway = async (list, id) => {
        const owners = await workload.refreshOwners();
        const live = await liveInstances(redis);
        return list.every(account => owners.get(account) && owners.get(account) !== id && live.has(owners.get(account)));
    };
    const stableOwners = async (id, list, windowMs) => {
        const before = await workload.refreshOwners();
        await sleep(windowMs);
        const after = await workload.refreshOwners();
        return list.filter(account => before.get(account) === id && after.get(account) !== id);
    };
    const killExpected = async instance => {
        await instance.kill();
        expectedExits.add(instance.lastExit && instance.lastExit.at);
    };
    const stopExpected = async instance => {
        await workload.drainAndStop(instance);
        expectedExits.add(instance.lastExit && instance.lastExit.at);
    };
    // Samples how the accounts are spread while `until` runs; an instance holding more than twice
    // an even share of them is a violation (the first instance back after a Redis outage once took
    // every account)
    const MAX_SHARE = 2;
    const watchSpread = async (label, until) => {
        let done = false;
        let worst = { ratio: 0 };
        const sampler = (async () => {
            while (!done) {
                const owners = await workload.refreshOwners();
                const running = fleet.instances.filter(instance => instance.running).length;
                const counts = new Map();
                for (const owner of owners.values()) {
                    if (owner) {
                        counts.set(owner, (counts.get(owner) || 0) + 1);
                    }
                }
                for (const [id, count] of counts) {
                    const ratio = count / (accounts.length / Math.max(1, running));
                    if (ratio > worst.ratio) {
                        worst = { ratio: Number(ratio.toFixed(2)), instance: id, accounts: count };
                    }
                }
                await sleep(250);
            }
        })();
        try {
            return await until();
        } finally {
            done = true;
            await sampler;
            if (worst.ratio > MAX_SHARE) {
                violate('concentrated', Object.assign({ during: label }, worst));
            }
        }
    };
    // Gives Redis back to the instances one by one, in a seeded order, the way their clients
    // reconnect on their own retry schedules. Spaced so every instance is back within one TTL
    const resumeRedisStaggered = async () => {
        const proxies = [...workload.redisProxies.values()].sort(() => random() - 0.5);
        const spacing = Math.floor(ttl / proxies.length);
        for (const [i, proxy] of proxies.entries()) {
            if (i) {
                await sleep(spacing);
            }
            proxy.resume();
        }
        return spacing;
    };
    const runningInstances = () => fleet.instances.filter(instance => instance.running);
    const countLog = msg => runningInstances().reduce((sum, instance) => sum + instance.logEntries(msg).length, 0);
    const everyAccountOwned = async () => {
        const owners = await workload.refreshOwners();
        const live = await liveInstances(redis);
        return accounts.every(account => live.has(owners.get(account)));
    };
    // Fails Redis calls of every instance for `ms`, returning how many were failed
    const withFaults = async (faults, ms) => {
        for (const proxy of workload.redisProxies.values()) {
            proxy.setFaults(faults);
        }
        await sleep(ms);
        let injected = 0;
        for (const proxy of workload.redisProxies.values()) {
            injected += proxy.setFaults({ rate: 0 });
        }
        return injected;
    };

    const restart = async instance => {
        await instance.start();
        await instance.waitReady();
        await waitFor(async () => (await ownedBy(instance.id)).length > 0, ttl * 6 + 30000, `${instance.id} to own accounts again`);
    };

    const EXPERIMENTS = {
        async crash() {
            const victim = pickVictim();
            const owned = await ownedBy(victim.id);
            await killExpected(victim);
            const t0 = Date.now();
            const rehomed = await waitFor(() => movedAway(owned, victim.id), ttl * 6 + 30000, 'the crashed instance accounts to move');
            await restart(victim);
            return { victim: victim.id, accounts: owned.length, rehomeMs: rehomed - t0 };
        },

        async graceful() {
            const victim = pickVictim();
            const owned = await ownedBy(victim.id);
            const t0 = Date.now();
            await stopExpected(victim);
            const stopped = Date.now();
            const rehomed = await waitFor(() => movedAway(owned, victim.id), ttl * 4 + 30000, 'the stopped instance accounts to move');
            await restart(victim);
            return { victim: victim.id, accounts: owned.length, stopMs: stopped - t0, rehomeAfterExitMs: rehomed - stopped };
        },

        async freeze() {
            const victim = pickVictim();
            const owned = await ownedBy(victim.id);
            victim.freeze();
            const t0 = Date.now();
            await sleep(ttl * 2.5);
            const tookOver = await movedAway(owned, victim.id);
            victim.thaw();
            await waitFor(async () => victim.logEntries('Rejoined the cluster').length > 0, ttl * 6 + 30000, 'the thawed instance to rejoin');
            await waitFor(async () => (await ownedBy(victim.id)).length > 0, ttl * 6 + 30000, 'the thawed instance to own accounts again');
            return { victim: victim.id, accounts: owned.length, frozenMs: Date.now() - t0, takenOverWhileFrozen: tookOver };
        },

        async slowPod() {
            // Stalls shorter than the heartbeat interval: nothing may move
            const victim = pickVictim();
            const owned = await ownedBy(victim.id);
            const before = await workload.refreshOwners();
            const until = Date.now() + 20000;
            while (Date.now() < until) {
                victim.freeze();
                await sleep(Math.min(400, ttl / 8));
                victim.thaw();
                await sleep(600);
            }
            const after = await workload.refreshOwners();
            const moved = owned.filter(account => before.get(account) !== after.get(account));
            if (moved.length) {
                violate('moved while slow', { victim: victim.id, moved: moved.length });
            }
            return { victim: victim.id, accounts: owned.length, moved: moved.length };
        },

        async slowRedis() {
            const victim = pickVictim();
            const owned = await ownedBy(victim.id);
            const proxy = workload.redisProxies.get(victim.id);
            proxy.setDelay(150);
            const moved = await stableOwners(victim.id, owned, 20000);
            proxy.setDelay(0);
            if (moved.length) {
                violate('moved while Redis was slow', { victim: victim.id, moved: moved.length });
            }
            return { victim: victim.id, accounts: owned.length, moved: moved.length };
        },

        async slowMailServer() {
            const all = await workload.refreshOwners();
            await host.call('addRule', { rule: { on: 'command', command: 'FETCH', delay: 500 }, account: accounts[0] });
            await sleep(20000);
            await host.call('clearRules');
            const after = await workload.refreshOwners();
            const moved = accounts.filter(account => all.get(account) !== after.get(account));
            if (moved.length) {
                violate('moved while a mail server was slow', { moved: moved.length });
            }
            return { moved: moved.length };
        },

        async mailDisconnect() {
            await host.call('disconnectAll', { serverIndex: 0 });
            await sleep(10000);
            return { server: 0 };
        },

        async redisOutage() {
            // Every instance loses Redis for longer than its heartbeat; each fences and rejoins,
            // keeping its own accounts however far apart they get Redis back
            for (const proxy of workload.redisProxies.values()) {
                proxy.pause();
            }
            await sleep(ttl * 1.5);
            const t0 = Date.now();
            let spacing;
            await watchSpread('redisOutage', async () => {
                spacing = await resumeRedisStaggered();
                await waitFor(
                    async () =>
                        (await workload.refreshOwners()) &&
                        fleet.instances.every(
                            instance =>
                                !instance.running ||
                                instance.logEntries('Rejoined the cluster').length > 0 ||
                                instance.logEntries('Joined the cluster').length > 1
                        ),
                    ttl * 6 + 60000,
                    'every instance to rejoin'
                );
                await sleep(ttl * 2);
            });
            return { pausedMs: ttl * 1.5, resumeSpacingMs: spacing, rejoinMs: Date.now() - t0 };
        },

        async redisOutageLong() {
            // Longer than an instance tries to register again: every instance gives up its
            // accounts and drops what it held back, and every new message must still be announced
            // once, by whichever instance owns the account afterwards
            for (const proxy of workload.redisProxies.values()) {
                proxy.pause();
            }
            await sleep(ttl * 4);
            const t0 = Date.now();
            let spacing;
            let reownedMs;
            await watchSpread('redisOutageLong', async () => {
                spacing = await resumeRedisStaggered();
                await waitFor(
                    async () => {
                        const owners = await workload.refreshOwners();
                        return accounts.every(account => owners.get(account));
                    },
                    ttl * 10 + 60000,
                    'every account owned again'
                );
                reownedMs = Date.now() - t0;
                await sleep(ttl * 2);
            });
            return { pausedMs: ttl * 4, resumeSpacingMs: spacing, reownedMs };
        },

        async redisPartition() {
            // One instance loses Redis while the others keep it: they take its accounts once its
            // heartbeat expires, while its mail connections are still open. It holds back what
            // it would announce, and drops the accounts once it reaches Redis again
            const victim = pickVictim();
            const owned = await ownedBy(victim.id);
            const proxy = workload.redisProxies.get(victim.id);
            proxy.pause();
            const t0 = Date.now();
            const rehomed = await waitFor(() => movedAway(owned, victim.id), ttl * 6 + 30000, 'the cut off instance accounts to move');
            await sleep(ttl);
            proxy.resume();
            await waitFor(async () => victim.logEntries('Rejoined the cluster').length > 0, ttl * 6 + 30000, 'the cut off instance to rejoin');
            await waitFor(async () => (await ownedBy(victim.id)).length > 0, ttl * 10 + 30000, 'the cut off instance to own accounts again');
            return { victim: victim.id, accounts: owned.length, rehomeMs: rehomed - t0 };
        },

        async redisOverload() {
            // Redis answers every instance slowly enough that renewals take longer than the
            // heartbeat interval and some records may expire: nothing may move, since every
            // instance sees the same slow Redis and none of them is gone
            const before = await workload.refreshOwners();
            const delay = Math.floor(ttl / 6);
            for (const proxy of workload.redisProxies.values()) {
                proxy.setDelay(delay);
            }
            await sleep(20000);
            for (const proxy of workload.redisProxies.values()) {
                proxy.setDelay(0);
            }
            await sleep(ttl * 2);
            const after = await workload.refreshOwners();
            const moved = accounts.filter(account => before.get(account) !== after.get(account));
            const fenced = runningInstances().filter(instance => instance.logEntries('Lost cluster membership').length > 0).length;
            if (moved.length) {
                violate('moved while Redis was slow for everyone', { moved: moved.length, delay });
            }
            return { delayEachWayMs: delay, moved: moved.length, instancesThatEverFenced: fenced };
        },

        async crashTwo() {
            // Two instances fail together (a node or a zone): the rest take both shares
            const victims = [];
            while (victims.length < 2 && runningInstances().length - victims.length > 1) {
                const victim = pickVictim();
                if (!victims.includes(victim)) {
                    victims.push(victim);
                    victim.outOfRotation = true;
                }
            }
            const owned = [];
            for (const victim of victims) {
                owned.push(...(await ownedBy(victim.id)));
            }
            await Promise.all(victims.map(killExpected));
            const t0 = Date.now();
            const rehomed = await waitFor(
                async () => {
                    for (const victim of victims) {
                        if (!(await movedAway(owned, victim.id))) {
                            return false;
                        }
                    }
                    return true;
                },
                ttl * 6 + 30000,
                'the accounts of both crashed instances to move'
            );
            await Promise.all(victims.map(restart));
            return { victims: victims.map(victim => victim.id), accounts: owned.length, rehomeMs: rehomed - t0 };
        },

        async crashDuringHandoff() {
            // A new instance is taking its share when one of the donors crashes
            const added = await workload.addInstance();
            await waitFor(async () => (await ownedBy(added.id)).length > 0, ttl * 6 + 30000, 'the new instance to take accounts');
            const donors = runningInstances().filter(instance => instance !== added && !instance.outOfRotation);
            const victim = donors[Math.floor(random() * donors.length)];
            const owned = await ownedBy(victim.id);
            await killExpected(victim);
            const t0 = Date.now();
            const rehomed = await waitFor(() => movedAway(owned, victim.id), ttl * 6 + 30000, 'the crashed donor accounts to move');
            await restart(victim);
            await stopExpected(added);
            await waitFor(() => movedAway(accounts, added.id), ttl * 4 + 30000, 'the added instance accounts to move');
            return { added: added.id, victim: victim.id, accounts: owned.length, rehomeMs: rehomed - t0 };
        },

        async fleetRestart() {
            // Every instance crashes and the whole fleet starts again at once: every account is
            // owned again and announces new mail once
            const instances = runningInstances();
            await Promise.all(instances.map(killExpected));
            const t0 = Date.now();
            await Promise.all(instances.map(instance => instance.start()));
            await Promise.all(instances.map(instance => instance.waitReady()));
            const ready = Date.now();
            // The owner records name the same instance ids before and after, so the check is the
            // state the API reports, which reads connecting until the new run has connected
            await waitFor(
                async () => {
                    const res = await instances[0].request('GET', `/v1/accounts?pageSize=1000`).catch(() => null);
                    const listed = (res && res.status === 200 && res.body.accounts) || [];
                    return listed.filter(entry => accounts.includes(entry.account) && entry.state === 'connected').length === accounts.length;
                },
                ttl * 10 + 60000,
                'every account connected by a restarted instance'
            );
            return { instances: instances.length, readyMs: ready - t0, connectedMs: Date.now() - t0 };
        },

        async redisFaults() {
            // Redis runs out of memory on and off: a share of the commands a full Redis refuses
            // (the ones that add data, and every script) fails with OOM on every instance, while
            // reads and deletes work. ioredis resends a command after a cut connection, so a reply
            // like this is how a Redis problem actually reaches the code: every caller has to keep
            // its work rather than drop it, and the fleet has to settle once Redis has room again
            const rate = 0.1;
            const faultMs = 30000;
            const exitsBefore = countLog('Worker exited');
            const fencesBefore = countLog('Lost cluster membership');
            const injected = await withFaults({ rate, random: faultRandom }, faultMs);
            const t0 = Date.now();
            await waitFor(everyAccountOwned, ttl * 10 + 60000, 'every account owned by a live instance');
            return {
                rate,
                faultMs,
                injected,
                settleMs: Date.now() - t0,
                workerExits: countLog('Worker exited') - exitsBefore,
                fences: countLog('Lost cluster membership') - fencesBefore
            };
        },

        async redisFaultsAny() {
            // Harsher than any one real condition and left out of the default order: a share of
            // every command fails, reads and deletes too, so every error path gets its turn. Run it
            // on its own to see what at-least-once costs (a step that failed after its webhook was
            // queued repeats it) and whether anything is still lost
            const rate = 0.05;
            const faultMs = 20000;
            // Messages injected shortly before the faults may be processed under them too
            const window = [Date.now() - 5000];
            toleranceWindows.push(window);
            const toleratedBefore = toleratedKeys.size;
            const injected = await withFaults({ rate, kind: 'any', random: faultRandom }, faultMs);
            window[1] = Date.now();
            await waitFor(everyAccountOwned, ttl * 10 + 60000, 'every account owned by a live instance');
            await sleep(ttl * 2);
            return { rate, faultMs, injected, duplicatesSoFar: toleratedKeys.size - toleratedBefore };
        },

        async redisLoading() {
            // Redis restarts and loads its dataset: every command of every instance is answered
            // LOADING for a few seconds, shorter than the heartbeat TTL
            const faultMs = 3000;
            const injected = await withFaults({ rate: 1, kind: 'any' }, faultMs);
            const t0 = Date.now();
            await waitFor(everyAccountOwned, ttl * 10 + 60000, 'every account owned by a live instance');
            return { faultMs, injected, settleMs: Date.now() - t0 };
        },

        async redisFaultsDuringFence() {
            // An instance loses Redis past its heartbeat, and once it has it back the read of who
            // owns its accounts keeps failing for longer than the fence retries it. It has to give
            // every account up rather than resume: a recovery that only logged the failed read
            // once resumed the lease with every account still connected, including the ones
            // another instance had taken meanwhile
            const victim = pickVictim();
            const owned = await ownedBy(victim.id);
            const proxy = workload.redisProxies.get(victim.id);
            const gaveUpBefore = victim.logEntries('serving every account').length;
            proxy.pause();
            await sleep(ttl * 1.5);
            proxy.setFaults({ rate: 1, kind: 'any', only: new Set(['MGET']) });
            proxy.resume();
            await waitFor(
                async () => victim.logEntries('serving every account').length > gaveUpBefore,
                ttl * 10 + 30000,
                'the instance to give its accounts up'
            );
            const injected = proxy.setFaults({ rate: 0 });
            await waitFor(everyAccountOwned, ttl * 10 + 60000, 'every account owned by a live instance');
            await waitFor(async () => (await ownedBy(victim.id)).length > 0, ttl * 10 + 30000, 'the instance to own accounts again');
            return { victim: victim.id, accounts: owned.length, injected };
        },

        async redisCut() {
            // Connections reset: every IMAP worker exits on the reconnect and comes back
            for (const proxy of workload.redisProxies.values()) {
                proxy.cut();
            }
            await sleep(15000);
            return {};
        },

        async partition() {
            // Peers cannot reach one instance; its own traffic and accounts are unaffected
            const victim = pickVictim();
            const proxy = workload.peerProxies.get(victim.id);
            const failedBefore = recorder.failed;
            proxy.pause();
            await sleep(20000);
            proxy.resume();
            proxy.cut();
            return { victim: victim.id, failedRequests: recorder.failed - failedBefore };
        },

        async scale() {
            const added = await workload.addInstance();
            await waitFor(async () => (await ownedBy(added.id)).length > 0, ttl * 6 + 30000, 'the new instance to take accounts');
            await sleep(10000);
            const owned = await ownedBy(added.id);
            await stopExpected(added);
            const stopped = Date.now();
            await waitFor(() => movedAway(owned, added.id), ttl * 4 + 30000, 'the removed instance accounts to move');
            return { added: added.id, took: owned.length, rehomeAfterExitMs: Date.now() - stopped };
        }
    };

    const order = [
        'crash',
        'graceful',
        'freeze',
        'slowPod',
        'slowRedis',
        'slowMailServer',
        'mailDisconnect',
        'partition',
        'scale',
        // Restarts every instance, so the ones after it run on a fresh uptime (see licenseNote())
        'fleetRestart',
        'redisOutage',
        'redisOutageLong',
        'redisCut',
        'redisPartition',
        'redisOverload',
        'redisFaults',
        'redisLoading',
        'redisFaultsDuringFence',
        'crashTwo',
        'crashDuringHandoff'
    ];
    const selected = opts.experiments === 'all' ? order : opts.experiments.split(',');
    const results = [];

    const runExperiment = async name => {
        const failedBefore = recorder.failed;
        const okBefore = recorder.ok;
        const started = Date.now();
        console.log(`-> ${name}`);
        recorder.phase = name;
        let result;
        try {
            result = Object.assign({ name, ok: true }, await EXPERIMENTS[name]());
        } catch (err) {
            result = { name, ok: false, error: err.message };
            violate('experiment failed', { name, error: err.message });
        }
        result.ms = Date.now() - started;
        result.requestsOk = recorder.ok - okBefore;
        result.requestsFailed = recorder.failed - failedBefore;
        results.push(result);
        console.log(`   ${JSON.stringify(result)}`);
        // Let the fleet settle before the next one
        recorder.phase = `after ${name}`;
        await sleep(ttl * 2);
    };

    try {
        for (const name of selected) {
            await runExperiment(name);
        }

        if (opts.mixMinutes > 0) {
            const quick = ['crash', 'graceful', 'freeze', 'slowPod', 'slowRedis', 'mailDisconnect', 'partition', 'scale'];
            const until = Date.now() + opts.mixMinutes * 60000;
            while (Date.now() < until) {
                await runExperiment(quick[Math.floor(random() * quick.length)]);
            }
        }
    } finally {
        running = false;
        await background;
        // After a sync ImapFlow re-enters IDLE only after 15 quiet seconds
        await sleep(25000);
        // A submission whose attempt failed waits out its retry backoff (5 s, 10 s, 20 s, ...) in
        // the delayed set, which is not a lost one
        const drained = await submitQueueDrained(redis, 120000);
        if (!drained) {
            console.error('The submit queue still held jobs two minutes after the traffic stopped');
        }
        clearInterval(checker);
    }
    checkFatal();

    const events = await host.call('reconcile', { since: runStartedAt });
    for (const missing of events.missing) {
        violate('missing', missing);
    }
    for (const duplicate of events.duplicates) {
        reportDuplicate(duplicate);
    }
    const submits = submissionReport(load, workload.capture);
    if (submits.duplicated) {
        violate('submission sent twice', { count: submits.duplicated, tokens: submits.duplicatedTokens });
    }
    if (submits.acceptedNotDelivered) {
        violate('accepted submission not delivered', { count: submits.acceptedNotDelivered, tokens: submits.undelivered });
    }

    const report = {
        options: opts,
        startedAt: startedAt.toISOString(),
        license,
        runSeconds: (Date.now() - runStartedAt) / 1000,
        experiments: results,
        violations,
        maxUnownedMs: maxUnowned,
        webhooks: {
            expected: events.injected,
            latency: summarize(events.latencies),
            missing: events.missing.length,
            duplicates: events.duplicates.length,
            // of those, the ones a fault-everything experiment was allowed to cause
            toleratedDuplicates: toleratedKeys.size
        },
        submits,
        requests: {
            ok: recorder.ok,
            failed: recorder.failed,
            errors: recorder.report().errors,
            byPhase: recorder.failuresByPhase(),
            kinds: recorder.failureSummary()
        },
        failures: recorder.failures
    };
    writeReport(report);
    await workload.cleanup();
    // Keep-alive pools and the like would hold the process open
    process.exit(violations.length ? 1 : 0);
}

/**
 * Waits until the submit queue has nothing waiting, delayed or running
 * @returns {Promise<boolean>} false when it still held jobs at the deadline
 */
async function submitQueueDrained(redis, timeout) {
    const deadline = Date.now() + timeout;
    while (Date.now() < deadline) {
        const [waiting, delayed, active, prioritized] = await Promise.all([
            redis.llen('bull:submit:wait'),
            redis.zcard('bull:submit:delayed'),
            redis.llen('bull:submit:active'),
            redis.zcard('bull:submit:prioritized')
        ]);
        if (!waiting && !delayed && !active && !prioritized) {
            return true;
        }
        await sleep(1000);
    }
    return false;
}

function writeReport(report) {
    fs.mkdirSync(RESULTS_DIR, { recursive: true });
    const name = `${report.startedAt.replace(/[:.]/g, '-')}-chaos-n${report.options.instances}-seed${report.options.seed}${report.options.label ? `-${report.options.label}` : ''}`;
    fs.writeFileSync(path.join(RESULTS_DIR, `${name}.json`), JSON.stringify(report, null, 2));
    const lines = [
        `# Chaos run: ${report.options.instances} instances, ${report.options.accounts} accounts, TTL ${report.options.ttl}, seed ${report.options.seed}`,
        '',
        `Ran ${report.runSeconds}s. ${report.violations.length} invariant violations. Longest time an account was without a live owner: ${report.maxUnownedMs} ms.`,
        `Webhooks: ${report.webhooks.expected} expected, ${report.webhooks.missing} missing, ${report.webhooks.duplicates} duplicated (${report.webhooks.toleratedDuplicates} tolerated). Submits: ${report.submits.accepted} accepted, ${report.submits.delivered} delivered, ${report.submits.duplicated} sent twice, ${report.submits.acceptedNotDelivered} accepted but not delivered, ${report.submits.deliveredAfterClientError} delivered after the client saw an error.`,
        `Requests: ${report.requests.ok} succeeded, ${report.requests.failed} failed.`,
        `License: ${report.license}.`,
        '',
        '| Experiment | OK | Duration s | Failed requests | Details |',
        '| --- | --- | ---: | ---: | --- |'
    ];
    for (const result of report.experiments) {
        const { name, ok, ms, requestsFailed, requestsOk, ...details } = result; // eslint-disable-line no-unused-vars
        lines.push(`| ${name} | ${ok ? 'yes' : 'no'} | ${(ms / 1000).toFixed(1)} | ${requestsFailed} | ${JSON.stringify(details)} |`);
    }
    if (report.requests.kinds.length) {
        lines.push('', '| Failed requests by kind | Phase | Status | Code | Count |', '| --- | --- | --- | --- | ---: |');
        for (const kind of report.requests.kinds) {
            lines.push(`| ${kind.op} | ${kind.phase} | ${kind.status} | ${String(kind.code).slice(0, 80)} | ${kind.count} |`);
        }
    }
    if (report.violations.length) {
        lines.push('', 'Violations:', '');
        for (const violation of report.violations) {
            lines.push(`- ${(violation.at / 1000).toFixed(1)}s ${violation.kind}: ${JSON.stringify(violation)}`);
        }
    }
    const md = lines.join('\n') + '\n';
    fs.writeFileSync(path.join(RESULTS_DIR, `${name}.md`), md);
    console.log(md);
}

main().catch(err => {
    console.error(err);
    process.exit(1);
});
