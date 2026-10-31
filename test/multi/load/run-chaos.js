#!/usr/bin/env node
'use strict';

// Chaos runner for the multi-instance setup (npm run test:chaos). Runs a fleet under steady
// background traffic (API reads, new messages, submissions) and puts it through failures one after
// another while an invariant checker watches:
//
//   - no message is announced twice, ever (checked every two seconds)
//   - no account goes without a live owner for longer than the failover allows
//   - no instance exits unless the runner made it
//   - at the end, every message that arrived during the run was announced
//
// Every instance's Redis and cluster port go through TCP proxies, so Redis can be slowed or cut and
// an instance can be partitioned from its peers without Docker.
//
//   npm run test:chaos -- --experiments all --mix-minutes 10 --seed 7
//
// Options: --instances N --accounts N --servers N --ttl DURATION --experiments LIST|all
// --mix-minutes N (a seeded random schedule after the experiments) --seed N --label TEXT

process.env.NODE_ENV = process.env.NODE_ENV || 'test';

const fs = require('node:fs');
const path = require('node:path');

const { setupWorkload, traffic, submissionReport, Recorder, sleep } = require('./workload');
const { summarize } = require('./metrics');

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
    const opts = { instances: 3, accounts: 120, servers: 40, ttl: '6s', experiments: 'all', mixMinutes: 0, seed: 1, label: '' };
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

// Small seeded generator so a failing schedule can be replayed
function seededRandom(seed) {
    let state = seed >>> 0 || 1;
    return () => {
        state = (state * 1664525 + 1013904223) >>> 0;
        return state / 2 ** 32;
    };
}

async function main() {
    const opts = parseArgs(process.argv.slice(2));
    const ttl = getDuration(opts.ttl);
    const random = seededRandom(opts.seed);
    const startedAt = new Date();
    console.log(`chaos: instances=${opts.instances} accounts=${opts.accounts} ttl=${opts.ttl} seed=${opts.seed}`);

    const workload = await setupWorkload({
        instances: opts.instances,
        accounts: opts.accounts,
        servers: opts.servers,
        ttl: opts.ttl,
        seed: true,
        redisProxies: true,
        peerProxies: true,
        prefix: 'chaos'
    });
    const { fleet, host, redis, accounts } = workload;
    console.log(`${accounts.length} accounts connected in ${workload.connectSeconds}s, logs in ${fleet.logDir}`);

    const runStartedAt = Date.now();
    const recorder = new Recorder();
    let running = true;
    const load = traffic(workload, recorder, () => running);
    const background = Promise.all([load.readers(4), load.events(2), load.submits(1)]);

    // Exits the runner caused; anything else is a violation
    const expectedExits = new Set();
    const violations = [];
    const violate = (kind, details) => {
        violations.push(Object.assign({ at: Date.now() - runStartedAt, kind }, details));
        console.error(`VIOLATION ${kind}`, JSON.stringify(details));
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
            if (events.duplicates.length) {
                for (const duplicate of events.duplicates) {
                    if (!violations.some(v => v.kind === 'duplicate' && v.token === duplicate.token && v.account === duplicate.account)) {
                        violate('duplicate', duplicate);
                    }
                }
            }

            const ids = await redis.smembers('cluster:instances');
            const live = new Set();
            for (const id of ids) {
                if (await redis.exists(`cluster:inst:${id}`)) {
                    live.add(id);
                }
            }
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
        const ids = await redis.smembers('cluster:instances');
        const live = new Set();
        for (const member of ids) {
            if (await redis.exists(`cluster:inst:${member}`)) {
                live.add(member);
            }
        }
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
            // Every instance loses Redis for longer than its heartbeat; each fences and rejoins
            for (const proxy of workload.redisProxies.values()) {
                proxy.pause();
            }
            await sleep(ttl * 1.5);
            for (const proxy of workload.redisProxies.values()) {
                proxy.resume();
            }
            const t0 = Date.now();
            await waitFor(
                async () =>
                    (await workload.refreshOwners()) &&
                    fleet.instances.every(
                        instance =>
                            !instance.running || instance.logEntries('Rejoined the cluster').length > 0 || instance.logEntries('Joined the cluster').length > 1
                    ),
                ttl * 6 + 60000,
                'every instance to rejoin'
            );
            return { pausedMs: ttl * 1.5, rejoinMs: Date.now() - t0 };
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

    const order = ['crash', 'graceful', 'freeze', 'slowPod', 'slowRedis', 'slowMailServer', 'mailDisconnect', 'partition', 'scale', 'redisOutage', 'redisCut'];
    const selected = opts.experiments === 'all' ? order : opts.experiments.split(',');
    const results = [];

    const runExperiment = async name => {
        const failedBefore = recorder.failed;
        const okBefore = recorder.ok;
        const started = Date.now();
        console.log(`-> ${name}`);
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
        clearInterval(checker);
    }

    const events = await host.call('reconcile', { since: runStartedAt });
    for (const missing of events.missing) {
        violate('missing', missing);
    }
    for (const duplicate of events.duplicates) {
        if (!violations.some(v => v.kind === 'duplicate' && v.token === duplicate.token && v.account === duplicate.account)) {
            violate('duplicate', duplicate);
        }
    }
    const submits = submissionReport(load, workload.capture);
    if (submits.duplicated) {
        violate('submission sent twice', { count: submits.duplicated });
    }
    if (submits.acceptedNotDelivered) {
        violate('accepted submission not delivered', { count: submits.acceptedNotDelivered });
    }

    const report = {
        options: opts,
        startedAt: startedAt.toISOString(),
        runSeconds: (Date.now() - runStartedAt) / 1000,
        experiments: results,
        violations,
        maxUnownedMs: maxUnowned,
        webhooks: { expected: events.injected, latency: summarize(events.latencies), missing: events.missing.length, duplicates: events.duplicates.length },
        submits,
        requests: { ok: recorder.ok, failed: recorder.failed, errors: recorder.report().errors },
        failures: recorder.failures
    };
    writeReport(report);
    await workload.cleanup();
    // Keep-alive pools and the like would hold the process open
    process.exit(violations.length ? 1 : 0);
}

function writeReport(report) {
    fs.mkdirSync(RESULTS_DIR, { recursive: true });
    const name = `${report.startedAt.replace(/[:.]/g, '-')}-chaos-n${report.options.instances}-seed${report.options.seed}${report.options.label ? `-${report.options.label}` : ''}`;
    fs.writeFileSync(path.join(RESULTS_DIR, `${name}.json`), JSON.stringify(report, null, 2));
    const lines = [
        `# Chaos run: ${report.options.instances} instances, ${report.options.accounts} accounts, TTL ${report.options.ttl}, seed ${report.options.seed}`,
        '',
        `Ran ${report.runSeconds}s. ${report.violations.length} invariant violations. Longest time an account was without a live owner: ${report.maxUnownedMs} ms.`,
        `Webhooks: ${report.webhooks.expected} expected, ${report.webhooks.missing} missing, ${report.webhooks.duplicates} duplicated. Submits: ${report.submits.accepted} accepted, ${report.submits.delivered} delivered, ${report.submits.duplicated} sent twice, ${report.submits.acceptedNotDelivered} accepted but not delivered, ${report.submits.deliveredAfterClientError} delivered after the client saw an error.`,
        `Requests: ${report.requests.ok} succeeded, ${report.requests.failed} failed.`,
        '',
        '| Experiment | OK | Duration s | Failed requests | Details |',
        '| --- | --- | ---: | ---: | --- |'
    ];
    for (const result of report.experiments) {
        const { name, ok, ms, requestsFailed, requestsOk, ...details } = result; // eslint-disable-line no-unused-vars
        lines.push(`| ${name} | ${ok ? 'yes' : 'no'} | ${(ms / 1000).toFixed(1)} | ${requestsFailed} | ${JSON.stringify(details)} |`);
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
