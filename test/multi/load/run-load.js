#!/usr/bin/env node
'use strict';

// Load runner for the multi-instance setup (npm run test:load). Boots a fleet of EmailEngine
// processes against an ImapKit farm in a separate process, registers the accounts, drives a load
// profile and writes a report to test/multi/results/.
//
//   npm run test:load -- --profile read --instances 3 --accounts 600
//
// Profiles:
//   read       API reads over every account: mailboxes, message lists, a message, its text, a 200 KB
//              attachment. Every request goes to a random instance, so roughly (N-1)/N of them are
//              forwarded to the owner; local and forwarded latencies are reported apart
//   events     new messages injected at --rate per second; webhook latency and exactly-once
//   mixed      read at half concurrency, events, and a message submitted every second
//   rebalance  mixed, while an instance is added at a third of the run and drained and stopped at
//              two thirds
//
// Options: --instances N --accounts N --servers N (ImapKit servers) --duration S --concurrency N
// --rate N --hop-delay MS (added in each direction on every cluster call, through a TCP proxy)
// --ttl DURATION --imap-workers N --label TEXT
//
// The run fails (exit code 1) when a webhook was delivered twice or not at all.

process.env.NODE_ENV = process.env.NODE_ENV || 'test';

const fs = require('node:fs');
const path = require('node:path');
const { fetch } = require('undici');

const { ACCESS_TOKEN, dispatcher } = require('../../helpers/instance-fleet');
const { setupWorkload, traffic, submissionReport, Recorder, sleep, licenseNote } = require('./workload');
const { summarize, parsePrometheus } = require('./metrics');

const RESULTS_DIR = path.join(__dirname, '..', 'results');

function parseArgs(argv) {
    const opts = {
        profile: 'read',
        instances: 3,
        accounts: 300,
        servers: 0,
        duration: 60,
        concurrency: 32,
        rate: 10,
        hopDelay: 0,
        ttl: '10s',
        imapWorkers: 2,
        label: ''
    };
    for (let i = 0; i < argv.length; i++) {
        const key = argv[i].replace(/^--/, '').replace(/-([a-z])/g, (m, c) => c.toUpperCase());
        if (!(key in opts)) {
            throw new Error(`Unknown option ${argv[i]}`);
        }
        opts[key] = typeof opts[key] === 'number' ? Number(argv[i + 1]) : argv[i + 1];
        i++;
    }
    if (!opts.servers) {
        opts.servers = Math.max(1, Math.ceil(opts.accounts / 20));
    }
    return opts;
}

async function instanceMetrics(instance) {
    try {
        const res = await fetch(`${instance.apiUrl}/metrics`, { dispatcher, headers: { Authorization: `Bearer ${ACCESS_TOKEN}` } });
        return parsePrometheus(await res.text(), ['process_cpu_seconds_total', 'process_resident_memory_bytes']);
    } catch (err) {
        return {};
    }
}

async function redisCommands(redis) {
    const info = await redis.info('stats');
    const match = /total_commands_processed:(\d+)/.exec(info);
    return match ? Number(match[1]) : 0;
}

async function snapshot(workload) {
    return {
        at: Date.now(),
        host: await workload.host.call('usage'),
        redis: await redisCommands(workload.redis),
        metrics: new Map(await Promise.all(workload.fleet.instances.map(async instance => [instance.id, await instanceMetrics(instance)])))
    };
}

async function main() {
    const opts = parseArgs(process.argv.slice(2));
    const startedAt = new Date();
    console.log(`profile=${opts.profile} instances=${opts.instances} accounts=${opts.accounts} servers=${opts.servers} hopDelay=${opts.hopDelay}ms`);

    const workload = await setupWorkload(Object.assign({}, opts, { seed: opts.profile !== 'events' }));
    console.log(`${opts.accounts} accounts connected in ${workload.connectSeconds}s, logs in ${workload.fleet.logDir}`);
    const license = licenseNote(workload.licensed);

    try {
        const recorder = new Recorder();
        const deadline = Date.now() + opts.duration * 1000;
        const load = traffic(workload, recorder, () => Date.now() < deadline);
        const actions = [];
        const before = await snapshot(workload);
        const loadStartedAt = Date.now();
        const act = action => actions.push({ at: Date.now() - loadStartedAt, action });

        const rebalance = async () => {
            await sleep((opts.duration * 1000) / 3);
            act('start a new instance');
            const added = await workload.addInstance();
            act(`${added.id} ready`);
            await sleep(Math.max(0, deadline - (opts.duration * 1000) / 3 - Date.now()));
            act(`${added.id} out of rotation, SIGTERM in 2s`);
            await workload.drainAndStop(added);
            act(`${added.id} exited (${JSON.stringify(added.lastExit)})`);
        };

        // Owner changes over the run, counted from the owner snapshots
        let moves = 0;
        let previousOwners = new Map(workload.ownerMap);
        const moveTimer = setInterval(() => {
            for (const [account, owner] of workload.ownerMap) {
                if (previousOwners.get(account) && owner && previousOwners.get(account) !== owner) {
                    moves++;
                }
            }
            previousOwners = new Map(workload.ownerMap);
        }, 1000);

        const half = Math.max(1, Math.floor(opts.concurrency / 2));
        const profiles = {
            read: () => [load.readers(opts.concurrency)],
            events: () => [load.events(opts.rate)],
            mixed: () => [load.readers(half), load.events(opts.rate), load.submits()],
            rebalance: () => [load.readers(half), load.events(opts.rate), load.submits(), rebalance()]
        };
        if (!profiles[opts.profile]) {
            throw new Error(`Unknown profile ${opts.profile}`);
        }
        await Promise.all(profiles[opts.profile]());
        const loadSeconds = (Date.now() - loadStartedAt) / 1000;
        const after = await snapshot(workload);

        // Webhooks still on their way. After a sync ImapFlow re-enters IDLE only after 15 quiet
        // seconds, so a message that arrived in that window is noticed up to 15 seconds late
        await sleep(20000);
        clearInterval(moveTimer);

        const events = await workload.host.call('reconcile', { since: loadStartedAt });
        const sessions = await workload.host.call('sessionsPerAccount', { accounts: workload.accounts });
        const seconds = (after.at - before.at) / 1000;
        const hostCpu = usage => usage.cpu.user + usage.cpu.system;

        const report = {
            options: opts,
            startedAt: startedAt.toISOString(),
            node: process.version,
            connectSeconds: workload.connectSeconds,
            loadSeconds,
            requests: recorder.report(),
            throughput: Math.round(recorder.ok / loadSeconds),
            webhooks: {
                injectedRecipients: events.injected,
                latency: summarize(events.latencies),
                duplicates: events.duplicates.length,
                missing: events.missing.length
            },
            submits: submissionReport(load, workload.capture),
            // Under load one instance opens a second session per account for fetches, so this is
            // informational; the multi tier checks one session per account while idle
            maxSessionsPerAccount: Math.max(0, ...Object.values(sessions)),
            accountMoves: moves,
            actions,
            failures: recorder.failures,
            license,
            redisCommandsPerSecond: Math.round((after.redis - before.redis) / seconds),
            // The farm and ledger process: near 100 means the harness, not EmailEngine, set the pace
            harnessCpuPercent: Math.round(((hostCpu(after.host) - hostCpu(before.host)) / 1e6 / seconds) * 100),
            instances: workload.fleet.instances.map(instance => {
                const start = before.metrics.get(instance.id) || {};
                const end = after.metrics.get(instance.id) || {};
                return {
                    id: instance.id,
                    cpuPercent:
                        start.process_cpu_seconds_total !== undefined && end.process_cpu_seconds_total !== undefined
                            ? Math.round(((end.process_cpu_seconds_total - start.process_cpu_seconds_total) / seconds) * 100)
                            : null,
                    rssMb: end.process_resident_memory_bytes ? Math.round(end.process_resident_memory_bytes / 1048576) : null
                };
            })
        };

        writeReport(report);
        process.exitCode = report.webhooks.duplicates || report.webhooks.missing || report.submits.duplicated || report.submits.acceptedNotDelivered ? 1 : 0;
    } finally {
        await workload.cleanup();
    }
}

function markdown(report) {
    const o = report.options;
    const lines = [
        `# Load run: ${o.profile}, ${o.instances} instance(s), ${o.accounts} accounts${o.hopDelay ? `, ${o.hopDelay} ms hop delay` : ''}`,
        '',
        `Started ${report.startedAt}, Node ${report.node}. Accounts connected in ${report.connectSeconds}s. Load ran ${report.loadSeconds}s at ${report.throughput} successful requests per second.`,
        ''
    ];
    if (report.requests.rows.length) {
        lines.push('| Operation | Hop | Count | p50 ms | p90 ms | p99 ms | max ms |', '| --- | --- | ---: | ---: | ---: | ---: | ---: |');
        for (const row of report.requests.rows) {
            lines.push(`| ${row.op} | ${row.hop} | ${row.count} | ${row.p50} | ${row.p90} | ${row.p99} | ${row.max} |`);
        }
        lines.push('');
    }
    if (report.requests.errors.length) {
        lines.push('| Operation | Hop | Status | Count |', '| --- | --- | --- | ---: |');
        for (const error of report.requests.errors) {
            lines.push(`| ${error.op} | ${error.hop} | ${error.status} | ${error.count} |`);
        }
        lines.push('');
    }
    const w = report.webhooks;
    lines.push(
        `Webhooks: ${w.injectedRecipients} expected, ${w.missing} missing, ${w.duplicates} duplicated. Latency p50 ${w.latency.p50} ms, p99 ${w.latency.p99} ms, max ${w.latency.max} ms.`,
        `Submits: ${report.submits.accepted} accepted, ${report.submits.delivered} delivered, ${report.submits.duplicated} sent twice. Most IMAP sessions of one account at the end: ${report.maxSessionsPerAccount}. Owner changes seen: ${report.accountMoves}.`,
        `Redis: ${report.redisCommandsPerSecond} commands per second. Harness process CPU: ${report.harnessCpuPercent}%.`,
        '',
        '| Instance | CPU % | RSS MB |',
        '| --- | ---: | ---: |'
    );
    for (const instance of report.instances) {
        lines.push(`| ${instance.id} | ${instance.cpuPercent} | ${instance.rssMb} |`);
    }
    if (report.actions.length) {
        lines.push('', 'Actions:', '');
        for (const action of report.actions) {
            lines.push(`- ${(action.at / 1000).toFixed(1)}s: ${action.action}`);
        }
    }
    return lines.join('\n') + '\n';
}

function writeReport(report) {
    fs.mkdirSync(RESULTS_DIR, { recursive: true });
    const o = report.options;
    const name = `${report.startedAt.replace(/[:.]/g, '-')}-${o.profile}-n${o.instances}-a${o.accounts}${o.hopDelay ? `-hop${o.hopDelay}` : ''}${o.label ? `-${o.label}` : ''}`;
    fs.writeFileSync(path.join(RESULTS_DIR, `${name}.json`), JSON.stringify(report, null, 2));
    const md = markdown(report);
    fs.writeFileSync(path.join(RESULTS_DIR, `${name}.md`), md);
    console.log(md);
}

main()
    // Keep-alive pools and the like would hold the process open
    .then(() => process.exit(process.exitCode || 0))
    .catch(err => {
        console.error(err);
        process.exit(1);
    });
