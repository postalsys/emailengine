'use strict';

// What the load runner (run-load.js) and the chaos runner (run-chaos.js) share: a fleet of
// EmailEngine processes with registered, connected accounts against the ImapKit farm, optional TCP
// proxies in front of each instance's Redis and cluster port, and the background traffic (API reads,
// new messages, submissions) with its recorder.

const Redis = require('ioredis');

const { startFleet, REDIS_URL } = require('../../helpers/instance-fleet');
const { startLatencyProxy } = require('../../helpers/latency-proxy');
const { IDLE_SETTLE, accountPayload, readOwners, redisProxyFor } = require('../../helpers/fleet-scenario');
const { startCaptureSmtp } = require('../../helpers/capture-smtp');
const { startHarnessHost } = require('./harness-client');
const { mapConcurrent } = require('../../../lib/utils/map-concurrent');
const { summarize } = require('./metrics');

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

/**
 * What the report says about licensing, printed as a warning when the fleet runs without one.
 * Without a license an API worker answers every API request with a bare 500 once its periodic
 * license check (TLS_RENEW_CHECK_INTERVAL, ten minutes) has run, so an instance that lives longer
 * than that fails all of its traffic for a reason that has nothing to do with the cluster.
 * EENGINE_PREPARED_LICENSE in the environment reaches every instance
 * @param {boolean} licensed - What the fleet itself reports (setupWorkload() asks /v1/license)
 * @returns {string} The line for the report
 */
function licenseNote(licensed) {
    if (licensed) {
        return 'active';
    }
    const note = 'none: an instance running longer than 10 minutes answers every API request with 500, keep runs shorter or set EENGINE_PREPARED_LICENSE';
    console.warn(`WARNING license ${note}`);
    return note;
}

const ATTACHMENT = Buffer.alloc(200 * 1024, 'x');

function seedMessage() {
    const boundary = 'b-load';
    return [
        'From: Sender <sender@example.com>',
        'To: Recipient <recipient@example.com>',
        'Subject: {{SUBJECT}}',
        `Message-ID: <${Date.now()}.${Math.random().toString(36).slice(2)}@load.test>`,
        `Date: ${new Date().toUTCString()}`,
        'MIME-Version: 1.0',
        `Content-Type: multipart/mixed; boundary="${boundary}"`,
        '',
        `--${boundary}`,
        'Content-Type: text/plain; charset=utf-8',
        '',
        'Seed message for the read traffic. '.repeat(40),
        `--${boundary}`,
        'Content-Type: application/octet-stream; name="data.bin"',
        'Content-Disposition: attachment; filename="data.bin"',
        'Content-Transfer-Encoding: base64',
        '',
        ATTACHMENT.toString('base64').replace(/.{76}/g, '$&\r\n'),
        `--${boundary}--`,
        ''
    ].join('\r\n');
}

function safeJson(text) {
    try {
        return JSON.parse(text);
    } catch (err) {
        return null;
    }
}

class Recorder {
    constructor() {
        this.samples = new Map();
        this.ok = 0;
        this.failed = 0;
        this.failures = [];
        this.failureGroups = new Map();
        this.phase = 'run';
        this.startedAt = Date.now();
    }

    /**
     * A failed request, counted by kind (operation, hop, status, error code and phase) and kept in
     * detail for the report: a few samples of every kind, so a rare kind is not crowded out by a
     * common one
     * @param {Object} details - `{ op, hop, status, ... }`
     */
    fail(details) {
        this.failed++;
        let code = details.error || '';
        const body = typeof details.body === 'string' ? safeJson(details.body) : details.body;
        if (body && typeof body === 'object') {
            code = body.code || body.error || code;
        }
        const key = `${details.op}\t${details.hop}\t${details.status}\t${code}\t${this.phase}`;
        const group = this.failureGroups.get(key) || { op: details.op, hop: details.hop, status: details.status, code, phase: this.phase, count: 0 };
        group.count++;
        this.failureGroups.set(key, group);
        if (group.count <= 3 && this.failures.length < 2000) {
            this.failures.push(Object.assign({ at: Date.now() - this.startedAt, phase: this.phase }, details));
        }
    }

    /** Failure kinds by phase, most frequent first */
    failureSummary() {
        return [...this.failureGroups.values()].sort((a, b) => b.count - a.count);
    }

    /** Failed requests per phase */
    failuresByPhase() {
        const phases = {};
        for (const group of this.failureGroups.values()) {
            phases[group.phase] = (phases[group.phase] || 0) + group.count;
        }
        return phases;
    }

    /** A request that succeeded, with its latency */
    record(op, hop, ms) {
        this.ok++;
        const key = `${op}\t${hop}`;
        if (!this.samples.has(key)) {
            this.samples.set(key, []);
        }
        this.samples.get(key).push(ms);
    }

    report() {
        const rows = [];
        for (const [key, samples] of this.samples) {
            const [op, hop] = key.split('\t');
            rows.push(Object.assign({ op, hop }, summarize(samples)));
        }
        rows.sort((a, b) => (a.op === b.op ? a.hop.localeCompare(b.hop) : a.op.localeCompare(b.op)));
        // Failures by operation, hop and status, whatever their code and phase
        const errors = new Map();
        for (const { op, hop, status, count } of this.failureGroups.values()) {
            const key = `${op}\t${hop}\t${status}`;
            const entry = errors.get(key) || { op, hop, status, count: 0 };
            entry.count += count;
            errors.set(key, entry);
        }
        return { rows, errors: [...errors.values()] };
    }
}

/**
 * Starts the farm, the fleet and the accounts
 * @param {Object} opts
 * @param {number} opts.instances
 * @param {number} opts.accounts
 * @param {number} opts.servers - ImapKit servers
 * @param {number} [opts.imapWorkers]
 * @param {string} [opts.ttl] - Cluster heartbeat TTL
 * @param {number} [opts.hopDelay] - Milliseconds added in each direction on cluster calls
 * @param {boolean} [opts.peerProxies] - Put every cluster port behind a proxy (for partitions)
 * @param {boolean} [opts.redisProxies] - Put every instance's Redis behind its own proxy
 * @param {boolean} [opts.seed] - Inject a message with an attachment and learn its ids per account
 * @param {string} [opts.prefix] - Account id prefix
 */
async function setupWorkload(opts) {
    const accounts = Array.from({ length: opts.accounts }, (_, i) => `${opts.prefix || 'load'}${String(i).padStart(5, '0')}`);
    const host = startHarnessHost();
    const { webhookUrl, imap } = await host.call('start', { accounts, servers: opts.servers });
    const capture = await startCaptureSmtp();
    const redis = new Redis(REDIS_URL);
    const peerProxies = new Map();
    const redisProxies = new Map();

    const prepareInstance = async instance => {
        if (opts.hopDelay > 0 || opts.peerProxies) {
            const proxy = await startLatencyProxy({ port: instance.clusterPort, delay: opts.hopDelay || 0 });
            peerProxies.set(instance.id, proxy);
            instance.clusterAddress = `127.0.0.1:${proxy.port}`;
        }
        if (opts.redisProxies) {
            // The chaos runs slow, cut and fail Redis calls through it
            redisProxies.set(instance.id, await redisProxyFor(instance));
        }
    };

    const fleet = await startFleet({
        size: opts.instances,
        webhookUrl,
        imapWorkers: opts.imapWorkers || 2,
        heartbeatTtl: opts.ttl || '10s',
        logLevel: opts.logLevel || 'warn',
        prepare: async created => {
            for (const instance of created.instances) {
                await prepareInstance(instance);
            }
        }
    });

    const workload = {
        fleet,
        host,
        capture,
        redis,
        accounts,
        targets: new Map(),
        peerProxies,
        redisProxies,
        prepareInstance,
        ownerMap: new Map(),
        ownerTimer: null,

        async refreshOwners() {
            workload.ownerMap = await readOwners(redis, accounts);
            return workload.ownerMap;
        },

        /** Adds an instance to the fleet, routed through proxies like the others, and starts it */
        async addInstance() {
            const instance = fleet.add();
            await prepareInstance(instance);
            await instance.start();
            await instance.waitReady();
            return instance;
        },

        /** Takes an instance out of rotation, as a load balancer would, then SIGTERMs it */
        async drainAndStop(instance, grace = 2000) {
            instance.outOfRotation = true;
            await sleep(grace);
            await instance.stop();
        },

        async cleanup() {
            clearInterval(workload.ownerTimer);
            await fleet.stopAll().catch(() => false);
            await host.stop().catch(() => false);
            await capture.close().catch(() => false);
            for (const proxy of [...peerProxies.values(), ...redisProxies.values()]) {
                await proxy.stop().catch(() => false);
            }
            await redis.quit().catch(() => false);
        }
    };

    try {
        // Registered through every instance, as a load balancer would spread them
        let created = 0;
        await mapConcurrent(accounts, 16, async account => {
            const instance = fleet.pick(created++);
            const res = await instance.request('POST', '/v1/account', accountPayload(account, imap[account], { smtpPort: capture.port }));
            if (res.status !== 200) {
                throw new Error(`Creating ${account}: ${res.status} ${JSON.stringify(res.body)}`);
            }
        });

        // Asked of the fleet rather than read off this process, so a license from any source counts
        const license = await fleet.instances[0].request('GET', '/v1/license');
        workload.licensed = !!(license.body && license.body.active);

        const connectStarted = Date.now();
        for (;;) {
            const res = await fleet.instances[0].request('GET', '/v1/stats');
            const connected = (res.body.connections && res.body.connections.connected) || 0;
            if (connected >= accounts.length) {
                break;
            }
            if (Date.now() - connectStarted > 10 * 60 * 1000) {
                throw new Error(`Only ${connected} of ${accounts.length} accounts connected`);
            }
            await sleep(1000);
        }
        workload.connectSeconds = (Date.now() - connectStarted) / 1000;

        await sleep(IDLE_SETTLE);

        if (opts.seed) {
            const seeded = new Set();
            for (let i = 0; i < accounts.length; i++) {
                const serverIndex = i % opts.servers;
                if (!seeded.has(serverIndex)) {
                    seeded.add(serverIndex);
                    await host.call('inject', { account: accounts[i], raw: seedMessage(), label: 'Seed' });
                }
            }
            await mapConcurrent(accounts, 32, async account => {
                for (let attempt = 0; attempt < 120; attempt++) {
                    const res = await fleet.pick(attempt).request('GET', `/v1/account/${account}/messages?path=INBOX&pageSize=5`);
                    const message = res.status === 200 && res.body.messages.find(entry => entry.attachments && entry.attachments.length);
                    if (message) {
                        workload.targets.set(account, { id: message.id, text: message.text.id, attachment: message.attachments[0].id });
                        return;
                    }
                    await sleep(500);
                }
                throw new Error(`No seed message for ${account}`);
            });
        }

        // Owners refreshed while traffic runs, so a request is classified by where the account was
        // served when it was sent
        await workload.refreshOwners();
        workload.ownerTimer = setInterval(() => workload.refreshOwners().catch(() => false), 1000);
    } catch (err) {
        await workload.cleanup();
        throw err;
    }

    return workload;
}

const READ_OPS = [
    { op: 'mailboxes', weight: 20, path: account => `/v1/account/${account}/mailboxes` },
    { op: 'listMessages', weight: 25, path: account => `/v1/account/${account}/messages?path=INBOX&pageSize=20` },
    { op: 'getMessage', weight: 25, path: (account, t) => `/v1/account/${account}/message/${t.id}` },
    { op: 'getText', weight: 15, path: (account, t) => `/v1/account/${account}/text/${t.text}?textType=*` },
    { op: 'attachment', weight: 15, path: (account, t) => `/v1/account/${account}/attachment/${t.attachment}`, raw: true }
];
const TOTAL_WEIGHT = READ_OPS.reduce((sum, entry) => sum + entry.weight, 0);

function pickReadOp() {
    let roll = Math.random() * TOTAL_WEIGHT;
    for (const entry of READ_OPS) {
        roll -= entry.weight;
        if (roll < 0) {
            return entry;
        }
    }
    return READ_OPS[0];
}

const randomAccount = accounts => accounts[Math.floor(Math.random() * accounts.length)];

/**
 * Background traffic against a workload until `running()` turns false
 * @returns {Object} `{ readers(concurrency), events(rate), submits(perSecond) }`, each resolving when it stops
 */
function traffic(workload, recorder, running) {
    const { fleet, accounts, host } = workload;
    const hopOf = (account, instance) => (workload.ownerMap.get(account) === instance.id ? 'local' : 'forwarded');

    return {
        submitted: 0,
        // Every submission's token, and whether the API accepted it. A request that timed out on the
        // client can still have been queued, so delivery is checked per token
        submissions: new Map(),

        async readers(concurrency) {
            let seq = 0;
            await Promise.all(
                Array.from({ length: concurrency }, async () => {
                    while (running()) {
                        const account = randomAccount(accounts);
                        const entry = pickReadOp();
                        let instance;
                        try {
                            instance = fleet.pick(seq++);
                        } catch (err) {
                            await sleep(100);
                            continue;
                        }
                        const hop = hopOf(account, instance);
                        try {
                            const res = await instance.request('GET', entry.path(account, workload.targets.get(account)), null, {
                                raw: entry.raw,
                                timeout: 30000
                            });
                            const truncated = entry.raw && res.status === 200 && res.body.length !== ATTACHMENT.length;
                            if (res.status === 200 && !truncated) {
                                recorder.record(entry.op, hop, res.ms);
                            } else {
                                const body = Buffer.isBuffer(res.body) ? res.body.toString().slice(0, 200) : res.body;
                                recorder.fail({
                                    op: entry.op,
                                    hop,
                                    account,
                                    instance: instance.id,
                                    owner: workload.ownerMap.get(account),
                                    status: truncated ? 'truncated' : res.status,
                                    body,
                                    headers: res.status >= 500 ? res.headers : undefined
                                });
                            }
                        } catch (err) {
                            const status = err.name === 'TimeoutError' ? 'timeout' : 'network';
                            recorder.fail({
                                op: entry.op,
                                hop,
                                account,
                                instance: instance.id,
                                owner: workload.ownerMap.get(account),
                                status,
                                error: err.message
                            });
                        }
                    }
                })
            );
        },

        async events(rate) {
            const interval = 1000 / rate;
            let next = Date.now();
            while (running()) {
                host.call('inject', { account: randomAccount(accounts), label: 'Load event' }).catch(err => console.error('inject failed', err.message));
                next += interval;
                await sleep(Math.max(0, next - Date.now()));
            }
        },

        async submits(perSecond = 1) {
            let seq = 0;
            while (running()) {
                const account = randomAccount(accounts);
                let instance;
                try {
                    instance = fleet.pick(seq++);
                } catch (err) {
                    await sleep(100);
                    continue;
                }
                const hop = hopOf(account, instance);
                const token = Math.random().toString(36).slice(2, 12);
                this.submissions.set(token, false);
                try {
                    const res = await instance.request('POST', `/v1/account/${account}/submit`, {
                        from: { address: `${account}@example.com` },
                        to: [{ address: 'recipient@example.com' }],
                        subject: `Load submit ${token}`,
                        text: 'Load'
                    });
                    if (res.status === 200) {
                        recorder.record('submit', hop, res.ms);
                        this.submitted++;
                        this.submissions.set(token, true);
                    } else {
                        recorder.fail({ op: 'submit', hop, account, instance: instance.id, status: res.status, body: res.body });
                    }
                } catch (err) {
                    recorder.fail({ op: 'submit', hop, account, instance: instance.id, status: 'network', error: err.message });
                }
                await sleep(1000 / perSecond);
            }
        }
    };
}

/**
 * What the capture SMTP server received of the traffic's submissions
 * @returns {{ accepted: number, delivered: number, duplicated: number, acceptedNotDelivered: number, deliveredAfterClientError: number, undelivered: string[], duplicatedTokens: string[] }}
 */
function submissionReport(load, capture) {
    const counts = new Map();
    for (const entry of capture.received) {
        const match = /Load submit ([a-z0-9]+)/.exec(entry.raw);
        if (match) {
            counts.set(match[1], (counts.get(match[1]) || 0) + 1);
        }
    }
    let duplicated = 0;
    let acceptedNotDelivered = 0;
    let deliveredAfterClientError = 0;
    // Named, so a lost one can be looked up in the instance logs by its subject
    const undelivered = [];
    const duplicatedTokens = [];
    for (const [token, accepted] of load.submissions) {
        const delivered = counts.get(token) || 0;
        if (delivered > 1) {
            duplicated++;
            duplicatedTokens.push(token);
        }
        if (accepted && !delivered) {
            acceptedNotDelivered++;
            undelivered.push(token);
        }
        if (!accepted && delivered) {
            deliveredAfterClientError++;
        }
    }
    return { accepted: load.submitted, delivered: counts.size, duplicated, acceptedNotDelivered, deliveredAfterClientError, undelivered, duplicatedTokens };
}

module.exports = {
    licenseNote,
    setupWorkload,
    traffic,
    submissionReport,
    Recorder,
    ATTACHMENT,
    sleep
};
