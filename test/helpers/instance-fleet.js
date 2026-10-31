'use strict';

// Runs several EmailEngine processes against one Redis, for the multi-instance tier and the load
// and chaos runs (test/multi). Each instance is a real `node server.js` with its own API port,
// cluster port and log file; the fleet can kill, stop, freeze, thaw and restart any of them.
//
// The fleet uses Redis database 15 so it never meets the unit and integration tiers (13) or the
// e2e tier (14), and flushes it before it starts. Instance i listens on BASE_PORT + 10 * i for the
// API and one above that for cluster calls. Processes are SIGKILLed when the test process exits,
// whatever way it exits.

const { spawn } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');
const { fetch, Agent } = require('undici');
const { flushRedis } = require('./flush-redis');
const { waitForServer } = require('./wait-for-server');

const PROJECT_ROOT = path.join(__dirname, '..', '..');

// The prepared "*"-scope token from config/test.toml, applied by every instance on boot
const ACCESS_TOKEN = '2aa97ad0456d6624a55d30780aa2ff61bfb7edc6fa00935b40814b271e718660';

const REDIS_DB = 15;
const REDIS_URL = `redis://127.0.0.1:6379/${REDIS_DB}`;
const BASE_PORT = Number(process.env.EE_FLEET_BASE_PORT) || 7500;

// One keep-alive pool for every request the tests make, so a load run measures EmailEngine
// rather than TCP handshakes
const dispatcher = new Agent({ keepAliveTimeout: 30000, connections: 256 });

const running = new Set();
process.on('exit', () => {
    for (const child of running) {
        try {
            child.kill('SIGKILL');
        } catch (err) {
            // already gone
        }
    }
});

function portIsFree(port) {
    return new Promise(resolve => {
        const socket = net.connect(port, '127.0.0.1');
        socket.setTimeout(500);
        socket.once('connect', () => {
            socket.destroy();
            resolve(false);
        });
        socket.once('timeout', () => {
            socket.destroy();
            resolve(true);
        });
        socket.once('error', () => resolve(true));
    });
}

const flushFleetDatabase = (redisUrl = REDIS_URL) => flushRedis(redisUrl);

class FleetInstance {
    constructor(fleet, index) {
        this.fleet = fleet;
        this.index = index;
        this.id = `ee-${index}`;
        this.apiPort = BASE_PORT + index * 10;
        this.clusterPort = this.apiPort + 1;
        this.apiUrl = `http://127.0.0.1:${this.apiPort}`;
        this.logPath = path.join(fleet.logDir, `${this.id}.log`);
        this.child = null;
        this.frozen = false;
        this.starts = 0;
        // Set by the test to route this instance's Redis traffic through a latency proxy
        this.redisUrl = fleet.redisUrl;
    }

    get pid() {
        return this.child ? this.child.pid : null;
    }

    get running() {
        return !!this.child;
    }

    env() {
        return Object.assign(
            {},
            process.env,
            {
                NODE_ENV: 'test',
                EENGINE_REDIS: this.redisUrl,
                EENGINE_PORT: String(this.apiPort),
                EENGINE_HOST: '127.0.0.1',
                EENGINE_WORKERS: String(this.fleet.imapWorkers),
                EENGINE_INSTANCE_ID: this.id,
                EENGINE_CLUSTER_PORT: String(this.clusterPort),
                EENGINE_CLUSTER_HOST: '127.0.0.1',
                EENGINE_CLUSTER_ADDRESS: this.fleet.clusterAddressFor(this),
                EENGINE_CLUSTER_HEARTBEAT_TTL: this.fleet.heartbeatTtl,
                EENGINE_LOG_LEVEL: this.fleet.logLevel,
                EENGINE_LOG_RAW: 'false',
                EENGINE_SETTINGS: JSON.stringify(this.fleet.settings),
                // Separate disks, as separate pods have: an export file is only on its writer
                EENGINE_EXPORT_PATH: path.join(this.fleet.logDir, `${this.id}-exports`)
            },
            this.fleet.extraEnv,
            this.extraEnv || {}
        );
    }

    async start() {
        if (this.child) {
            return;
        }
        if (!(await portIsFree(this.apiPort)) || !(await portIsFree(this.clusterPort))) {
            throw new Error(`Port ${this.apiPort} or ${this.clusterPort} is in use, stop the process holding it (pkill -x emailengine)`);
        }

        const fd = fs.openSync(this.logPath, 'a');
        const child = spawn(process.execPath, ['server.js'], {
            cwd: PROJECT_ROOT,
            stdio: ['ignore', fd, fd],
            env: this.env()
        });
        fs.closeSync(fd);
        this.child = child;
        this.frozen = false;
        // As a load balancer would: no traffic until the readiness check passes (waitReady())
        this.outOfRotation = true;
        this.starts++;
        running.add(child);
        child.unref();

        child.once('exit', (code, signal) => {
            running.delete(child);
            if (this.child === child) {
                this.child = null;
            }
            this.lastExit = { code, signal, at: Date.now() };
        });
    }

    /** Polls /health until it answers 200, failing fast if the process dies, then takes traffic */
    async waitReady(timeout = 90000) {
        try {
            await waitForServer({ child: this.child, url: `${this.apiUrl}/health`, timeout, quiet: true });
        } catch (err) {
            err.message = `${this.id}: ${err.message}, see ${this.logPath}`;
            throw err;
        }
        this.outOfRotation = false;
    }

    /** Sends a signal and waits for the process to go away */
    async signal(sig, timeout = 20000) {
        const child = this.child;
        if (!child) {
            return;
        }
        if (this.frozen && sig !== 'SIGKILL') {
            this.thaw();
        }
        const exited = new Promise(resolve => child.once('exit', resolve));
        child.kill(sig);
        const timer = new Promise(resolve => setTimeout(() => resolve('timeout'), timeout));
        if ((await Promise.race([exited, timer])) === 'timeout') {
            child.kill('SIGKILL');
            await exited;
        }
    }

    kill() {
        return this.signal('SIGKILL');
    }

    stop() {
        return this.signal('SIGTERM');
    }

    freeze() {
        if (this.child && !this.frozen) {
            this.child.kill('SIGSTOP');
            this.frozen = true;
        }
    }

    thaw() {
        if (this.child && this.frozen) {
            this.child.kill('SIGCONT');
            this.frozen = false;
        }
    }

    async restart() {
        await this.stop();
        await this.start();
        await this.waitReady();
    }

    /**
     * Calls the REST API on this instance
     * @returns {Promise<{status: number, body: *, headers: Object, ms: number}>}
     */
    async request(method, urlPath, body, { timeout = 30000, raw = false } = {}) {
        const started = performance.now();
        const res = await fetch(`${this.apiUrl}${urlPath}`, {
            method,
            dispatcher,
            headers: Object.assign({ Authorization: `Bearer ${ACCESS_TOKEN}` }, body ? { 'Content-Type': 'application/json' } : {}),
            body: body ? JSON.stringify(body) : undefined,
            signal: AbortSignal.timeout(timeout)
        });
        let payload;
        if (raw) {
            payload = Buffer.from(await res.arrayBuffer());
        } else {
            const text = await res.text();
            try {
                payload = text ? JSON.parse(text) : null;
            } catch (err) {
                payload = text;
            }
        }
        return { status: res.status, body: payload, headers: Object.fromEntries(res.headers), ms: performance.now() - started };
    }

    /** Parsed pino lines of this instance's log, optionally filtered by message text */
    logEntries(msg) {
        let text;
        try {
            text = fs.readFileSync(this.logPath, 'utf8');
        } catch (err) {
            return [];
        }
        const entries = [];
        for (const line of text.split('\n')) {
            if (!line || line[0] !== '{') {
                continue;
            }
            try {
                const entry = JSON.parse(line);
                if (!msg || (typeof entry.msg === 'string' && entry.msg.includes(msg))) {
                    entries.push(entry);
                }
            } catch (err) {
                // a partial line at the end of the file
            }
        }
        return entries;
    }

    logTail(lines = 40) {
        try {
            return fs.readFileSync(this.logPath, 'utf8').trim().split('\n').slice(-lines).join('\n');
        } catch (err) {
            return '';
        }
    }
}

/**
 * @param {Object} opts
 * @param {number} opts.size - Instances to start
 * @param {Object} [opts.settings] - Prepared settings, merged over the fleet defaults
 * @param {string} [opts.webhookUrl] - Where every instance delivers webhooks
 * @param {number} [opts.imapWorkers] - IMAP worker threads per instance
 * @param {string} [opts.heartbeatTtl] - Cluster heartbeat TTL, short so tests move quickly
 * @param {Object} [opts.env] - Extra environment for every instance
 * @param {boolean} [opts.flush] - Flush the fleet database first (default true)
 * @param {boolean} [opts.wait] - Wait for every instance to be ready (default true)
 * @param {Function} [opts.prepare] - async (fleet) before any instance starts
 * @returns {Promise<Object>} The fleet
 */
async function startFleet(opts) {
    const logDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ee-fleet-'));

    const fleet = {
        logDir,
        redisUrl: opts.redisUrl || REDIS_URL,
        imapWorkers: opts.imapWorkers || 2,
        heartbeatTtl: opts.heartbeatTtl || '4s',
        logLevel: opts.logLevel || 'info',
        extraEnv: opts.env || {},
        settings: Object.assign(
            {
                serviceUrl: `http://127.0.0.1:${BASE_PORT}`,
                webhooksEnabled: !!opts.webhookUrl,
                webhooks: opts.webhookUrl || '',
                webhookEvents: ['*'],
                notifyText: true,
                sentryEnabled: false
            },
            opts.settings
        ),
        instances: [],
        // Peers reach an instance at its cluster port unless a test reroutes it through a proxy
        clusterAddressFor: instance => (instance.clusterAddress ? instance.clusterAddress : `127.0.0.1:${instance.clusterPort}`)
    };

    for (let i = 0; i < opts.size; i++) {
        fleet.instances.push(new FleetInstance(fleet, i));
    }

    Object.assign(fleet, {
        /** Adds an instance (not started) and returns it */
        add() {
            const instance = new FleetInstance(fleet, fleet.instances.length);
            fleet.instances.push(instance);
            return instance;
        },

        get running() {
            return fleet.instances.filter(instance => instance.running);
        },

        /** A running, unfrozen instance, round robin */
        pick(seq) {
            const candidates = fleet.instances.filter(instance => instance.running && !instance.frozen && !instance.outOfRotation);
            if (!candidates.length) {
                throw new Error('No running instance');
            }
            return candidates[Math.abs(seq) % candidates.length];
        },

        async startAll() {
            await Promise.all(fleet.instances.map(instance => instance.start()));
            await Promise.all(fleet.instances.map(instance => instance.waitReady()));
        },

        async stopAll() {
            await Promise.all(fleet.instances.map(instance => instance.kill()));
        },

        /** Log tails of every instance, for a failure message */
        describe() {
            return fleet.instances.map(instance => `--- ${instance.id} (${instance.logPath})\n${instance.logTail(25)}`).join('\n');
        }
    });

    if (opts.flush !== false) {
        await flushFleetDatabase(fleet.redisUrl);
    }

    // A chance to reroute instances (latency proxies) before anything starts
    if (opts.prepare) {
        await opts.prepare(fleet);
    }

    if (opts.wait !== false) {
        await fleet.startAll();
    } else {
        await Promise.all(fleet.instances.map(instance => instance.start()));
    }

    return fleet;
}

module.exports = { startFleet, flushFleetDatabase, ACCESS_TOKEN, REDIS_URL, REDIS_DB, dispatcher };
