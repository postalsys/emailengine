'use strict';

// Runs one instance's part of the cluster: its membership record and heartbeat, the ownership
// passes that decide which accounts it serves, fencing when it loses its heartbeat, the calls it
// sends to and receives from the other instances, and the broadcast bus.
//
// It lives in the main thread of server.js and knows nothing about worker threads: what serving an
// account means (assigning it to an IMAP worker, closing it) is passed in as callbacks.
//
// The rules it keeps, whatever happens:
//
//   - An instance serves an account only after its claim succeeded in Redis, and stops serving it
//     before it releases the claim, so two instances never serve one account at the same time.
//   - An instance whose heartbeat record is gone has lost every account. It stops serving all of
//     them (fencing) before it registers again; until it has, its workers hold back what they
//     would announce (lib/cluster/lease.js).
//   - Nothing waits for another instance to cooperate: a dead owner's accounts are claimed once its
//     record expires, and an account placement assigns to an instance that does not take it is
//     taken by any instance after a grace period.

const crypto = require('crypto');
const os = require('os');
const EventEmitter = require('events');

const store = require('./store');
const { clusterKeys } = require('./keys');
const { planPass, desiredOwner } = require('./placement');
const { ClusterBus } = require('./bus');
const { createRpcClient, createRpcServer } = require('./rpc');
const { LeaseView, createLeaseBuffer, monotonicNow } = require('./lease');

// Version of what instances say to each other. A record of a different protocol is not a peer
const PROTOCOL = 1;

const DEFAULT_TTL = 20 * 1000;
const MIN_TTL = 2000;

// Accounts an instance gives up per pass when placement moves them, so a scale-up does not
// disconnect a whole instance's accounts at once
const HANDOFF_LIMIT = 100;

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

/**
 * The id of this instance: the configured one, or the host name plus a random suffix, so two
 * processes on one host never share an id and a restarted process is a new member
 * @param {string} [configured]
 * @returns {string}
 */
function resolveInstanceId(configured) {
    const clean = value =>
        (value || '')
            .replace(/[^A-Za-z0-9._-]+/g, '-')
            .replace(/^-+|-+$/g, '')
            .slice(0, 64);
    const fromConfig = clean(configured);
    if (fromConfig) {
        return fromConfig;
    }
    return `${clean(os.hostname()) || 'emailengine'}-${crypto.randomBytes(3).toString('hex')}`;
}

/**
 * Where the other instances reach this one: the configured address, otherwise the first external
 * IPv4 address (IPv6 when there is none) and the cluster port
 * @param {Object} opts
 * @param {string} [opts.configured] - host or host:port
 * @param {number} opts.port
 * @param {Object} [opts.interfaces] - os.networkInterfaces(), for tests
 * @returns {string|null}
 */
function resolveAddress({ configured, port, interfaces }) {
    if (!port) {
        return null;
    }
    if (configured) {
        const value = configured.trim();
        // host:port, [v6]:port, or a bare host (IPv6 literals need the brackets)
        if (/^\[.+\]:\d+$/.test(value) || /^[^:]+:\d+$/.test(value)) {
            return value;
        }
        return value.includes(':') ? `[${value.replace(/^\[|\]$/g, '')}]:${port}` : `${value}:${port}`;
    }
    const all = Object.values(interfaces || os.networkInterfaces())
        .flat()
        .filter(entry => entry && !entry.internal);
    const v4 = all.find(entry => entry.family === 'IPv4' || entry.family === 4);
    if (v4) {
        return `${v4.address}:${port}`;
    }
    const v6 = all.find(entry => entry.family === 'IPv6' || entry.family === 6);
    if (v6) {
        return `[${v6.address}]:${port}`;
    }
    return `127.0.0.1:${port}`;
}

/**
 * WorkerNotAvailable, as an instance that serves nothing for the account always answered. Marked
 * `ownerUnsettled`: the account has no reachable owner right now, which is what a handoff looks
 * like for a moment, so the caller may ask again shortly
 */
function noHandlerError() {
    const err = new Error('No active handler for requested account. Try again later.');
    err.statusCode = 503;
    err.code = 'WorkerNotAvailable';
    err.ownerUnsettled = true;
    return err;
}

/** Answered by an instance that was asked about an account it does not serve (any more) */
function notOwnedHereError() {
    const err = new Error('This instance does not serve the requested account');
    err.statusCode = 503;
    err.code = 'NotOwnedHere';
    return err;
}

class ClusterCoordinator extends EventEmitter {
    /**
     * @param {Object} opts
     * @param {Object} opts.redis - The shared ioredis client (lib/db.js)
     * @param {Object} opts.subscriber - A dedicated client for the bus
     * @param {Object} opts.logger
     * @param {string} opts.instanceId
     * @param {string|null} opts.address - Where peers reach this instance, null when it takes no calls
     * @param {number} [opts.ttl]
     * @param {number} opts.runIndex
     * @param {string} opts.version
     * @param {Object} opts.hooks
     * @param {Function} opts.hooks.serve - (accounts) start serving accounts this instance now owns
     * @param {Function} opts.hooks.stopServing - async (account, { lost }) => true once it is no longer
     *   served here; `lost` when another instance owns it now, so nothing held back for it may go out
     * @param {Function} opts.hooks.stopServingAll - async (accounts, { lost }) the same for many
     * @param {Function} opts.hooks.handleCall - async (message) => { response } | { stream }
     * @param {Function} opts.hooks.onBroadcast - (type, data, from) for broadcasts this module does not handle
     * @param {Function} [opts.hooks.recordExtras] - () => fields added to every heartbeat
     * @param {Function} [opts.hooks.onForward] - ({ cmd, outcome, seconds }) after each forwarded call
     */
    constructor(opts) {
        super();
        this.redis = opts.redis;
        this.subscriber = opts.subscriber;
        this.logger = opts.logger;
        this.id = opts.instanceId;
        this.address = opts.address || null;
        this.ttl = Math.max(MIN_TTL, opts.ttl || DEFAULT_TTL);
        this.runIndex = opts.runIndex;
        this.version = opts.version;
        this.hooks = opts.hooks;

        // Renewal and the regular pass run on this interval; a full pass every few of them
        this.interval = Math.max(250, Math.floor(this.ttl / 4));
        this.fullPassInterval = Math.max(5000, this.interval * 6);
        // How long an account may stay without a live owner before any instance takes it
        this.orphanGrace = this.ttl * 2;
        // Renewal starts are measured locally; the record expires `ttl` after it reached Redis, so
        // the local view of the lease ends a little earlier
        this.leaseSafety = Math.min(2000, Math.floor(this.ttl / 5));

        this.leaseBuffer = createLeaseBuffer();
        this.lease = new LeaseView(this.leaseBuffer);

        this.token = null;
        this.registered = false;
        this.ready = false;
        // leaving: shutting down, takes nothing new but keeps its heartbeat while it drains;
        // closing: gone, the heartbeat has stopped
        this.leaving = false;
        this.closing = false;
        this.firstPassDone = false;

        // Accounts this instance has claimed and serves
        this.held = new Set();
        this.unownedSince = new Map();
        this.live = new Map();
        this.liveReadAt = 0;
        this.membershipSignature = '';
        this.lastFullPass = 0;

        this.passRunning = null;
        this.pendingFull = false;
        this.pendingAccounts = new Set();

        this.tickTimer = null;
        this.fencing = null;

        this.secret = null;
        this.getSecret = async () => {
            if (!this.secret) {
                this.secret = await store.ensureSecret(this.redis);
            }
            return this.secret;
        };

        this.rpcClient = createRpcClient({ instanceId: this.id, getSecret: this.getSecret });
        this.rpcServer = null;

        this.bus = new ClusterBus({
            publisher: this.redis,
            subscriber: this.subscriber,
            channel: clusterKeys.bus,
            instanceId: this.id,
            logger: this.logger,
            onMessage: (type, data, from) => this.onBusMessage(type, data, from)
        });

        this.stats = { forwarded: 0, forwardFailed: 0, received: 0, claims: 0, releases: 0, drops: 0, fences: 0 };
    }

    /** Fields of the heartbeat record */
    record() {
        return Object.assign(
            {
                protocol: PROTOCOL,
                version: this.version,
                address: this.address || '',
                hostname: os.hostname(),
                pid: process.pid,
                started: this.started,
                runIndex: this.runIndex,
                ready: this.ready && !this.leaving && !this.closing ? 1 : 0,
                owned: this.held.size,
                heartbeat: Date.now()
            },
            this.hooks.recordExtras ? this.hooks.recordExtras() : {}
        );
    }

    /**
     * Joins the cluster: opens the call listener, subscribes to the bus and registers. Waits while
     * a live record of another process holds this instance id
     * @param {Object} [listen] - `{ port, host }` of the call listener, omitted to take no calls
     */
    async start(listen) {
        this.started = Date.now();
        await this.getSecret();

        if (listen && listen.port) {
            this.rpcServer = createRpcServer({
                instanceId: this.id,
                getSecret: this.getSecret,
                logger: this.logger,
                handle: message => this.receiveCall(message)
            });
            await this.rpcServer.listen(listen.port, listen.host);
            this.logger.info({ msg: 'Listening for cluster calls', instance: this.id, port: listen.port, host: listen.host, address: this.address });
        }

        await this.bus.start();
        await this.register();
        this.scheduleTick();
    }

    /**
     * Registers a run of this instance, retrying until it succeeds or `giveUpAfter` passes
     * @param {Object} [opts]
     * @param {boolean} [opts.extendLease] - Let the workers announce again at once (fencing decides that itself)
     * @param {number} [opts.giveUpAfter] - Milliseconds, unlimited by default
     * @returns {Promise<boolean>} Whether it registered
     */
    async register({ extendLease = true, giveUpAfter = Infinity } = {}) {
        let warned = false;
        const deadline = Date.now() + giveUpAfter;
        while (!this.closing && Date.now() < deadline) {
            const token = crypto.randomBytes(16).toString('hex');
            const started = monotonicNow();
            let ok = false;
            try {
                ok = await store.register(this.redis, { id: this.id, token, ttl: this.ttl, record: this.record() });
            } catch (err) {
                this.logger.error({ msg: 'Failed to register in the cluster, retrying', instance: this.id, err });
            }
            if (ok) {
                this.token = token;
                this.registered = true;
                this.leaseStart = started;
                if (extendLease) {
                    this.lease.extend(started + this.ttl - this.leaseSafety);
                }
                this.logger.info({ msg: 'Joined the cluster', instance: this.id, address: this.address, ttl: this.ttl });
                this.bus.publish('joined', { id: this.id });
                return true;
            }
            if (!warned) {
                warned = true;
                this.logger.warn({
                    msg: 'Another live process is registered with this instance id, waiting for its record to expire',
                    instance: this.id,
                    ttl: this.ttl
                });
            }
            await sleep(Math.min(1000, this.interval));
        }
        return false;
    }

    /**
     * Schedules the next tick (heartbeat, membership, ownership pass). A request for an earlier tick
     * brings it forward but never pushes an already scheduled one back: the tick is also what renews
     * the heartbeat, and a steady stream of requests (claim hints during a bulk import) must not
     * starve it. Ticks never overlap; one asked for while another runs follows it
     * @param {number} [delay]
     */
    scheduleTick(delay = this.interval) {
        if (this.closing) {
            return;
        }
        const at = Date.now() + delay;
        if (this.tickTimer && this.nextTickAt <= at) {
            return;
        }
        clearTimeout(this.tickTimer);
        this.nextTickAt = at;
        this.tickTimer = setTimeout(() => {
            this.tickTimer = null;
            if (this.ticking) {
                this.scheduleTick(50);
                return;
            }
            this.ticking = true;
            this.tick()
                .catch(err => this.logger.error({ msg: 'Cluster heartbeat failed', instance: this.id, err }))
                .finally(() => {
                    this.ticking = false;
                    this.scheduleTick();
                });
        }, delay);
    }

    async tick() {
        if (this.closing || !this.registered || this.fencing) {
            return;
        }

        const started = monotonicNow();
        let renewed;
        try {
            renewed = await store.renew(this.redis, { id: this.id, token: this.token, ttl: this.ttl, record: this.record() });
        } catch (err) {
            // Redis did not answer. The lease runs out on its own; whether the record survived is
            // learned from the next renewal that does get an answer
            this.logger.warn({ msg: 'Failed to renew the cluster heartbeat', instance: this.id, err });
            return;
        }

        if (!renewed) {
            await this.fence('heartbeat record expired');
            return;
        }
        this.lease.extend(started + this.ttl - this.leaseSafety);

        await this.refreshLive();

        const full = this.pendingFull || Date.now() - this.lastFullPass >= this.fullPassInterval;
        if (full || this.pendingAccounts.size) {
            await this.runPass({ full });
        }
    }

    async refreshLive() {
        const live = await store.listLive(this.redis);
        for (const [id, record] of live) {
            if (record.protocol !== PROTOCOL) {
                // Not a peer this instance can talk to or share placement with
                live.delete(id);
            }
        }
        this.live = live;
        this.liveReadAt = Date.now();

        const signature = [...live.values()]
            .map(record => `${record.id}:${record.ready ? 1 : 0}`)
            .sort()
            .join(',');
        if (signature !== this.membershipSignature) {
            if (this.membershipSignature) {
                this.logger.info({ msg: 'Cluster membership changed', instance: this.id, members: signature });
            }
            this.membershipSignature = signature;
            this.pendingFull = true;
        }
        return live;
    }

    candidates() {
        return [...this.live.values()].filter(record => record.ready).map(record => record.id);
    }

    /** Asks for a pass soon; `accounts` limits it to those, otherwise it covers every account */
    requestPass(accounts) {
        if (accounts && accounts.length) {
            for (const account of accounts) {
                this.pendingAccounts.add(account);
            }
        } else {
            this.pendingFull = true;
        }
        if (!this.passRunning && this.registered && !this.closing) {
            // Debounced so a burst of events (a bulk import, a membership change) is one pass
            this.scheduleTick(50);
        }
    }

    async runPass({ full }) {
        if (this.passRunning) {
            if (full) {
                this.pendingFull = true;
            }
            return this.passRunning;
        }
        this.passRunning = this.pass(full)
            .catch(err => this.logger.error({ msg: 'Cluster ownership pass failed', instance: this.id, err }))
            .finally(() => {
                this.passRunning = null;
                // Asked for while this pass ran
                if (this.pendingFull || this.pendingAccounts.size) {
                    this.scheduleTick(50);
                }
            });
        return this.passRunning;
    }

    async pass(full) {
        if (!this.ready || this.leaving || this.closing || !this.live.has(this.id)) {
            return;
        }

        let accounts;
        if (full) {
            this.pendingFull = false;
            this.pendingAccounts.clear();
            accounts = await this.redis.smembers(clusterKeys.accounts);
            // A served account that is no longer registered was deleted. Its deletion is broadcast
            // to the instance serving it; this catches an instance that missed the broadcast
            const registered = new Set(accounts);
            for (const account of [...this.held]) {
                if (!registered.has(account)) {
                    this.held.delete(account);
                    this.logger.info({ msg: 'Stopped serving a deleted account', instance: this.id, account });
                    await this.hooks.stopServing(account);
                }
            }
        } else {
            accounts = [...this.pendingAccounts];
            this.pendingAccounts.clear();
        }

        const owners = await store.readOwners(this.redis, accounts);
        const plan = planPass({
            me: this.id,
            accounts,
            owners,
            live: new Set(this.live.keys()),
            candidates: this.candidates(),
            held: this.held,
            unownedSince: this.unownedSince,
            now: Date.now(),
            orphanGrace: this.orphanGrace,
            handoffLimit: HANDOFF_LIMIT
        });

        await this.carryOut(plan);

        if (full) {
            this.lastFullPass = Date.now();
            if (!this.firstPassDone) {
                this.firstPassDone = true;
                this.logger.info({ msg: 'First cluster ownership pass completed', instance: this.id, owned: this.held.size, members: this.live.size });
                this.emit('firstPass');
            }
        }
    }

    async carryOut(plan) {
        // Drops first: another live instance owns these, and serving them here as well is the one
        // state that must not last
        for (const account of plan.drop) {
            this.held.delete(account);
            this.stats.drops++;
            this.logger.warn({ msg: 'Stopped serving an account another instance owns', instance: this.id, account });
            await this.hooks.stopServing(account, { lost: true });
        }

        if (plan.release.length) {
            const handedOff = [];
            for (const { account } of plan.release) {
                // Stop serving before the record is cleared, so the next owner never overlaps
                if (await this.hooks.stopServing(account)) {
                    this.held.delete(account);
                    handedOff.push(account);
                }
            }
            if (handedOff.length) {
                const released = await store.release(this.redis, handedOff, this.id);
                this.stats.releases += released.length;
                // Tell the new owners, so they claim now rather than at their next pass
                const byTarget = new Map();
                for (const { account, to } of plan.release) {
                    if (released.includes(account)) {
                        if (!byTarget.has(to)) {
                            byTarget.set(to, []);
                        }
                        byTarget.get(to).push(account);
                    }
                }
                for (const [to, accounts] of byTarget) {
                    this.bus.publish('claim', { to, accounts });
                }
                this.logger.info({ msg: 'Handed accounts over to other instances', instance: this.id, accounts: released.length });
            }
        }

        if (plan.claim.length && !this.leaving && !this.closing && !this.fencing) {
            const outcome = await store.claim(this.redis, plan.claim, this.id, this.runIndex);
            for (const account of outcome.claimed) {
                this.held.add(account);
            }
            this.stats.claims += outcome.claimed.length;
            if (outcome.claimed.length) {
                this.logger.info({ msg: 'Claimed accounts', instance: this.id, accounts: outcome.claimed.length });
                this.hooks.serve(outcome.claimed);
            }
        }
    }

    /**
     * Stops serving everything after the heartbeat record was lost, then registers again
     * @param {string} reason
     */
    /**
     * Recovers from a lost heartbeat record. Until it is done the workers hold back every
     * announcement (lib/cluster/lease.js). Once registered again, an account still recorded as owned
     * by this instance was never taken over (the record only changes through a claim), so it keeps
     * its connection and what its worker held back goes out. An account another instance claimed
     * meanwhile is closed here, and what was held back for it is dropped: the new owner announces it.
     * When this instance cannot register again (another live process holds its id), it gives up
     * every account.
     * @param {string} reason
     */
    async fence(reason) {
        if (this.fencing) {
            return this.fencing;
        }
        this.fencing = (async () => {
            this.stats.fences++;
            this.lease.suspend();
            this.registered = false;
            this.unownedSince.clear();
            this.logger.error({
                msg: 'Lost cluster membership, holding back announcements until it is settled',
                instance: this.id,
                reason,
                accounts: this.held.size
            });

            if (!(await this.register({ extendLease: false, giveUpAfter: this.ttl * 2 }))) {
                const lost = [...this.held];
                this.held.clear();
                this.lease.revoke();
                this.logger.error({ msg: 'Could not rejoin the cluster, stopped serving every account', instance: this.id, accounts: lost.length });
                await this.stopServingLost(lost);
                await this.register();
                this.pendingFull = true;
                return;
            }

            const held = [...this.held];
            const owners = await store.readOwners(this.redis, held);
            const lost = held.filter(account => owners.get(account) !== this.id);
            for (const account of lost) {
                this.held.delete(account);
            }
            await this.stopServingLost(lost);
            this.lease.extend(this.leaseStart + this.ttl - this.leaseSafety);
            this.logger.warn({ msg: 'Rejoined the cluster', instance: this.id, kept: this.held.size, lost: lost.length });
            this.pendingFull = true;
        })()
            .catch(err => this.logger.error({ msg: 'Failed to recover cluster membership', instance: this.id, err }))
            .finally(() => {
                this.fencing = null;
            });
        return this.fencing;
    }

    async stopServingLost(accounts) {
        if (!accounts.length) {
            return;
        }
        try {
            await this.hooks.stopServingAll(accounts, { lost: true });
        } catch (err) {
            this.logger.error({ msg: 'Failed to stop serving accounts another instance took over', instance: this.id, err });
        }
    }

    /** Marks the instance as taking accounts (its IMAP workers are up) */
    setReady(ready) {
        this.ready = !!ready;
        this.requestPass();
    }

    isReady() {
        return this.firstPassDone && this.registered && !this.fencing;
    }

    /** A new account was registered, maybe through another instance's API */
    accountAdded(account) {
        if (!this.ready || this.leaving) {
            return;
        }
        const candidates = this.candidates();
        const target = candidates.length ? desiredOwner(account, candidates) : this.id;
        if (target === this.id) {
            this.requestPass([account]);
        } else {
            this.bus.publish('claim', { to: target, accounts: [account] });
        }
    }

    /** An account was deleted; its owner record went with it */
    accountDeleted(account) {
        this.held.delete(account);
        this.unownedSince.delete(account);
    }

    holds(account) {
        return this.held.has(account);
    }

    /** The live record of an instance, re-reading membership once when it is not known yet */
    async peer(id) {
        let record = this.live.get(id);
        if (!record && Date.now() - this.liveReadAt > 1000) {
            await this.refreshLive();
            record = this.live.get(id);
        }
        return record || null;
    }

    /**
     * Runs an account command on the instance that owns the account
     * @param {Object} message - The command, with `account`
     * @param {Object} [opts]
     * @param {number} [opts.timeout]
     * @param {boolean} [opts.stream] - The answer is a download
     * @param {*} [opts.unowned] - Resolved with when no instance owns the account, which otherwise
     *   fails with WorkerNotAvailable
     * @returns {Promise<*>}
     */
    async forward(message, opts = {}) {
        const { timeout, stream } = opts;
        const started = process.hrtime.bigint();
        let outcome = 'ok';
        try {
            for (let attempt = 0; ; attempt++) {
                const owner = await store.readOwner(this.redis, message.account);
                if (!owner || owner === this.id) {
                    // Nobody owns it, or this instance claimed it and is still connecting it
                    outcome = 'unowned';
                    if ('unowned' in opts) {
                        return opts.unowned;
                    }
                    throw noHandlerError();
                }
                const peer = await this.peer(owner);
                if (!peer || !peer.address) {
                    outcome = 'unreachable';
                    throw noHandlerError();
                }
                try {
                    this.stats.forwarded++;
                    return await this.rpcClient.call(peer, message, { timeout, stream });
                } catch (err) {
                    // Retried once when the call certainly did not run: the owner moved on, or the
                    // connection was refused. Anything else may have run and is not repeated
                    if (attempt === 0 && (err.code === 'NotOwnedHere' || err.notDelivered)) {
                        await sleep(100);
                        continue;
                    }
                    outcome = err.code === 'Timeout' ? 'timeout' : 'error';
                    this.stats.forwardFailed++;
                    if (
                        err.code === 'NotOwnedHere' ||
                        err.code === 'ClusterUnreachable' ||
                        err.code === 'ClusterCallFailed' ||
                        err.code === 'ClusterAuthFailed'
                    ) {
                        this.logger.warn({
                            msg: 'Forwarded account command failed',
                            instance: this.id,
                            account: message.account,
                            cmd: message.cmd,
                            to: owner,
                            err
                        });
                        throw noHandlerError();
                    }
                    throw err;
                }
            }
        } finally {
            if (this.hooks.onForward) {
                const seconds = Number(process.hrtime.bigint() - started) / 1e9;
                this.hooks.onForward({ cmd: message.cmd, outcome, seconds });
            }
        }
    }

    /**
     * Runs a command on one named instance, for state that lives on that instance's disk rather
     * than with an account (an export file)
     * @param {string} id - Instance id
     * @param {Object} message
     * @param {Object} [opts] - `{ timeout, stream }`
     * @returns {Promise<*>}
     */
    async callInstance(id, message, opts = {}) {
        const peer = await this.peer(id);
        if (!peer || !peer.address) {
            const err = new Error('The instance that holds this data is no longer running');
            err.statusCode = 410;
            err.code = 'InstanceGone';
            throw err;
        }
        return await this.rpcClient.call(peer, message, opts);
    }

    /** A call from another instance */
    async receiveCall(message) {
        this.stats.received++;
        if (!message || typeof message.cmd !== 'string') {
            throw notOwnedHereError();
        }
        return await this.hooks.handleCall(message);
    }

    /** Broadcasts to the other instances */
    broadcast(type, data) {
        this.bus.publish(type, data);
    }

    onBusMessage(type, data, from) {
        switch (type) {
            case 'joined':
            case 'left':
                this.requestPass();
                return;
            case 'claim':
                if (data && data.to === this.id && Array.isArray(data.accounts)) {
                    this.requestPass(data.accounts);
                }
                return;
        }
        return this.hooks.onBroadcast(type, data, from);
    }

    /**
     * Leaves the cluster on shutdown, once the accounts are no longer served: their owner records
     * are cleared and the heartbeat removed, so the other instances take over at once
     */
    async leave() {
        this.leaving = true;
        this.closing = true;
        clearTimeout(this.tickTimer);
        if (this.passRunning) {
            await this.passRunning.catch(() => false);
        }
        const held = [...this.held];
        this.held.clear();
        try {
            if (held.length) {
                await store.release(this.redis, held, this.id);
            }
            if (this.token) {
                await store.leave(this.redis, { id: this.id, token: this.token });
            }
            this.bus.publish('left', { id: this.id });
            this.logger.info({ msg: 'Left the cluster', instance: this.id, released: held.length });
        } catch (err) {
            this.logger.error({ msg: 'Failed to leave the cluster cleanly, the records expire on their own', instance: this.id, err });
        }
    }

    /**
     * Stops taking new work at the start of a shutdown, before the workers drain. The heartbeat keeps
     * running until leave(): the accounts are still served while the workers close them, and a
     * record that expired now would let another instance claim one that is still connected here
     */
    async stopListening() {
        this.leaving = true;
        if (this.rpcServer) {
            await this.rpcServer.close();
        }
    }

    async close() {
        await this.bus.stop();
        await this.rpcClient.close();
    }

    /** What /v1/instances and the dashboard show about this instance and its peers */
    describe() {
        return {
            instance: this.id,
            ready: this.isReady(),
            held: this.held.size,
            members: [...this.live.values()],
            stats: Object.assign({}, this.stats, { busPublished: this.bus.published, busReceived: this.bus.received })
        };
    }
}

module.exports = { ClusterCoordinator, resolveInstanceId, resolveAddress, noHandlerError, notOwnedHereError, PROTOCOL, DEFAULT_TTL };
