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
//   - An instance whose heartbeat record is gone may have lost accounts to another instance. Its
//     workers hold back what they would announce (lib/cluster/lease.js) until it has registered
//     again and closed every account another instance claimed meanwhile (fencing).
//   - Nothing waits for another instance to cooperate: a dead owner's accounts are claimed once its
//     record expires, and an account placement assigns to an instance that does not take it is
//     taken by any instance after a grace period.

const crypto = require('crypto');
const os = require('os');

const store = require('./store');
const { clusterKeys } = require('./keys');
const { planPass } = require('./placement');
const { ClusterBus } = require('./bus');
const { createRpcClient, createRpcServer } = require('./rpc');
const { LeaseView, createLeaseBuffer, monotonicNow } = require('./lease');
const { statusError } = require('../utils/status-error');
const { remainingTimeout } = require('../command-budget');
const { mapConcurrent } = require('../utils/map-concurrent');

// Version of what instances say to each other. An instance of another protocol is still a live
// owner of what it holds, so nothing claims its accounts, but it takes no part in placement and
// takes no forwarded calls from this one
const PROTOCOL = 1;

const DEFAULT_TTL = 20 * 1000;
const MIN_TTL = 2000;

// How long a paced handoff or a batch of left over claims waits for the pass that continues it
const PASS_PAUSE = 1000;

// Accounts an instance gives up per pass when placement moves them, so a scale-up does not
// disconnect a whole instance's accounts at once. While more are left to move, the next pass
// follows after PASS_PAUSE rather than at the next full pass, so a large fleet settles in minutes
// rather than in hours
const HANDOFF_LIMIT = 100;

// Accounts an instance claims per pass beyond those it is still connecting, so it never takes
// accounts faster than it can serve them. An instance that is up while the others are still on their
// way (a fleet starting minutes apart, members dropping out together) would otherwise take all of
// their accounts and then hand them back a hundred at a time. Accounts handed to it or added just
// now are not counted. The claims left over are kept (deferredClaims) and taken a batch at a time:
// the next pass follows after PASS_PAUSE, or as soon as the workers have taken every account
// claimed so far (backlogDrained()), but no sooner than CLAIM_GAP after the one before
const CLAIM_LIMIT = 1000;
const CLAIM_GAP = 250;

// How long after its own start an instance keeps the share of the members still starting for them
// (in orphan graces). That is the cold start of a whole fleet; an instance that has been running
// takes over a crashed member's accounts at once, whoever else happens to be starting then
const COLD_START_GRACES = 3;

// How long the signing key of cluster calls is used before it is read from Redis again
const SECRET_REFRESH = 60 * 1000;

// Accounts closed at once when a pass hands them over or drops them
const STOP_CONCURRENCY = 16;

// A failed forward is logged at warn at most once per owner and error code in this window; the rest
// go to debug. A crashed owner fails every request for its accounts until its heartbeat expires,
// which was a thousand warn lines in a few seconds on an instance of three thousand accounts
const FORWARD_WARN_INTERVAL = 10 * 1000;

// Looked up at call time, so a suite can stub the waits (test/helpers/instant-timers.js)
const timers = require('node:timers/promises');

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
 * WorkerNotAvailable, as an instance that serves nothing for the account always answered
 * @param {boolean} unsettled - The account is between owners (unowned, claimed and still being set
 *   up, or released), which settles within moments, so the caller may ask again shortly. Not for an
 *   owner that is merely unreachable: that only clears when its heartbeat expires
 * @returns {Error}
 */
function noHandlerError(unsettled) {
    const err = statusError('No active handler for requested account. Try again later.', 'WorkerNotAvailable', 503);
    err.ownerUnsettled = !!unsettled;
    return err;
}

/** Answered by an instance that was asked about an account it does not serve (any more) */
function notOwnedHereError() {
    return statusError('This instance does not serve the requested account', 'NotOwnedHere', 503);
}

class ClusterCoordinator {
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
     * @param {string} [opts.localSecret] - EENGINE_SECRET; mixed into the signing key, so the key
     *   Redis holds is not enough to sign a call on its own
     * @param {Object} opts.hooks
     * @param {Function} opts.hooks.serve - (accounts) start serving accounts this instance now owns
     * @param {Function} opts.hooks.stopServing - async (account, { lost }) resolves once it is no longer
     *   served here; `lost` when another instance owns it now, so nothing held back for it may go out
     * @param {Function} opts.hooks.handleCall - async (message) => { response } | { stream }
     * @param {Function} opts.hooks.onBroadcast - (type, data, from) for broadcasts this module does not handle
     * @param {Function} [opts.hooks.recordExtras] - () => fields added to every heartbeat
     * @param {Function} [opts.hooks.backlog] - () => accounts claimed and not yet handed to a worker
     * @param {Function} [opts.hooks.onForward] - ({ cmd, outcome, seconds }) after each forwarded call
     */
    constructor(opts) {
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
        // closing: left, the heartbeat has stopped. closing implies leaving
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
        // When the next batch of a paced handoff may start; 0 when no handoff is waiting
        this.handoffResumeAt = 0;
        // When a pass should take the claims an earlier one left over; 0 when none are waiting
        this.claimResumeAt = 0;
        // When the pass that left them over ran
        this.claimDeferredAt = 0;
        // The accounts left over, so a pass that resumes them reads those rather than every account
        this.deferredClaims = new Set();
        // When this instance last had trouble with Redis itself (a renewal that failed or was slow,
        // a lost record). For an orphan grace after it, an owner that looks dead may only be
        // reconnecting after the same outage, so its accounts are left alone (spareDeadOwners())
        this.redisTroubleAt = 0;
        // Members still starting keep their share until then (starting())
        this.coldStartUntil = 0;
        this.pendingAccounts = new Set();

        this.tickTimer = null;
        this.fencing = null;

        // Read again now and then: a Redis that lost the key (a flush, a failover to a replica
        // that never had it) gets a new one from whichever instance asks first, and the others
        // would sign with the old one until they restarted
        this.secret = null;
        this.secretReadAt = 0;
        this.secretReading = null;
        this.getSecret = async () => {
            if (this.secret && Date.now() - this.secretReadAt <= SECRET_REFRESH) {
                return this.secret;
            }
            // One read for every call that finds the key stale at the same time
            if (!this.secretReading) {
                this.secretReading = store
                    .ensureSecret(this.redis)
                    .then(secret => {
                        // A Redis backup or a read-only replica holds cluster:secret; with the
                        // encryption secret mixed in, it alone does not let anyone call the port
                        this.secret = opts.localSecret ? crypto.createHmac('sha256', opts.localSecret).update(secret).digest() : secret;
                        this.secretReadAt = Date.now();
                        return this.secret;
                    })
                    .finally(() => {
                        this.secretReading = null;
                    });
            }
            return await this.secretReading;
        };

        this.rpcClient = createRpcClient({ instanceId: this.id, getSecret: this.getSecret });
        this.rpcServer = null;

        this.bus = new ClusterBus({
            publisher: this.redis,
            subscriber: this.subscriber,
            channel: clusterKeys.bus(this.redis.options && this.redis.options.db),
            instanceId: this.id,
            logger: this.logger,
            onMessage: (type, data, from) => this.onBusMessage(type, data, from)
        });

        this.stats = { fences: 0 };
        // `${owner}:${code}` -> when that failure was last logged at warn
        this.forwardWarnedAt = new Map();
    }

    /**
     * The level a failed forward is logged at. NotOwnedHere is the account moving between owners,
     * which the caller retries; the others repeat for every request while an owner is unreachable,
     * so only the first in FORWARD_WARN_INTERVAL is a warning
     * @param {string} owner
     * @param {string} code
     * @returns {string}
     */
    forwardFailureLevel(owner, code) {
        if (code === 'NotOwnedHere') {
            return 'debug';
        }
        const now = Date.now();
        const key = `${owner}:${code}`;
        if (now - (this.forwardWarnedAt.get(key) || 0) < FORWARD_WARN_INTERVAL) {
            return 'debug';
        }
        if (this.forwardWarnedAt.size > 100) {
            // Owners come and go with their pods
            for (const [entry, at] of this.forwardWarnedAt) {
                if (now - at >= FORWARD_WARN_INTERVAL) {
                    this.forwardWarnedAt.delete(entry);
                }
            }
        }
        this.forwardWarnedAt.set(key, now);
        return 'warn';
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
                ready: this.ready && !this.leaving ? 1 : 0,
                // Registered and about to take accounts: placement keeps its share for it
                starting: !this.ready && !this.leaving ? 1 : 0,
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
        this.coldStartUntil = this.started + this.orphanGrace * COLD_START_GRACES;
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

        if (this.rpcServer) {
            // Only logs, so nothing waits for it
            this.checkOwnAddress().catch(() => false);
        }
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
            await timers.setTimeout(this.retryDelay());
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
            this.redisTroubleAt = Date.now();
            this.logger.warn({ msg: 'Failed to renew the cluster heartbeat', instance: this.id, err });
            return;
        }

        if (!renewed) {
            await this.fence('heartbeat record expired');
            return;
        }
        if (monotonicNow() - started > this.interval) {
            // A renewal this slow (it waited out a disconnect, or Redis is overloaded) may have let
            // the records of other instances expire too
            this.redisTroubleAt = Date.now();
        }
        this.lease.extend(started + this.ttl - this.leaseSafety);

        await this.refreshLive();

        // Not awaited: a pass that hands accounts over waits on the workers closing them, and the
        // next renewal must not wait for that
        const full = this.pendingFull || Date.now() - this.lastFullPass >= this.fullPassInterval;
        if (full || this.pendingAccounts.size || this.handoffDue() || this.claimDue()) {
            this.runPass({ full });
        }
    }

    async refreshLive() {
        const live = await store.listLive(this.redis);
        this.live = live;
        this.liveReadAt = Date.now();

        // A member that is still starting matters to placement only during this instance's cold start
        // (starting()); otherwise its arrival would cost every instance a full pass for nothing, and
        // a second one when it turns ready
        const coldStart = Date.now() < this.coldStartUntil;
        const signature = [...live.values()]
            .filter(record => record.ready || !record.starting || coldStart)
            .map(record => `${record.id}:${record.ready ? 'r' : record.starting ? 's' : '-'}`)
            .sort()
            .join(',');
        if (signature !== this.membershipSignature) {
            if (this.membershipSignature) {
                this.logger.info({ msg: 'Cluster membership changed', instance: this.id, members: signature });
            }
            this.membershipSignature = signature;
            this.pendingFull = true;
            this.warnUnreachableMembers(live);
        }
        return live;
    }

    /**
     * An instance without a call listener still takes its share of the accounts, and every other
     * instance answers 503 for those. Said once per membership change, by every instance, so the
     * logs of whichever pod an operator looks at name the cause
     * @param {Map<string, Object>} live
     */
    warnUnreachableMembers(live) {
        if (live.size < 2) {
            return;
        }
        const unreachable = [...live.values()].filter(record => !record.address).map(record => record.id);
        if (unreachable.length) {
            this.logger.warn({
                msg: 'Instances without EENGINE_CLUSTER_PORT serve accounts the other instances cannot forward requests to; those requests answer 503',
                instance: this.id,
                unreachable
            });
        }
    }

    /** Ids of the live instances of this protocol whose record matches */
    peersWhere(match) {
        return [...this.live.values()].filter(record => record.protocol === PROTOCOL && match(record)).map(record => record.id);
    }

    /** Live instances of this protocol that take accounts */
    candidates() {
        return this.peersWhere(record => record.ready);
    }

    /**
     * Live instances of this protocol that are starting, for the first COLD_START_GRACES orphan
     * graces after this instance started. An account placement gives one of them is left for it for
     * the orphan grace, so on a cold start of the whole fleet the first instance to be ready does not
     * claim every account and then hand most of them over
     */
    starting() {
        return Date.now() < this.coldStartUntil ? this.peersWhere(record => record.starting) : [];
    }

    /** Whether a paced handoff is due to continue */
    handoffDue() {
        return this.handoffResumeAt > 0 && Date.now() >= this.handoffResumeAt;
    }

    /** Whether claims left over by an earlier pass are due */
    claimDue() {
        return this.claimResumeAt > 0 && Date.now() >= this.claimResumeAt;
    }

    /**
     * Every account claimed so far went to a worker, so the claims left over need not wait out the
     * rest of PASS_PAUSE: an instance claims as fast as its workers take the accounts. The accounts
     * spared after a Redis outage keep their grace
     */
    backlogDrained() {
        const resumeAt = Math.max(Date.now(), this.claimDeferredAt + CLAIM_GAP);
        if (this.claimResumeAt > resumeAt && !this.spareDeadOwners()) {
            this.claimResumeAt = resumeAt;
            this.scheduleTick(resumeAt - Date.now());
        }
    }

    /**
     * Whether this instance had trouble reaching Redis within the last orphan grace. The other
     * instances most likely had the same trouble, and their records may have expired while they
     * still serve their accounts: an instance that reconnected first would otherwise take every
     * account of every instance that reconnects a few seconds after it
     */
    spareDeadOwners() {
        return Date.now() - this.redisTroubleAt < this.orphanGrace;
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
                } else if (this.handoffResumeAt || this.claimResumeAt) {
                    const resumeAt = Math.min(...[this.handoffResumeAt, this.claimResumeAt].filter(Boolean));
                    this.scheduleTick(Math.max(50, resumeAt - Date.now()));
                }
            });
        return this.passRunning;
    }

    async pass(full) {
        if (!this.ready || this.leaving || !this.live.has(this.id)) {
            return;
        }

        // Accounts handed to this instance or added just now are claimed whatever the claim limit
        const exempt = new Set(this.pendingAccounts);
        const claimLimit = Math.max(0, CLAIM_LIMIT - (this.hooks.backlog ? this.hooks.backlog() : 0));
        let resumedClaims = false;
        let accounts;
        if (full) {
            this.pendingFull = false;
            this.claimResumeAt = 0;
            this.deferredClaims.clear();
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
            const selected = new Set(this.pendingAccounts);
            this.pendingAccounts.clear();
            if (this.handoffDue()) {
                // Only what this instance holds can be handed over: no need to read every account
                this.held.forEach(account => selected.add(account));
            }
            if (this.claimDue()) {
                // The next batch of the claims left over, as many as the claim limit takes: a pass
                // over every account per batch read the whole account list a hundred times over
                // while an instance took 100,000 accounts, and one over every left over claim still
                // read the owners of all of them for each batch
                this.claimResumeAt = 0;
                resumedClaims = true;
                let taken = 0;
                for (const account of this.deferredClaims) {
                    if (taken++ >= claimLimit) {
                        break;
                    }
                    selected.add(account);
                    this.deferredClaims.delete(account);
                }
            }
            accounts = [...selected];
        }

        // Handoffs are paced, whatever else asks for a pass meanwhile
        const handoffOpen = Date.now() >= this.handoffResumeAt;
        if (handoffOpen) {
            this.handoffResumeAt = 0;
        }

        const owners = await store.readOwners(this.redis, accounts);
        const spareDeadOwners = this.spareDeadOwners();
        const plan = planPass({
            me: this.id,
            accounts,
            owners,
            live: new Set(this.live.keys()),
            candidates: this.candidates(),
            starting: this.starting(),
            held: this.held,
            unownedSince: this.unownedSince,
            now: Date.now(),
            orphanGrace: this.orphanGrace,
            handoffLimit: handoffOpen ? HANDOFF_LIMIT : 0,
            claimLimit,
            exempt,
            spareDeadOwners
        });

        await this.carryOut(plan);

        plan.deferred.forEach(account => this.deferredClaims.add(account));
        // Only a pass that left claims over or took a batch of them sets when the next batch comes:
        // the passes for single accounts in between would otherwise keep pushing it back
        if (this.deferredClaims.size && (plan.deferred.length || resumedClaims)) {
            // Spared accounts wait out the grace, the ones over the claim limit only a pause
            this.claimResumeAt = Math.max(Date.now() + PASS_PAUSE, spareDeadOwners ? this.redisTroubleAt + this.orphanGrace : 0);
            this.claimDeferredAt = Date.now();
        }

        // The handoff budget ran out: more accounts may be waiting to move
        if (plan.release.length >= HANDOFF_LIMIT) {
            this.handoffResumeAt = Date.now() + PASS_PAUSE;
        }

        if (full) {
            this.lastFullPass = Date.now();
            if (!this.firstPassDone) {
                this.firstPassDone = true;
                this.logger.info({ msg: 'First cluster ownership pass completed', instance: this.id, owned: this.held.size, members: this.live.size });
            }
        }
    }

    async carryOut(plan) {
        // Drops first: another live instance owns these, and serving them here as well is the one
        // state that must not last
        if (plan.drop.length) {
            for (const account of plan.drop) {
                this.held.delete(account);
            }
            this.logger.warn({ msg: 'Stopped serving accounts another instance owns', instance: this.id, accounts: plan.drop.length });
            await this.stopServingMany(plan.drop, { lost: true });
        }

        if (plan.release.length) {
            const handedOff = plan.release.map(({ account }) => account);
            // Stop serving before the record is cleared, so the next owner never overlaps
            await this.stopServingMany(handedOff);
            for (const account of handedOff) {
                this.held.delete(account);
            }
            const released = await store.release(this.redis, handedOff, this.id);
            // The new owners claim now rather than at their next pass
            this.bus.publish('claim', { accounts: released });
            this.logger.info({ msg: 'Handed accounts over to other instances', instance: this.id, accounts: released.length });
        }

        if (plan.claim.length && !this.leaving && !this.fencing) {
            const claimed = await store.claim(this.redis, plan.claim, this.id, this.runIndex);
            for (const account of claimed) {
                this.held.add(account);
            }
            if (claimed.length) {
                this.logger.info({ msg: 'Claimed accounts', instance: this.id, accounts: claimed.length });
                this.hooks.serve(claimed);
            }
        }
    }

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
                await this.giveUpEverything('Could not rejoin the cluster, stopped serving every account');
                return;
            }

            const held = [...this.held];
            // Retried while the new record is surely alive (no renewal runs during a fence). Without
            // the owners it is unknown which accounts another instance took; a read that keeps
            // failing ends in the catch below
            const owners = await this.readOwnersUntil(held, Date.now() + this.ttl / 2);
            const lost = held.filter(account => owners.get(account) !== this.id);
            for (const account of lost) {
                this.held.delete(account);
            }
            await this.stopServingLost(lost);
            this.lease.extend(this.leaseStart + this.ttl - this.leaseSafety);
            this.logger.warn({ msg: 'Rejoined the cluster', instance: this.id, kept: this.held.size, lost: lost.length });
        })()
            .catch(err => {
                // Fail closed: a recovery that did not settle which accounts are still ours must not
                // leave a registered record whose next renewal resumes the lease with all of them
                this.logger.error({ msg: 'Failed to recover cluster membership', instance: this.id, err });
                return this.giveUpEverything('Stopped serving every account after a failed recovery').catch(err =>
                    this.logger.error({ msg: 'Failed to stop serving accounts after a failed recovery', instance: this.id, err })
                );
            })
            .finally(() => {
                // The grace that spares dead-looking owners runs from here: the others reconnect on
                // their own schedule once Redis is back
                this.redisTroubleAt = Date.now();
                this.pendingFull = true;
                this.fencing = null;
            });
        return this.fencing;
    }

    /**
     * Reads the owners of the accounts, retrying a failed read until the deadline
     * @param {string[]} accounts
     * @param {number} deadline - Date.now() value
     * @returns {Promise<Map>} Rejects with the last failure when no read succeeded in time
     */
    async readOwnersUntil(accounts, deadline) {
        for (;;) {
            try {
                return await store.readOwners(this.redis, accounts);
            } catch (err) {
                if (this.closing || Date.now() + this.retryDelay() >= deadline) {
                    throw err;
                }
                this.logger.warn({ msg: 'Failed to read account owners while rejoining the cluster, retrying', instance: this.id, err });
            }
            await timers.setTimeout(this.retryDelay());
        }
    }

    retryDelay() {
        return Math.min(1000, this.interval);
    }

    /**
     * The fail-closed end of a fence: revokes the lease so nothing held back goes out, closes every
     * account, and registers anew unless the record is already back; the next passes claim back what
     * placement gives this instance. With nothing held, a renewal may extend the lease again
     * @param {string} msg
     */
    async giveUpEverything(msg) {
        const lost = [...this.held];
        this.held.clear();
        this.lease.revoke();
        this.logger.error({ msg, instance: this.id, accounts: lost.length });
        await this.stopServingLost(lost);
        if (!this.registered) {
            await this.register();
        }
    }

    /** Stops serving accounts here, STOP_CONCURRENCY at a time */
    async stopServingMany(accounts, opts) {
        await mapConcurrent(accounts, STOP_CONCURRENCY, account => this.hooks.stopServing(account, opts));
    }

    async stopServingLost(accounts) {
        if (!accounts.length) {
            return;
        }
        try {
            await this.stopServingMany(accounts, { lost: true });
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
        // Every instance plans it with its own view of the members and the one placement picks
        // claims it, so a view that is behind a membership change on one instance does not leave the
        // account waiting for the next full pass
        this.bus.publish('claim', { accounts: [account] });
        this.requestPass([account]);
    }

    /** An account was deleted; its owner record went with it */
    accountDeleted(account) {
        this.held.delete(account);
        this.unownedSince.delete(account);
    }

    /** The live record of an instance, re-reading membership once when it is not known yet */
    async peer(id) {
        let record = this.live.get(id);
        if (!record && Date.now() - this.liveReadAt > 1000) {
            await this.refreshLive();
            record = this.live.get(id);
        }
        // An instance of another protocol may not understand the call
        return record && record.protocol === PROTOCOL ? record : null;
    }

    /**
     * Runs an account command on the instance that owns the account, once. A failure that only
     * means the account is between owners (none recorded, the owner let it go, or the account moved
     * on while the call could not connect) is a WorkerNotAvailable with `ownerUnsettled`, which the
     * caller retries with what is left of its budget (server.js commandAccountOperation())
     * @param {Object} message - The command, with `account`
     * @param {Object} [opts]
     * @param {number} [opts.timeout] - What is left of the command's budget; the owner lookups come
     *   out of it, and a command with too little left is not sent
     * @param {boolean} [opts.stream] - The answer is a download
     * @returns {Promise<*>}
     */
    async forward(message, opts = {}) {
        // The default is the cluster call's own; every caller in server.js passes its budget
        const { timeout = 10000, stream } = opts;
        const started = process.hrtime.bigint();
        const startedAt = Date.now();
        let outcome = 'ok';
        try {
            const owner = await store.readOwner(this.redis, message.account);
            if (!owner || owner === this.id) {
                // Nobody owns it, or this instance claimed it and is still connecting it
                outcome = 'unowned';
                throw noHandlerError(true);
            }
            const peer = await this.peer(owner);
            if (!peer || !peer.address) {
                // A dead owner, or one that takes no calls: neither clears in moments
                outcome = 'unreachable';
                throw noHandlerError(false);
            }
            // The lookups above can take a while on a busy Redis, and the caller gives up when the
            // budget runs out: a command sent on the whole of it ran on the owner after that,
            // where retrying an upload or a submission then did it twice
            const left = remainingTimeout(timeout, startedAt);
            if (!left) {
                outcome = 'timeout';
                throw statusError('Request timed out', 'Timeout', 504);
            }
            try {
                return await this.rpcClient.call(peer, { ...message, timeout: left }, { timeout: left, stream });
            } catch (err) {
                outcome = err.code === 'Timeout' ? 'timeout' : 'error';
                // A connection refused or never made did not run the command. Worth another try only
                // when the account moved on: the same address would just fail again, as slowly
                if (err.notDelivered && (await store.readOwner(this.redis, message.account)) !== owner) {
                    throw noHandlerError(true);
                }
                if (err.code === 'NotOwnedHere' || err.code === 'ClusterUnreachable' || err.code === 'ClusterCallFailed' || err.code === 'ClusterAuthFailed') {
                    this.logger[this.forwardFailureLevel(owner, err.code)]({
                        msg: 'Forwarded account command failed',
                        instance: this.id,
                        account: message.account,
                        cmd: message.cmd,
                        to: owner,
                        err
                    });
                    // The owner said it does not serve the account: it claimed it and is setting it
                    // up, or just released it. An owner that cannot be reached will not recover soon
                    throw noHandlerError(err.code === 'NotOwnedHere');
                }
                throw err;
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
            throw statusError('The instance that holds this data is no longer running', 'InstanceGone', 410);
        }
        return await this.rpcClient.call(peer, message, opts);
    }

    /** A call from another instance */
    async receiveCall(message) {
        if (!message || typeof message.cmd !== 'string') {
            throw notOwnedHereError();
        }
        if (message.cmd === 'clusterPing') {
            return { response: { id: this.id } };
        }
        return await this.hooks.handleCall(message);
    }

    /**
     * Calls this instance at the address it advertises, the way the other instances will. An
     * address that does not lead back here (a wrong EENGINE_CLUSTER_ADDRESS, an interface picked
     * that peers cannot use, a listener bound to loopback) leaves every forwarded call for this
     * instance's accounts failing, and nothing else would say why. Logged, not fatal: a lone
     * instance never forwards anything
     * @returns {Promise<boolean>}
     */
    async checkOwnAddress() {
        if (!this.address) {
            return false;
        }
        try {
            const answer = await this.rpcClient.call({ id: this.id, address: this.address }, { cmd: 'clusterPing' }, { timeout: 2000 });
            if (answer && answer.id === this.id) {
                return true;
            }
            this.logger.error({
                msg: 'The advertised cluster address leads to another instance',
                instance: this.id,
                address: this.address,
                answeredBy: answer && answer.id
            });
        } catch (err) {
            this.logger.error({
                msg: 'The advertised cluster address does not lead back to this instance, other instances cannot forward calls here. Check EENGINE_CLUSTER_ADDRESS and EENGINE_CLUSTER_HOST',
                instance: this.id,
                address: this.address,
                err
            });
        }
        return false;
    }

    /** Broadcasts to the other instances */
    broadcast(type, data) {
        this.bus.publish(type, data);
    }

    onBusMessage(type, data, from) {
        switch (type) {
            case 'joined':
            case 'left':
                // Read the members now rather than at the next tick; a change that matters to
                // placement asks for a full pass from there (refreshLive())
                if (this.registered && !this.closing) {
                    this.scheduleTick(50);
                }
                return;
            case 'claim':
                if (data && Array.isArray(data.accounts)) {
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
}

module.exports = { ClusterCoordinator, resolveInstanceId, resolveAddress, notOwnedHereError, noHandlerError };
