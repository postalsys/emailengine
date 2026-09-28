'use strict';

// subscriptions/listen: the long-lived notification stream of the modern (2026-07-28) protocol
// revision, bridged from the account state-change fanout that already feeds /v1/changes and the
// admin dashboard.
//
// What is honored, and why only this: `resourceSubscriptions` on account resource URIs
// (emailengine://account/{id}), delivered as notifications/resources/updated whenever that
// account's state changes. The other filter fields are omitted from the acknowledgment, which
// per the spec means "not honored": the tool list is static for the life of the worker, so
// toolsListChanged would never fire, and prompts do not exist here.
//
// Authorization is per subscribed account, enforced by injecting GET /v1/account/{account} with
// the caller's own credential at accept time - a URI the credential cannot read is silently
// dropped from the acknowledged subset, exactly as the spec expects unsupported entries to be.
// This deliberately reuses the REST enforcement rather than inventing a subscription-specific
// rule; the acknowledgment tells the client what survived.
//
// Every stream lives in the API worker that accepted it. The main thread already fans account
// state changes out to every API worker for the admin SSE feed, so with multiple API workers
// each one feeds its own streams and nothing needs affinity.

const { openSseStream } = require('../response-stream');
const { apiInject } = require('./inject');
const { accountUri, parseAccountUri } = require('./resources');

// Live MCP listen streams in this worker. Deliberately not the change-feed registry in
// lib/response-stream.js: these streams carry JSON-RPC frames, and the two fanouts must not
// receive each other's messages.
const mcpListenStreams = new Set();

const META_SUBSCRIPTION_ID = 'io.modelcontextprotocol/subscriptionId';

// Accept-time authorization injects one full API request per subscribed URI - token read,
// permission check, account read - so a listen request is an amplifier by construction. Three
// bounds keep it one: how many URIs a request may name, how many of those checks run at once,
// and how many streams a single credential may hold open.
//
// The stream cap counts what THIS worker holds, because that is what the registry below can see -
// with EENGINE_WORKERS_API above 1 a credential can hold the cap on each of them. That is the
// right bound anyway: the cost this limits is per-worker (the registry walk on every fanout, the
// sockets on that process), and nothing here needs an instance-wide count.
const MAX_RESOURCE_SUBSCRIPTIONS = 20;
const AUTH_CHECK_CONCURRENCY = 5;
const MAX_STREAMS_PER_CREDENTIAL = 4;

// How often an open stream re-asks whether its credential may still read what it subscribed to.
// Authorization used to happen once, at accept time, so a revoked token kept receiving account
// change notifications for as long as the socket stayed up.
const LISTEN_RECHECK_INTERVAL = 60 * 1000;

// One timer serves every open stream: it runs while any stream has a server to re-check against
// and stops with the last of them. A timer per stream was one setInterval and one round of
// injected requests per stream, even for streams of the same credential watching the same
// accounts. The period is the shortest one asked for, which outside the tests is always
// LISTEN_RECHECK_INTERVAL.
let recheckTimer = null;
let recheckPeriod = Infinity;
let recheckInFlight = null;

// Streams per credential that have been admitted but are still waiting on the accept-time
// authorization checks. Counted alongside the open ones: the checks are awaited before the stream
// exists, and counting only open streams let concurrent requests all pass the cap at once and each
// start its own round of injected requests.
const pendingListenStreams = new Map();

/**
 * The credential a stream belongs to, for the per-credential stream cap. Token records are keyed
 * by their hash; the `preauth` caller of the disableTokens mode has no record and shares one
 * bucket, which is correct - it is one anonymous caller as far as this instance can tell.
 */
function credentialId(request) {
    return (request.auth && request.auth.artifacts && request.auth.artifacts.id) || 'preauth';
}

/**
 * Whether this credential may open another listen stream on this worker.
 */
function canOpenListenStream(request) {
    const id = credentialId(request);
    let open = pendingListenStreams.get(id) || 0;
    for (const stream of mcpListenStreams) {
        if (stream.mcpSubscription && stream.mcpSubscription.credentialId === id) {
            open++;
        }
    }
    return open < MAX_STREAMS_PER_CREDENTIAL;
}

/**
 * Takes one of the credential's stream slots, synchronously, for the time between admitting a
 * listen request and registering its stream.
 *
 * @returns {Function|null} release function (idempotent), or null when the credential is at its cap
 */
function reserveListenStream(request) {
    if (!canOpenListenStream(request)) {
        return null;
    }

    const id = credentialId(request);
    pendingListenStreams.set(id, (pendingListenStreams.get(id) || 0) + 1);

    let released = false;
    return () => {
        if (released) {
            return;
        }
        released = true;
        const left = (pendingListenStreams.get(id) || 1) - 1;
        if (left > 0) {
            pendingListenStreams.set(id, left);
        } else {
            pendingListenStreams.delete(id);
        }
    };
}

/**
 * Validates a requested notification filter against what the caller may actually see.
 *
 * @returns {Promise<Object>} the acknowledged filter subset
 */
async function acceptFilter({ server, request, filter }) {
    const accepted = {};

    const requested = Array.isArray(filter.resourceSubscriptions) ? filter.resourceSubscriptions.slice(0, MAX_RESOURCE_SUBSCRIPTIONS) : [];

    const accounts = [...new Set(requested.map(uri => parseAccountUri(uri)).filter(Boolean))];

    const statuses = await probeAccounts({ server, request, accounts });
    const uris = accounts.filter(account => statuses.get(account) < 400).map(account => accountUri(account));
    if (uris.length) {
        accepted.resourceSubscriptions = uris;
    }

    return accepted;
}

/**
 * Asks, with the caller's own credential, whether each account may be read: one injected
 * GET /v1/account/{account} per account. Independent yes/no checks about separate accounts, so
 * they run concurrently - serialized, a broad subscription would pay one full request pipeline
 * per URI in connect latency. In batches rather than all at once: every check is a full injected
 * request, and one client should not be able to put twenty of those in flight with a single POST.
 *
 * @returns {Promise<Map>} account -> HTTP status of its check. A failed dispatch rejects; the
 *   caller decides whether that fails the request (accept time) or changes nothing (re-check)
 */
async function probeAccounts({ server, request, accounts }) {
    const statuses = new Map();
    for (let pos = 0; pos < accounts.length; pos += AUTH_CHECK_CONCURRENCY) {
        const batch = accounts.slice(pos, pos + AUTH_CHECK_CONCURRENCY);
        const results = await Promise.all(
            batch.map(account => apiInject({ server, request, method: 'get', url: `/v1/account/${encodeURIComponent(account)}` }))
        );
        batch.forEach((account, i) => statuses.set(account, results[i].statusCode));
    }
    return statuses;
}

/**
 * Re-runs the per-account authorization of every open stream, once per (credential, account)
 * pair however many streams share it. A URI the credential can no longer read (403) or that no
 * longer exists (404) is dropped from each stream holding it; a credential that is gone (401), or
 * a stream left with nothing it may read, is closed. Anything else, a 5xx or a failed dispatch,
 * is treated as transient and changes nothing. A call made while a pass is running joins it.
 *
 * @returns {Promise<void>}
 */
function recheckListenStreams() {
    if (!recheckInFlight) {
        recheckInFlight = runRecheckPass().finally(() => {
            recheckInFlight = null;
        });
    }
    return recheckInFlight;
}

async function runRecheckPass() {
    // Streams grouped by credential, with the union of the accounts they watch
    const groups = new Map();
    for (const stream of mcpListenStreams) {
        const subscription = stream.mcpSubscription;
        if (!subscription || !subscription.recheck || !subscription.resourceUris.size) {
            continue;
        }
        let group = groups.get(subscription.credentialId);
        if (!group) {
            group = { server: subscription.recheck.server, request: subscription.recheck.request, accounts: new Set(), streams: [] };
            groups.set(subscription.credentialId, group);
        }
        group.streams.push(stream);
        for (const uri of subscription.resourceUris) {
            group.accounts.add(parseAccountUri(uri));
        }
    }

    for (const group of groups.values()) {
        let statuses;
        try {
            statuses = await probeAccounts({ server: group.server, request: group.request, accounts: [...group.accounts] });
        } catch (err) {
            // a failed dispatch says nothing about the credential
            continue;
        }

        for (const stream of group.streams) {
            if (stream._finalized || stream.destroyed) {
                continue;
            }
            const subscription = stream.mcpSubscription;
            let revoked = false;
            for (const uri of [...subscription.resourceUris]) {
                const status = statuses.get(parseAccountUri(uri));
                if (status === 401) {
                    revoked = true;
                    break;
                }
                if (status === 403 || status === 404) {
                    subscription.resourceUris.delete(uri);
                }
            }
            if (revoked || !subscription.resourceUris.size) {
                stream.finalize();
            }
        }
    }
}

/**
 * Starts the shared re-check timer, or shortens its period to the one asked for.
 */
function ensureRecheckTimer(period) {
    if (recheckTimer && period >= recheckPeriod) {
        return;
    }
    if (recheckTimer) {
        clearInterval(recheckTimer);
    }
    recheckPeriod = period;
    recheckTimer = setInterval(recheckListenStreams, period);
    recheckTimer.unref();
}

/**
 * Stops the shared timer once no open stream is left to re-check.
 */
function releaseRecheckTimer() {
    for (const stream of mcpListenStreams) {
        if (stream.mcpSubscription && stream.mcpSubscription.recheck) {
            return;
        }
    }
    if (recheckTimer) {
        clearInterval(recheckTimer);
        recheckTimer = null;
        recheckPeriod = Infinity;
    }
}

/**
 * Opens the SSE response stream for an accepted subscriptions/listen request.
 *
 * @param {Object} opts
 * @param {Object} opts.h - Hapi response toolkit
 * @param {Object} opts.request - the /mcp request, for the credential the stream is counted under
 * @param {*} opts.subscriptionId - the JSON-RPC id of the subscriptions/listen request
 * @param {Object} opts.accepted - the acknowledged filter subset from acceptFilter()
 * @param {Object} [opts.server] - Hapi server; when given, the stream joins the periodic
 *   re-check of its authorization
 * @param {number} [opts.recheckInterval] - period of the shared re-check timer, defaults to
 *   LISTEN_RECHECK_INTERVAL; a shorter one than the timer already runs at replaces it
 * @returns {Object} Hapi response
 */
function openListenStream({ h, request, subscriptionId, accepted, server, recheckInterval }) {
    const { stream, response } = openSseStream(h, {
        registry: mcpListenStreams,
        onOpen: opened =>
            opened.sendMessage({
                jsonrpc: '2.0',
                method: 'notifications/subscriptions/acknowledged',
                params: {
                    _meta: { [META_SUBSCRIPTION_ID]: subscriptionId },
                    notifications: accepted
                }
            })
    });

    stream.mcpSubscription = {
        id: subscriptionId,
        credentialId: credentialId(request),
        resourceUris: new Set(accepted.resourceSubscriptions || []),
        // What the periodic re-check asks again with: this stream's own credential
        recheck: server ? { server, request } : null
    };

    if (server) {
        ensureRecheckTimer(recheckInterval || LISTEN_RECHECK_INTERVAL);
        // finalize() has already dropped the stream from the registry by the time this fires
        stream.once('close', releaseRecheckTimer);
    }

    return response;
}

/**
 * The whole subscriptions/listen admission: reserve a stream slot, authorize the requested
 * subscriptions, open the stream. The slot is taken before the first await and held until the
 * stream is registered, so concurrent requests cannot all pass the cap.
 *
 * @returns {Promise<Object|null>} Hapi response, or null when the credential is at its stream cap
 */
async function handleListen({ h, server, request, subscriptionId, filter, recheckInterval }) {
    const release = reserveListenStream(request);
    if (!release) {
        return null;
    }

    try {
        const accepted = await acceptFilter({ server, request, filter });
        // Registers the stream synchronously, so releasing the reservation below does not open a gap
        return openListenStream({ h, request, subscriptionId, accepted, server, recheckInterval });
    } finally {
        release();
    }
}

/**
 * Fans one account state-change event out to the listen streams that subscribed to it.
 * Called from the API worker's 'change' message handler, alongside the admin feed fanout.
 */
function publishAccountChange(data, logger) {
    if (!mcpListenStreams.size || !data || !data.account) {
        return;
    }

    const uri = accountUri(data.account);

    for (const stream of mcpListenStreams) {
        const subscription = stream.mcpSubscription;
        if (!subscription || !subscription.resourceUris.has(uri)) {
            continue;
        }

        try {
            stream.sendMessage({
                jsonrpc: '2.0',
                method: 'notifications/resources/updated',
                params: {
                    _meta: { [META_SUBSCRIPTION_ID]: subscription.id },
                    uri
                }
            });
        } catch (err) {
            if (logger) {
                logger.warn({ msg: 'Failed to publish MCP resource update', err, account: data.account });
            }
        }
    }
}

module.exports = {
    acceptFilter,
    openListenStream,
    handleListen,
    reserveListenStream,
    probeAccounts,
    recheckListenStreams,
    publishAccountChange,
    canOpenListenStream,
    MAX_STREAMS_PER_CREDENTIAL,
    MAX_RESOURCE_SUBSCRIPTIONS
};
