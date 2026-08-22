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
    let open = 0;
    for (const stream of mcpListenStreams) {
        if (stream.mcpSubscription && stream.mcpSubscription.credentialId === id) {
            open++;
        }
    }
    return open < MAX_STREAMS_PER_CREDENTIAL;
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

    // Independent yes/no checks about separate accounts, so they run concurrently - serialized,
    // a broad subscription would pay one full request pipeline per URI in connect latency. In
    // batches rather than all at once: every check is a full injected request, and one client
    // should not be able to put twenty of those in flight with a single POST.
    const uris = [];
    for (let pos = 0; pos < accounts.length; pos += AUTH_CHECK_CONCURRENCY) {
        const batch = accounts.slice(pos, pos + AUTH_CHECK_CONCURRENCY);
        const admitted = await Promise.all(
            batch.map(async account => {
                const res = await apiInject({ server, request, method: 'get', url: `/v1/account/${encodeURIComponent(account)}` });
                return res.statusCode < 400 ? accountUri(account) : null;
            })
        );
        uris.push(...admitted.filter(Boolean));
    }
    if (uris.length) {
        accepted.resourceSubscriptions = uris;
    }

    return accepted;
}

/**
 * Opens the SSE response stream for an accepted subscriptions/listen request.
 *
 * @param {Object} opts
 * @param {Object} opts.h - Hapi response toolkit
 * @param {Object} opts.request - the /mcp request, for the credential the stream is counted under
 * @param {*} opts.subscriptionId - the JSON-RPC id of the subscriptions/listen request
 * @param {Object} opts.accepted - the acknowledged filter subset from acceptFilter()
 * @returns {Object} Hapi response
 */
function openListenStream({ h, request, subscriptionId, accepted }) {
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
        resourceUris: new Set(accepted.resourceSubscriptions || [])
    };

    return response;
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

module.exports = { acceptFilter, openListenStream, publishAccountChange, canOpenListenStream, MAX_STREAMS_PER_CREDENTIAL, MAX_RESOURCE_SUBSCRIPTIONS };
