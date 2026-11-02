'use strict';

// Calls between the instances of a cluster.
//
// An account operation that reaches an instance which does not own the account is sent to the
// owner over HTTP: the main thread of the receiving instance runs it against its own worker
// exactly as if one of its workers had asked, and the answer comes back the same way. Downloads
// (a message source, an attachment) come back as a stream, with the metadata the worker returned
// in a response header.
//
// Every call is signed with a key the instances share through Redis (cluster:secret), over the
// method, path, sender, recipient, a timestamp, a nonce and a hash of the body. The hash travels in
// a header, so the signature is checked before the body is read: whoever can reach the port without
// the key cannot make the instance buffer anything. The receiver only answers a call addressed to its
// own instance id, made within CLOCK_WINDOW of its clock, with a nonce it has not seen, and with a
// body matching the signed hash. The listener is meant for the pod network, but nothing on it
// depends on the network being private.
//
// Wire format: the request body is a msgpack-encoded command. A plain answer is a msgpack object,
// { r: response } or { e: packed error }; a stream is the raw bytes, marked by the
// x-ee-cluster-stream header, with the worker's answer in x-ee-cluster-meta.

const http = require('http');
const crypto = require('crypto');
const { pipeline } = require('stream');
const { Agent, request } = require('undici');
const msgpack = require('../msgpack');
const { packRpcError, unpackRpcError } = require('../worker-rpc-error');
const { statusError } = require('../utils/status-error');

const CALL_PATH = '/cluster/v1/call';
const PROTOCOL_HEADER_PREFIX = 'x-ee-cluster-';

// How far apart two instances' clocks may be, and so how long a nonce has to be remembered
const CLOCK_WINDOW = 60 * 1000;

// Request bodies carry a message to submit or upload, so they are allowed to be large
const DEFAULT_MAX_BODY = 128 * 1024 * 1024;

// A download that stops moving for this long is abandoned
const STREAM_IDLE_TIMEOUT = 5 * 60 * 1000;

// Extra time a remote call gets over the command's own timeout: the hop, and the remote main thread
const TIMEOUT_MARGIN = 2000;

// How long a cluster call waits for its connection. The address of a pod that is gone usually
// answers nothing at all rather than refusing, and the library default of ten seconds made every
// call to a crashed owner hang that long before failing
const CONNECT_TIMEOUT = 2000;

// Connection failures that prove the call never reached the other instance
const NOT_DELIVERED_CODES = new Set(['ECONNREFUSED', 'UND_ERR_CONNECT_TIMEOUT']);

function sha256(buffer) {
    return crypto.createHash('sha256').update(buffer).digest('hex');
}

function signatureBase({ method, path, from, to, ts, nonce, bodyHash }) {
    return [method, path, from, to, ts, nonce, bodyHash].join('\n');
}

/**
 * Signs a call
 * @returns {Object} The headers to send
 */
function signRequest(secret, { method, path, from, to, body, now = Date.now() }) {
    const ts = String(now);
    const nonce = crypto.randomBytes(12).toString('hex');
    const bodyHash = sha256(body);
    const signature = crypto.createHmac('sha256', secret).update(signatureBase({ method, path, from, to, ts, nonce, bodyHash })).digest('hex');
    return {
        [`${PROTOCOL_HEADER_PREFIX}from`]: from,
        [`${PROTOCOL_HEADER_PREFIX}to`]: to,
        [`${PROTOCOL_HEADER_PREFIX}ts`]: ts,
        [`${PROTOCOL_HEADER_PREFIX}nonce`]: nonce,
        [`${PROTOCOL_HEADER_PREFIX}body`]: bodyHash,
        [`${PROTOCOL_HEADER_PREFIX}signature`]: signature
    };
}

/** Nonces seen within the clock window, so a captured call cannot be replayed */
class NonceCache {
    constructor(windowMs = CLOCK_WINDOW) {
        this.windowMs = windowMs;
        this.entries = new Map();
    }

    /** Records a nonce; false when it was already used */
    remember(nonce, now = Date.now()) {
        this.prune(now);
        if (this.entries.has(nonce)) {
            return false;
        }
        // A call is accepted while its timestamp is within the window on either side, so the nonce
        // has to be kept for twice the window
        this.entries.set(nonce, now + 2 * this.windowMs);
        return true;
    }

    /**
     * Drops the expired nonces. Every entry lives the same two windows and a Map keeps insertion
     * order, so the entries come oldest first and the scan ends at the first one still alive: a
     * prune on a busy listener costs the expired entries, not the whole map. A clock that stepped
     * back leaves newer entries behind older ones with later expiries, which only delays their
     * removal; a nonce kept for longer is never a replay let through
     */
    prune(now = Date.now()) {
        for (const [nonce, expires] of this.entries) {
            if (expires > now) {
                return;
            }
            this.entries.delete(nonce);
        }
    }
}

/** The signature headers of a received call */
function readSignatureHeaders(headers) {
    return {
        from: headers[`${PROTOCOL_HEADER_PREFIX}from`],
        to: headers[`${PROTOCOL_HEADER_PREFIX}to`],
        ts: headers[`${PROTOCOL_HEADER_PREFIX}ts`],
        nonce: headers[`${PROTOCOL_HEADER_PREFIX}nonce`],
        bodyHash: headers[`${PROTOCOL_HEADER_PREFIX}body`],
        signature: headers[`${PROTOCOL_HEADER_PREFIX}signature`]
    };
}

const HEX_SHA256 = /^[0-9a-f]{64}$/;

// Why a request that is not shaped like a call is refused: a scanner or a stray client rather than
// a peer, so the listener logs it below the level the other refusals get
const UNSIGNED = 'missing signature';

/**
 * The checks that need neither the key nor the body
 * @returns {string|null} Why the call is refused, null when it is worth checking the signature
 */
function precheckHeaders({ headers, me, now = Date.now() }) {
    const { from, to, ts, nonce, bodyHash, signature } = readSignatureHeaders(headers);

    if (!from || !to || !ts || !nonce || !HEX_SHA256.test(bodyHash || '') || !HEX_SHA256.test(signature || '')) {
        return UNSIGNED;
    }
    if (to !== me) {
        return 'addressed to another instance';
    }
    const sent = Number(ts);
    if (!Number.isFinite(sent) || Math.abs(now - sent) > CLOCK_WINDOW) {
        return 'timestamp outside the accepted window';
    }
    return null;
}

/**
 * Checks everything about a received call that needs no body, the signature included: the body hash
 * it covers comes in a header. A request that fails is refused before its body is read
 * @returns {string|null} Why it is refused, null when the body is worth reading
 */
function verifyHeaders(secret, { method, path, headers, me, nonces, now = Date.now() }) {
    const early = precheckHeaders({ headers, me, now });
    if (early) {
        return early;
    }

    const { from, to, ts, nonce, bodyHash, signature } = readSignatureHeaders(headers);
    const expected = crypto.createHmac('sha256', secret).update(signatureBase({ method, path, from, to, ts, nonce, bodyHash })).digest();
    if (!crypto.timingSafeEqual(expected, Buffer.from(signature, 'hex'))) {
        return 'bad signature';
    }
    // Only after the signature: an unsigned request must not be able to fill the cache
    if (!nonces.remember(nonce, now)) {
        return 'replayed';
    }
    return null;
}

/** Whether a body is the one the verified headers signed */
function bodyMatches(headers, body) {
    return sha256(body) === readSignatureHeaders(headers).bodyHash;
}

/**
 * Turns values msgpack cannot carry into ones it can: an ArrayBuffer would become an empty map. Copy
 * on write: an object or array is rebuilt only when something inside it changed, which a command or
 * answer rarely needs, so the value usually comes back as it went in
 */
function toWire(value) {
    if (value instanceof ArrayBuffer) {
        return Buffer.from(value);
    }
    if (value === null || typeof value !== 'object' || Buffer.isBuffer(value) || ArrayBuffer.isView(value) || value instanceof Date) {
        return value;
    }
    let copy = null;
    const keys = Object.keys(value);
    for (const key of keys) {
        const wired = toWire(value[key]);
        if (wired !== value[key] && !copy) {
            copy = Array.isArray(value) ? value.slice() : Object.assign({}, value);
        }
        if (copy) {
            copy[key] = wired;
        }
    }
    return copy || value;
}

const clusterError = (message, code, statusCode = 503) => statusError(message, code, statusCode);

function readBody(req, maxBodySize) {
    return new Promise((resolve, reject) => {
        const chunks = [];
        let size = 0;
        req.on('data', chunk => {
            size += chunk.length;
            if (size > maxBodySize) {
                reject(clusterError('Cluster call body too large', 'ClusterBodyTooLarge', 413));
                req.destroy();
                return;
            }
            chunks.push(chunk);
        });
        req.on('end', () => resolve(Buffer.concat(chunks)));
        req.on('error', reject);
    });
}

/**
 * The listener that receives calls from the other instances
 * @param {Object} opts
 * @param {string} opts.instanceId
 * @param {Function} opts.getSecret - Resolves to the signing key
 * @param {Function} opts.handle - (message) => { response } or { stream: { meta, readable } }
 * @param {Object} opts.logger
 * @param {number} [opts.maxBodySize]
 * @returns {Object} `{ listen(port, host), close() }`
 */
function createRpcServer({ instanceId, getSecret, handle, logger, maxBodySize = DEFAULT_MAX_BODY }) {
    const nonces = new NonceCache();

    const reply = (res, statusCode, payload) => {
        if (res.headersSent) {
            res.destroy();
            return;
        }
        const body = msgpack.encode(payload);
        res.writeHead(statusCode, { 'Content-Type': 'application/x-msgpack', 'Content-Length': body.length });
        res.end(body);
    };

    const handleRequest = async (req, res) => {
        if (req.method !== 'POST' || req.url !== CALL_PATH) {
            res.writeHead(404, { 'Content-Type': 'text/plain' });
            res.end('Not found');
            req.resume();
            return;
        }

        const refuse = reason => {
            // A call carrying the cluster headers that is refused is a peer with the wrong key, a
            // skewed clock or a wrong address, which an operator has to see
            logger[reason === UNSIGNED ? 'debug' : 'warn']({
                msg: 'Refused a cluster call',
                reason,
                from: req.headers[`${PROTOCOL_HEADER_PREFIX}from`],
                remoteAddress: req.socket.remoteAddress
            });
            res.writeHead(401, { 'Content-Type': 'text/plain', Connection: 'close' });
            res.end('Unauthorized');
        };

        // Refused before the body is read, see verifyHeaders(); a request that is not even shaped
        // like a call is refused without waiting for the key
        const reason =
            precheckHeaders({ headers: req.headers, me: instanceId }) ||
            verifyHeaders(await getSecret(), { method: req.method, path: req.url, headers: req.headers, me: instanceId, nonces });
        if (reason) {
            req.resume();
            return refuse(reason);
        }

        let message;
        try {
            const body = await readBody(req, maxBodySize);
            if (!bodyMatches(req.headers, body)) {
                return refuse('bad signature');
            }
            message = msgpack.decode(body);
        } catch (err) {
            if (!res.headersSent) {
                res.writeHead(err.statusCode === 413 ? 413 : 400, { 'Content-Type': 'text/plain' });
                res.end('Bad request');
            }
            return;
        }

        let result;
        try {
            result = await handle(message);
        } catch (err) {
            return reply(res, 200, { e: packRpcError(err) });
        }

        if (result && result.stream) {
            const { meta, readable } = result.stream;
            if (res.destroyed || res.writableEnded) {
                // The caller gave up while the worker was getting the download ready (a timeout, or
                // this process was stalled). Nobody reads it: release the worker's download, and the
                // mailbox lock it holds, instead of piping into a closed response, which throws
                readable.destroy();
                return;
            }
            res.writeHead(200, {
                'Content-Type': 'application/octet-stream',
                [`${PROTOCOL_HEADER_PREFIX}stream`]: '1',
                [`${PROTOCOL_HEADER_PREFIX}meta`]: msgpack.encode(toWire(meta === undefined ? null : meta)).toString('base64')
            });
            // A caller that goes away destroys the response, and pipeline() passes that upstream so
            // the worker stops reading from the mail server
            pipeline(readable, res, err => {
                if (err && err.code !== 'ERR_STREAM_PREMATURE_CLOSE') {
                    logger.warn({ msg: 'Cluster stream failed', cmd: message && message.cmd, err });
                }
            });
            return;
        }

        try {
            reply(res, 200, { r: toWire(result ? result.response : null) });
        } catch (err) {
            logger.error({ msg: 'Failed to encode a cluster call answer', cmd: message && message.cmd, err });
            reply(res, 200, { e: packRpcError(clusterError('Unable to encode the answer', 'ClusterEncodeFailed', 500)) });
        }
    };

    // Once close() was called, every answer ends its connection. server.close() closes only the
    // connections idle at that moment, and one that was answering a call would otherwise stay open
    // for as long as the caller keeps it (about a minute), holding up the shutdown waiting on it
    let closing = false;
    const answering = new Set();

    // The handler is async; anything it lets escape would be an unhandled rejection that takes the
    // whole main thread down, so it ends here as a failed call instead
    const server = http.createServer((req, res) => {
        if (closing) {
            res.shouldKeepAlive = false;
        }
        answering.add(res);
        res.once('close', () => {
            answering.delete(res);
            if (closing) {
                // A download whose headers went out before close() still asked to keep its connection
                setImmediate(() => server.closeIdleConnections?.());
            }
        });
        handleRequest(req, res).catch(err => {
            logger.error({ msg: 'Failed to answer a cluster call', err });
            res.destroy();
        });
    });

    // Calls reuse connections; keep them open past the client's own idle timeout
    server.keepAliveTimeout = 65 * 1000;
    server.headersTimeout = 70 * 1000;

    // Expired nonces go whether or not calls keep arriving: a burst of calls followed by silence
    // would otherwise be remembered until the next call
    const pruneTimer = setInterval(() => nonces.prune(), CLOCK_WINDOW);
    pruneTimer.unref();

    return {
        listen(port, host) {
            return new Promise((resolve, reject) => {
                server.once('error', reject);
                server.listen(port, host, () => {
                    server.removeListener('error', reject);
                    // A failed accept (out of file descriptors) is emitted here; without a listener it
                    // would reach the global handler and end the main thread with every account
                    server.on('error', err => logger.error({ msg: 'Cluster call listener error', err }));
                    resolve(server.address());
                });
            });
        },
        close() {
            closing = true;
            clearInterval(pruneTimer);
            for (const res of answering) {
                if (!res.headersSent) {
                    res.shouldKeepAlive = false;
                }
            }
            return new Promise(resolve => {
                server.close(() => resolve());
                server.closeIdleConnections?.();
            });
        }
    };
}

/**
 * Makes calls to the other instances
 * @param {Object} opts
 * @param {string} opts.instanceId
 * @param {Function} opts.getSecret
 * @returns {Object} `{ call(peer, message, opts), close() }`
 */
function createRpcClient({ instanceId, getSecret }) {
    // Cluster traffic never goes through the HTTP proxy the rest of EmailEngine may use
    const dispatcher = new Agent({ keepAliveTimeout: 30 * 1000, keepAliveMaxTimeout: 60 * 1000, connections: 128, connect: { timeout: CONNECT_TIMEOUT } });

    /**
     * @param {Object} peer - `{ id, address }`
     * @param {Object} message - The command
     * @param {Object} [opts]
     * @param {number} [opts.timeout] - Milliseconds the command may take
     * @param {boolean} [opts.stream] - The answer is a download
     * @returns {Promise<*>} The response, or `{ meta, body }` for a stream
     */
    async function call(peer, message, { timeout = 10000, stream = false } = {}) {
        const body = msgpack.encode(toWire(message));
        const headers = Object.assign(
            { 'content-type': 'application/x-msgpack' },
            signRequest(await getSecret(), { method: 'POST', path: CALL_PATH, from: instanceId, to: peer.id, body })
        );

        let res;
        try {
            res = await request(`http://${peer.address}${CALL_PATH}`, {
                method: 'POST',
                body,
                headers,
                dispatcher,
                headersTimeout: timeout + TIMEOUT_MARGIN,
                bodyTimeout: stream ? STREAM_IDLE_TIMEOUT : timeout + TIMEOUT_MARGIN
            });
        } catch (err) {
            const code = err.code || (err.cause && err.cause.code);
            if (code === 'UND_ERR_HEADERS_TIMEOUT' || code === 'UND_ERR_BODY_TIMEOUT') {
                const timeoutErr = clusterError('Request timed out', 'Timeout', 504);
                timeoutErr.remote = peer.id;
                throw timeoutErr;
            }
            const connectErr = clusterError(`Instance ${peer.id} could not be reached: ${err.message}`, 'ClusterUnreachable');
            // The call never arrived, so it is safe to ask again
            connectErr.notDelivered = NOT_DELIVERED_CODES.has(code);
            connectErr.remote = peer.id;
            throw connectErr;
        }

        if (res.statusCode !== 200) {
            await res.body.dump().catch(() => false);
            throw clusterError(`Instance ${peer.id} refused the call (${res.statusCode})`, res.statusCode === 401 ? 'ClusterAuthFailed' : 'ClusterCallFailed');
        }

        if (res.headers[`${PROTOCOL_HEADER_PREFIX}stream`]) {
            // The caller pipes the body only once it has the answer; a socket error before that
            // must not be an 'error' event nobody listens to. pipeline() adds its own listener
            res.body.on('error', () => false);
            let meta = null;
            const header = res.headers[`${PROTOCOL_HEADER_PREFIX}meta`];
            try {
                if (header) {
                    meta = msgpack.decode(Buffer.from(header, 'base64'));
                }
            } catch (err) {
                res.body.destroy();
                throw clusterError(`Instance ${peer.id} sent an unreadable answer`, 'ClusterCallFailed');
            }
            return { meta, body: res.body };
        }

        const payload = msgpack.decode(Buffer.from(await res.body.arrayBuffer()));
        if (payload && payload.e) {
            const err = unpackRpcError(payload.e);
            err.remote = peer.id;
            throw err;
        }
        return payload ? payload.r : null;
    }

    return {
        call,
        close() {
            return dispatcher.close().catch(() => false);
        }
    };
}

module.exports = { createRpcServer, createRpcClient, signRequest, verifyHeaders, bodyMatches, NonceCache, toWire, CALL_PATH, CLOCK_WINDOW };
