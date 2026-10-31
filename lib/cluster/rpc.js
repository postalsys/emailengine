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
// method, path, sender, recipient, a timestamp, a nonce and a hash of the body. The receiver only
// answers a call addressed to its own instance id, made within CLOCK_WINDOW of its clock, with a
// nonce it has not seen. The listener is meant for the pod network, but nothing on it depends on
// the network being private.
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
        if (this.entries.size > 1000) {
            this.prune(now);
        }
        if (this.entries.has(nonce)) {
            return false;
        }
        // A call is accepted while its timestamp is within the window on either side, so the nonce
        // has to be kept for twice the window
        this.entries.set(nonce, now + 2 * this.windowMs);
        return true;
    }

    prune(now = Date.now()) {
        for (const [nonce, expires] of this.entries) {
            if (expires <= now) {
                this.entries.delete(nonce);
            }
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
        signature: headers[`${PROTOCOL_HEADER_PREFIX}signature`]
    };
}

/**
 * The checks that need no body: a request that fails them is refused before its body is read, so
 * whoever can reach the port without the key cannot make the instance buffer large bodies
 * @returns {string|null} Why it is refused, null when the body is worth reading
 */
function precheckRequest({ headers, me, now = Date.now() }) {
    const { from, to, ts, nonce, signature } = readSignatureHeaders(headers);

    if (!from || !to || !ts || !nonce || typeof signature !== 'string' || !/^[0-9a-f]{64}$/.test(signature)) {
        return 'missing signature';
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
 * Checks a received call. Returns null when it is acceptable, otherwise a reason
 * @returns {string|null}
 */
function verifyRequest(secret, { method, path, headers, body, me, nonces, now = Date.now() }) {
    const { from, to, ts, nonce, signature } = readSignatureHeaders(headers);

    const early = precheckRequest({ headers, me, now });
    if (early) {
        return early;
    }

    const expected = crypto
        .createHmac('sha256', secret)
        .update(signatureBase({ method, path, from, to, ts, nonce, bodyHash: sha256(body) }))
        .digest();
    if (!crypto.timingSafeEqual(expected, Buffer.from(signature, 'hex'))) {
        return 'bad signature';
    }
    // Only after the signature: an unsigned request must not be able to fill the cache
    if (!nonces.remember(nonce, now)) {
        return 'replayed';
    }
    return null;
}

/** Whether a value holds an ArrayBuffer anywhere, without building anything */
function holdsArrayBuffer(value) {
    if (value instanceof ArrayBuffer) {
        return true;
    }
    if (value === null || typeof value !== 'object' || Buffer.isBuffer(value) || ArrayBuffer.isView(value) || value instanceof Date) {
        return false;
    }
    for (const key of Object.keys(value)) {
        if (holdsArrayBuffer(value[key])) {
            return true;
        }
    }
    return false;
}

/**
 * Turns values msgpack cannot carry into ones it can: an ArrayBuffer would become an empty map. The
 * value is copied only when it holds one, which a command or answer rarely does
 */
function toWire(value) {
    return holdsArrayBuffer(value) ? convertArrayBuffers(value) : value;
}

function convertArrayBuffers(value) {
    if (value instanceof ArrayBuffer) {
        return Buffer.from(value);
    }
    if (Buffer.isBuffer(value) || ArrayBuffer.isView(value) || value instanceof Date || value === null || typeof value !== 'object') {
        return value;
    }
    if (Array.isArray(value)) {
        return value.map(convertArrayBuffers);
    }
    const result = {};
    for (const key of Object.keys(value)) {
        result[key] = convertArrayBuffers(value[key]);
    }
    return result;
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
            logger.warn({ msg: 'Refused a cluster call', reason, from: req.headers[`${PROTOCOL_HEADER_PREFIX}from`], remoteAddress: req.socket.remoteAddress });
            res.writeHead(401, { 'Content-Type': 'text/plain', Connection: 'close' });
            res.end('Unauthorized');
        };

        // Refused before the body is read, see precheckRequest()
        const early = precheckRequest({ headers: req.headers, me: instanceId });
        if (early) {
            req.resume();
            return refuse(early);
        }

        let message;
        try {
            const body = await readBody(req, maxBodySize);
            const reason = verifyRequest(await getSecret(), { method: req.method, path: req.url, headers: req.headers, body, me: instanceId, nonces });
            if (reason) {
                return refuse(reason);
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

    // The handler is async; anything it lets escape would be an unhandled rejection that takes the
    // whole main thread down, so it ends here as a failed call instead
    const server = http.createServer((req, res) => {
        handleRequest(req, res).catch(err => {
            logger.error({ msg: 'Failed to answer a cluster call', err });
            res.destroy();
        });
    });

    // Calls reuse connections; keep them open past the client's own idle timeout
    server.keepAliveTimeout = 65 * 1000;
    server.headersTimeout = 70 * 1000;

    return {
        listen(port, host) {
            return new Promise((resolve, reject) => {
                server.once('error', reject);
                server.listen(port, host, () => {
                    server.removeListener('error', reject);
                    resolve(server.address());
                });
            });
        },
        close() {
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
    const dispatcher = new Agent({ keepAliveTimeout: 30 * 1000, keepAliveMaxTimeout: 60 * 1000, connections: 128 });

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
            // ECONNREFUSED means the call never arrived, so it is safe to retry elsewhere
            connectErr.notDelivered = code === 'ECONNREFUSED';
            connectErr.remote = peer.id;
            throw connectErr;
        }

        if (res.statusCode !== 200) {
            await res.body.dump().catch(() => false);
            throw clusterError(`Instance ${peer.id} refused the call (${res.statusCode})`, res.statusCode === 401 ? 'ClusterAuthFailed' : 'ClusterCallFailed');
        }

        if (res.headers[`${PROTOCOL_HEADER_PREFIX}stream`]) {
            let meta = null;
            const header = res.headers[`${PROTOCOL_HEADER_PREFIX}meta`];
            if (header) {
                meta = msgpack.decode(Buffer.from(header, 'base64'));
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

module.exports = { createRpcServer, createRpcClient, signRequest, verifyRequest, precheckRequest, NonceCache, toWire, CALL_PATH, CLOCK_WINDOW };
