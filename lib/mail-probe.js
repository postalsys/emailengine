'use strict';

// Checks whether a host runs a mail server, for the last autodiscovery stage: a domain that
// publishes nothing about its mail is often served by its MX host or an `imap.`/`smtp.` name, and
// the only way to tell is to connect and see what answers.
//
// The probe sends nothing but a TLS ClientHello and reads the first line the server volunteers. It
// never logs in and never writes to the stream, so a host that is not a mail server sees an
// ordinary TLS connection that closes.

const dns = require('dns').promises;
const tls = require('tls');
const { proxyConnection, detachEarlyErrorHandler } = require('imapflow/lib/proxy-connection.js');
const { assertAllowedUrl, createEgressLookup } = require('./egress-filter');
const { WEBHOOK_EGRESS_POLICY } = require('./webhook-egress');
const logger = require('./logger');

// Budget of one probe: name lookup, proxy negotiation, handshake and the greeting line. Short
// enough that the IMAP and the SMTP round of the fallback stage both fit its time budget.
const PROBE_TIMEOUT = 2 * 1000;

// A greeting is one line; a server that sends more than this without a newline is not one
const MAX_GREETING = 512;

// Keyed by port: 993 is IMAP over implicit TLS, 465 is SMTP submission over implicit TLS
const PROTOCOLS = {
    993: { greeting: /^\* (?:OK|PREAUTH)\b/i, silentIsEnough: false },
    // SMTP servers commonly hold the greeting back for several seconds to catch clients that talk
    // first, longer than this probe waits. A completed handshake with a certificate valid for the
    // name is then the answer on the submission port, where nothing but a mail server listens.
    465: { greeting: /^220[ -]/, silentIsEnough: true }
};

const probeLogger = logger.child({ component: 'mail-probe' });

const resolveAll = hostname => dns.lookup(hostname, { all: true });

/**
 * Opens the TLS connection and checks the certificate against the probed name.
 *
 * The probe's destinations come from the address domain's DNS, which a caller controls, so the
 * autodiscovery egress policy applies. Directly, the policy-bound lookup is also the one the socket
 * connects with, so the addresses vetted are the addresses connected to. Behind a proxy the proxy
 * resolves the name again, so only the up-front check applies - the same rules, and the same
 * limitation, as the HTTP lookups of autodiscovery.
 */
async function openTls(host, port, ctx) {
    const policy = ctx.egressPolicy || WEBHOOK_EGRESS_POLICY;
    const resolve = ctx.resolve || resolveAll;
    const tlsOptions = Object.assign({ servername: host }, ctx.tlsOptions || {});
    // Tests point the well-known ports at local servers; production never sets this
    const connectPort = (ctx.ports && ctx.ports[port]) || port;

    // Up front on both paths: a candidate can be an address literal (an MX or CNAME record may name
    // `127.0.0.1` outright), and net.connect skips the lookup below for a literal
    await assertAllowedUrl(`https://${host}:${connectPort}/`, { policy, resolve });

    if (!ctx.proxyUrl) {
        return tls.connect(Object.assign({ host, port: connectPort, lookup: createEgressLookup(policy, { resolve }) }, tlsOptions));
    }

    const socket = await proxyConnection(probeLogger, ctx.proxyUrl, host, connectPort, { connectionTimeout: ctx.timeout || PROBE_TIMEOUT });
    if (!socket) {
        throw new Error('Unsupported proxy protocol');
    }
    const secure = tls.connect(Object.assign({ socket }, tlsOptions));
    // The TLS socket owns the raw one from here, and the error handler in readGreeting() covers both
    detachEarlyErrorHandler(socket);
    return secure;
}

/**
 * Waits for the server's first line on an open TLS socket, and closes it either way.
 *
 * @returns {Promise<boolean>} Whether the line is the protocol's greeting
 */
function readGreeting(socket, protocol, timeout, signal) {
    return new Promise(resolve => {
        let settled = false;
        let received = '';
        let handshake = false;

        const finish = result => {
            if (settled) {
                return;
            }
            settled = true;
            clearTimeout(timer);
            if (signal) {
                signal.removeEventListener('abort', onAbort);
            }
            socket.destroy();
            resolve(result);
        };
        const onAbort = () => finish(false);

        // A wall-clock limit rather than the socket's idle timeout, which a server trickling a byte
        // at a time would keep resetting
        const timer = setTimeout(() => finish(handshake && protocol.silentIsEnough), timeout);
        timer.unref();

        // A blocked address, a refused connection and a certificate that does not cover the name
        // all land here
        socket.on('error', () => finish(false));
        socket.on('close', () => finish(false));

        if (signal) {
            if (signal.aborted) {
                return finish(false);
            }
            signal.addEventListener('abort', onAbort, { once: true });
        }

        socket.on('secureConnect', () => {
            handshake = true;
        });
        socket.setEncoding('utf-8');
        socket.on('data', chunk => {
            received += chunk;
            if (received.includes('\n') || received.length > MAX_GREETING) {
                finish(protocol.greeting.test(received));
            }
        });
    });
}

/**
 * Connects to a host over implicit TLS and checks the first line the server sends.
 *
 * @param {string} host - Name to probe
 * @param {number} port - 993 for IMAP, 465 for SMTP
 * @param {Object} [ctx] - `{ signal, proxyUrl }`, plus for tests `resolve` (a `dns.lookup`
 *   stand-in answering `[{ address, family }]`), `egressPolicy`, `tlsOptions` (merged into the TLS
 *   connect options), `ports` (993/465 mapped to other ports) and `timeout`
 * @returns {Promise<boolean>} Whether a mail server of that protocol answered for the name
 */
async function probeMailServer(host, port, ctx) {
    ctx = ctx || {};
    const protocol = PROTOCOLS[port];
    if (!protocol) {
        throw new Error(`No probe for port ${port}`);
    }
    if (ctx.signal && ctx.signal.aborted) {
        return false;
    }

    let socket;
    try {
        socket = await openTls(host, port, ctx);
    } catch (err) {
        return false;
    }

    return await readGreeting(socket, protocol, ctx.timeout || PROBE_TIMEOUT, ctx.signal);
}

module.exports = { probeMailServer };
