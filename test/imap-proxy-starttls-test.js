'use strict';

// Regression tests for STARTTLS hardening in the IMAP proxy (Commit 6).
//
//  - In proxy mode STARTTLS is unadvertised (disableSTARTTLS:true). A client that
//    invokes it directly must be refused, not upgraded against the built-in
//    fallback certificate.
//  - When STARTTLS IS enabled, plaintext commands pipelined together with STARTTLS
//    must never be executed (STARTTLS command injection, CVE-2011-0411 class).
//
// These drive the imap-core IMAPServer directly with a raw TCP socket, mirroring
// test/imap-proxy-protocol-test.js.

const test = require('node:test');
const assert = require('node:assert');
const net = require('node:net');

const { IMAPServer } = require('../lib/imapproxy/imap-core/index.js');

function startServer(options) {
    return new Promise((resolve, reject) => {
        const server = new IMAPServer(
            Object.assign(
                {
                    secure: false,
                    proxyMode: true,
                    logger: false,
                    id: { name: 'EmailEngine IMAP Proxy Test' }
                },
                options
            )
        );
        server.on('error', reject);
        server.listen(0, '127.0.0.1', () => {
            resolve({ server, port: server.server.address().port });
        });
    });
}

function closeServer(server) {
    return new Promise(resolve => {
        server.close(() => resolve());
    });
}

// Connect, wait for the greeting, send the raw payload, resolve with the response
// text once the marker is seen, the socket closes, or the idle timer fires.
function runRawClient({ port, payload, untilMarker, idleTimeout = 1500 }) {
    return new Promise(resolve => {
        const socket = net.connect({ port, host: '127.0.0.1' });
        let buffer = '';
        let greeted = false;
        let settled = false;

        const finish = () => {
            if (settled) {
                return;
            }
            settled = true;
            clearTimeout(timer);
            try {
                socket.destroy();
            } catch (err) {
                // ignore
            }
            resolve(buffer);
        };

        const timer = setTimeout(finish, idleTimeout);

        socket.setEncoding('utf8');
        socket.on('data', chunk => {
            buffer += chunk;
            if (!greeted && /\* OK /.test(buffer)) {
                greeted = true;
                socket.write(payload);
            }
            if (untilMarker && buffer.includes(untilMarker)) {
                finish();
            }
        });
        // A TLS-level reset after an aborted handshake is an acceptable outcome.
        socket.on('close', finish);
        socket.on('error', finish);
    });
}

test('STARTTLS is refused in proxy mode (disableSTARTTLS)', async () => {
    const { server, port } = await startServer({ disableSTARTTLS: true });

    try {
        const resp = await runRawClient({ port, payload: 'A1 STARTTLS\r\n', untilMarker: 'A1 ' });
        assert.match(resp, /A1 (NO|BAD)/, 'STARTTLS must be refused when disabled');
        assert.doesNotMatch(resp, /A1 OK/, 'STARTTLS must not be accepted when disabled');
    } finally {
        await closeServer(server);
    }
});

test('pipelined plaintext after STARTTLS is not executed', async () => {
    const { server, port } = await startServer({ disableSTARTTLS: false });

    try {
        // STARTTLS plus an injected command in a single write.
        const resp = await runRawClient({
            port,
            payload: 'A1 STARTTLS\r\nA2 CAPABILITY\r\n'
        });
        assert.match(resp, /A1 OK/, 'STARTTLS should be accepted when enabled');
        assert.doesNotMatch(resp, /A2 OK/, 'the injected pipelined command must not be executed');
    } finally {
        await closeServer(server);
    }
});
