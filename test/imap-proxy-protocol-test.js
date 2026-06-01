'use strict';

// Regression tests for the IMAP proxy protocol layer (lib/imapproxy/imap-core).
//
// These drive the imap-core IMAPServer directly (no Redis/Account/worker needed) and
// connect with a raw TCP socket, mirroring the production proxy configuration
// ({ secure: false, disableSTARTTLS: true, proxyMode: true }).
//
// Covered:
//  - F1: a client sending more than MAX_BAD_COMMANDS bad commands must receive
//        "* BYE Too many protocol errors" and disconnect, NOT crash the worker.
//        (Before the fix, countBadResponses() called a method that does not exist on
//         IMAPCommand, throwing a TypeError that reached the global handler.)
//  - F2: a connection that enters proxy mode must be removed from server.connections
//        once its handed-off socket closes (before the fix it leaked forever, because
//        unbind() strips the close/end/error listeners so _onClose never runs).

const test = require('node:test');
const assert = require('node:assert');
const net = require('node:net');

const { IMAPServer } = require('../lib/imapproxy/imap-core/index.js');

// silent logger for the server
const silentLogger = false;

function startServer(onAuth) {
    return new Promise((resolve, reject) => {
        const server = new IMAPServer({
            secure: false,
            disableSTARTTLS: true,
            proxyMode: true,
            logger: silentLogger,
            id: { name: 'EmailEngine IMAP Proxy Test' }
        });

        if (typeof onAuth === 'function') {
            server.onAuth = onAuth;
        }

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

// Connect, wait for the greeting, send the supplied lines, then resolve with the full
// response text once the socket closes (or once `untilMarker` is observed).
function runRawClient({ port, lines, untilMarker, idleTimeout = 4000 }) {
    return new Promise((resolve, reject) => {
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
                for (let line of lines) {
                    socket.write(line + '\r\n');
                }
            }
            if (untilMarker && buffer.includes(untilMarker)) {
                finish();
            }
        });

        socket.on('close', finish);
        socket.on('error', err => {
            if (settled) {
                return;
            }
            settled = true;
            clearTimeout(timer);
            reject(err);
        });
    });
}

test('F1: too many bad commands yields BYE and does not crash the worker', async () => {
    const { server, port } = await startServer();

    try {
        // MAX_BAD_COMMANDS is 50; send well past it.
        const lines = [];
        for (let i = 1; i <= 60; i++) {
            lines.push(`A${i} ZZZBOGUS`);
        }

        const resp = await runRawClient({
            port,
            lines,
            untilMarker: 'Too many protocol errors'
        });

        assert.match(resp, /\* BYE Too many protocol errors/, 'server should send the protocol-error BYE');
        // If the bug were present the process would have crashed with a TypeError
        // before reaching this assertion.
    } finally {
        await closeServer(server);
    }
});

test('F2: proxied connection is removed from server.connections after its socket closes', async () => {
    const { server, port } = await startServer((login, session, callback) => {
        // mirror the production wiring: onProxy is set before auth completes
        session.onProxy = () => {
            // stub: hold the handed-off socket, do nothing with it
        };
        callback(null, {
            user: {
                id: 'id.' + login.username,
                username: login.username
            }
        });
    });

    try {
        const socket = net.connect({ port, host: '127.0.0.1' });
        socket.setEncoding('utf8');

        let buffer = '';
        let sentLogin = false;
        await new Promise((resolve, reject) => {
            const timer = setTimeout(() => reject(new Error('timed out waiting for login OK')), 4000);
            socket.on('error', reject);
            socket.on('data', chunk => {
                buffer += chunk;
                if (!sentLogin && /\* OK /.test(buffer)) {
                    sentLogin = true;
                    socket.write('A1 LOGIN testuser testpass\r\n');
                }
                if (/^A1 OK/m.test(buffer)) {
                    clearTimeout(timer);
                    resolve();
                }
            });
        });

        // connection is now in proxy mode and must still be tracked
        assert.strictEqual(server.connections.size, 1, 'connection should be tracked while proxying');

        // client disconnects -> handed-off socket closes -> connection must be dropped
        await new Promise(resolve => {
            socket.on('close', resolve);
            socket.end();
        });

        // wait for the server-side 'close' to propagate
        await new Promise((resolve, reject) => {
            const deadline = Date.now() + 4000;
            const poll = () => {
                if (server.connections.size === 0) {
                    return resolve();
                }
                if (Date.now() > deadline) {
                    return reject(new Error(`connection leaked: server.connections.size=${server.connections.size}`));
                }
                setTimeout(poll, 25);
            };
            poll();
        });

        assert.strictEqual(server.connections.size, 0, 'proxied connection must be removed after close');
    } finally {
        await closeServer(server);
    }
});
