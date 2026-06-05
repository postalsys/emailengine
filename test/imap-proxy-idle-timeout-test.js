'use strict';

// Regression test for the IMAP proxy post-handoff idle timeout (Commit 8).
//
// On proxy handoff unbind() disarmed the socket timeout and nothing re-armed one,
// so a proxied connection could stay open forever (fd/connection exhaustion).
// unbind() now re-arms a generous idle timeout (default 30 min, configurable via
// proxyTimeout; 0 disables) that destroys the idle socket. RFC-compliant IMAP IDLE
// refreshes well under the default, so legitimate sessions are unaffected.
//
// These drive the imap-core IMAPServer directly and reach proxy mode via a
// session.onProxy stub that holds the handed-off socket idle (no upstream needed),
// mirroring test/imap-proxy-protocol-test.js.

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
                    disableSTARTTLS: true,
                    proxyMode: true,
                    logger: false,
                    id: { name: 'EmailEngine IMAP Proxy Test' }
                },
                options
            )
        );

        server.onAuth = (login, session, callback) => {
            // Mirror production wiring: onProxy is set before auth completes. The stub
            // holds the handed-off socket and leaves it idle.
            session.onProxy = () => {};
            callback(null, {
                user: {
                    id: 'id.' + login.username,
                    username: login.username
                }
            });
        };

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

// Log in to reach proxy mode, then report whether the server closed the (idle)
// connection on its own within waitMs.
function awaitProxyIdleClose(port, waitMs) {
    return new Promise((resolve, reject) => {
        const socket = net.connect({ port, host: '127.0.0.1' });
        socket.setEncoding('utf8');

        let buffer = '';
        let sentLogin = false;
        let loggedIn = false;
        let settled = false;
        let waitTimer = null;

        const giveUp = setTimeout(() => {
            if (!settled) {
                settled = true;
                try {
                    socket.destroy();
                } catch (err) {
                    // ignore
                }
                reject(new Error('did not reach proxy mode'));
            }
        }, 4000);

        const settle = result => {
            if (settled) {
                return;
            }
            settled = true;
            clearTimeout(giveUp);
            clearTimeout(waitTimer);
            try {
                socket.destroy();
            } catch (err) {
                // ignore
            }
            resolve(result);
        };

        // Server-initiated close after login means the idle timeout fired.
        socket.on('close', () => {
            if (loggedIn) {
                settle(true);
            }
        });
        socket.on('error', () => {
            // ignore resets
        });

        socket.on('data', chunk => {
            buffer += chunk;
            if (!sentLogin && /\* OK /.test(buffer)) {
                sentLogin = true;
                socket.write('A1 LOGIN testuser testpass\r\n');
            }
            if (!loggedIn && /^A1 OK/m.test(buffer)) {
                loggedIn = true;
                clearTimeout(giveUp);
                waitTimer = setTimeout(() => settle(false), waitMs);
            }
        });
    });
}

test('an idle proxied connection is dropped after proxyTimeout', async () => {
    const { server, port } = await startServer({ proxyTimeout: 300 });
    try {
        const closed = await awaitProxyIdleClose(port, 2500);
        assert.strictEqual(closed, true, 'idle proxied connection should be dropped after proxyTimeout');
    } finally {
        await closeServer(server);
    }
});

test('proxyTimeout: 0 keeps the proxied connection open (backwards compatible)', async () => {
    const { server, port } = await startServer({ proxyTimeout: 0 });
    try {
        const closed = await awaitProxyIdleClose(port, 1000);
        assert.strictEqual(closed, false, 'with proxyTimeout:0 the connection must stay open');
    } finally {
        await closeServer(server);
    }
});
