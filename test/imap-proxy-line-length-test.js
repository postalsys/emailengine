'use strict';

// Regression test for the IMAP proxy inbound line-length cap (Commit 7).
//
// IMAPStream accumulated an unterminated command line (no CRLF) without any bound,
// so a single client could grow per-connection memory until the worker OOMs. The
// parser now rejects a line longer than maxLineLength and the connection is closed
// with a BYE. Literals stay bounded separately by the existing literal-size cap.

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

test('an unterminated over-long command line is rejected, not buffered forever', async () => {
    const { server, port } = await startServer({ maxLineLength: 1000 });

    try {
        const resp = await new Promise(resolve => {
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

            const timer = setTimeout(finish, 3000);

            socket.setEncoding('utf8');
            socket.on('data', chunk => {
                buffer += chunk;
                if (!greeted && /\* OK /.test(buffer)) {
                    greeted = true;
                    // A single command line far over the cap, with NO terminating CRLF.
                    socket.write('A1 ' + 'X'.repeat(5000));
                }
                if (/BYE/.test(buffer)) {
                    finish();
                }
            });
            socket.on('close', finish);
            socket.on('error', finish);
        });

        assert.match(resp, /\* BYE/, 'an over-long command line must be closed with BYE');
        assert.match(resp, /too long/i, 'the BYE should explain the line was too long');
    } finally {
        await closeServer(server);
    }
});
