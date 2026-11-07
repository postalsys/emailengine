'use strict';

// socketTimeout only notices a silent server. One that trickles a line at a time kept a delivery
// going forever, and the submit worker waiting on it held its slot for the whole call timeout.

const test = require('node:test');
const assert = require('node:assert').strict;
const net = require('node:net');

const { sendWithDeadline } = require('../lib/email-client/smtp-pool-manager');

test('a delivery to a server that trickles its greeting fails at the deadline and closes the pool', async () => {
    const sockets = new Set();
    const server = net.createServer(socket => {
        sockets.add(socket);
        socket.on('error', () => false);
        // a multi-line greeting that never ends
        const timer = setInterval(() => socket.write('220-still here\r\n'), 20);
        socket.on('close', () => {
            clearInterval(timer);
            sockets.delete(socket);
        });
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    const settings = { host: '127.0.0.1', port: server.address().port, secure: false, ignoreTLS: true, logger: false };
    try {
        const started = Date.now();
        await assert.rejects(
            sendWithDeadline(settings, { envelope: { from: 'a@example.com', to: ['b@example.com'] }, raw: 'Subject: x\r\n\r\nx' }, 300),
            err => err.code === 'ETIMEDOUT' && err.deadlineExceeded === true
        );
        assert.ok(Date.now() - started < 3000, 'it fails at the deadline, not at socketTimeout');
        const waitUntil = require('./helpers/wait-until');
        assert.ok(await waitUntil(() => sockets.size === 0), 'and its connection is closed');
    } finally {
        for (const socket of sockets) {
            socket.destroy();
        }
        await new Promise(resolve => server.close(resolve));
    }
});
