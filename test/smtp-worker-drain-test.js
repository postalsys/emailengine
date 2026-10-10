'use strict';

// workers/smtp.js shutdown drain. server.js broadcasts { cmd: 'close' } to every worker on
// shutdown, and the SMTP worker used to answer it as an unknown command, so a submission halfway
// through DATA was cut at process exit - and a message queued just before the cut was sent again
// by a client that never saw its 250. The worker boots a server on load, so it runs in a Worker
// thread against the test Redis db, driven over the same RPC protocol the main thread uses.

const test = require('node:test');
const assert = require('node:assert').strict;
const net = require('node:net');

const { redis } = require('../lib/db');
const settings = require('../lib/settings');
const registerRedisTeardown = require('./helpers/redis-teardown');
const { startWorker } = require('./helpers/worker-rpc');

registerRedisTeardown(redis);

function freePort() {
    return new Promise((resolve, reject) => {
        const probe = net.createServer();
        probe.once('error', reject);
        probe.listen(0, '127.0.0.1', () => {
            const { port } = probe.address();
            probe.close(() => resolve(port));
        });
    });
}

// Resolves true when something accepts a connection on the port
function tryConnect(port) {
    return new Promise(resolve => {
        const socket = net.connect({ port, host: '127.0.0.1' });
        socket.once('connect', () => {
            socket.destroy();
            resolve(true);
        });
        socket.once('error', () => resolve(false));
    });
}

async function waitForListener(port, deadline) {
    while (!(await tryConnect(port))) {
        if (Date.now() > deadline) {
            throw new Error('SMTP worker did not start listening');
        }
        await new Promise(r => setTimeout(r, 50));
    }
}

function smtpClient(port) {
    const socket = net.connect({ port, host: '127.0.0.1' });
    socket.setEncoding('utf8');
    socket.on('error', () => false);
    const client = { socket, buffer: '', closed: false };
    socket.on('data', chunk => {
        client.buffer += chunk;
    });
    socket.on('close', () => {
        client.closed = true;
    });
    client.waitFor = async (re, timeout = 4000) => {
        const deadline = Date.now() + timeout;
        while (!re.test(client.buffer)) {
            if (client.closed || Date.now() > deadline) {
                throw new Error(`waiting for ${re}; got: ${client.buffer}`);
            }
            await new Promise(r => setTimeout(r, 10));
        }
    };
    // Sends a command and waits for its final reply line (a code followed by a space)
    client.command = async (line, code) => {
        client.buffer = '';
        client.socket.write(line);
        await client.waitFor(new RegExp(`^${code} `, 'm'));
    };
    return client;
}

test('the SMTP worker drains its sessions when asked to close', async t => {
    const port = await freePort();
    await settings.setMulti({ smtpServerPort: port, smtpServerHost: '127.0.0.1', smtpServerAuthEnabled: false, smtpServerTLSEnabled: false });

    const { worker, ready, call } = startWorker('smtp.js');
    t.after(() => worker.terminate());
    await ready;

    await waitForListener(port, Date.now() + 10000);

    // A session halfway through DATA when the shutdown arrives
    const client = smtpClient(port);
    await client.waitFor(/^220 /m);
    await client.command('EHLO test\r\n', 250);
    await client.command('MAIL FROM:<sender@example.com>\r\n', 250);
    await client.command('RCPT TO:<rcpt@example.com>\r\n', 250);
    await client.command('DATA\r\n', 354);
    client.socket.write('Subject: drain\r\n\r\nfirst half\r\n');

    const closed = call({ cmd: 'close' });
    await new Promise(r => setTimeout(r, 100));

    // The listener stops accepting while the session in flight keeps going
    assert.strictEqual(await tryConnect(port), false, 'no new connections are accepted once the drain starts');

    // Whatever the verdict on this message (the stub main thread resolves no account), the client
    // gets an answer for it rather than a cut connection
    await client.command('second half\r\n.\r\n', '[245]\\d\\d');
    assert.doesNotMatch(client.buffer, /421/, 'the session was not cut short');
    client.socket.write('QUIT\r\n');

    const response = await closed;
    assert.strictEqual(response.response, true, 'the worker reports the drain done');
});
