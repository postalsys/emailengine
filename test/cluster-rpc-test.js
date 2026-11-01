'use strict';

// Calls between instances (lib/cluster/rpc.js): what a receiver accepts, and that answers, errors
// and downloads arrive the way a local worker call would have produced them.

const test = require('node:test');
const assert = require('node:assert').strict;
const crypto = require('node:crypto');
const net = require('node:net');
const { Readable } = require('node:stream');

const {
    createRpcServer,
    createRpcClient,
    signRequest,
    verifyHeaders,
    bodyMatches,
    NonceCache,
    toWire,
    CALL_PATH,
    CLOCK_WINDOW
} = require('../lib/cluster/rpc');

const SECRET = crypto.randomBytes(32);
const logger = { info() {}, warn() {}, error() {}, debug() {} };

function freePort() {
    return new Promise(resolve => {
        const server = net.createServer();
        server.listen(0, '127.0.0.1', () => {
            const { port } = server.address();
            server.close(() => resolve(port));
        });
    });
}

function signed(overrides = {}) {
    const body = Buffer.from('payload');
    const headers = signRequest(SECRET, { method: 'POST', path: CALL_PATH, from: 'a', to: 'b', body, now: overrides.now });
    return Object.assign({ method: 'POST', path: CALL_PATH, headers, body, me: 'b', nonces: new NonceCache() }, overrides.request || {});
}

test('verifyHeaders() and bodyMatches()', async t => {
    await t.test('accepts a correctly signed call', () => {
        assert.equal(verifyHeaders(SECRET, signed()), null);
    });

    await t.test('refuses a call signed with another key', () => {
        assert.equal(verifyHeaders(crypto.randomBytes(32), signed()), 'bad signature');
    });

    await t.test('refuses a call addressed to another instance', () => {
        assert.equal(verifyHeaders(SECRET, signed({ request: { me: 'c' } })), 'addressed to another instance');
    });

    await t.test('refuses a changed body', () => {
        const { headers, body } = signed();
        assert.equal(bodyMatches(headers, body), true);
        assert.equal(bodyMatches(headers, Buffer.from('other')), false);
    });

    await t.test('refuses a replay', () => {
        const request = signed();
        assert.equal(verifyHeaders(SECRET, request), null);
        assert.equal(verifyHeaders(SECRET, request), 'replayed');
    });

    await t.test('refuses a call from outside the clock window', () => {
        assert.equal(verifyHeaders(SECRET, signed({ now: Date.now() - CLOCK_WINDOW - 1000 })), 'timestamp outside the accepted window');
    });

    await t.test('refuses a call without a signature', () => {
        const request = signed();
        delete request.headers['x-ee-cluster-signature'];
        assert.equal(verifyHeaders(SECRET, request), 'missing signature');
    });

    await t.test('the signature is checked from the headers alone, so a stranger is refused before it sends a body', () => {
        const { headers } = signed();
        assert.equal(verifyHeaders(SECRET, { method: 'POST', path: CALL_PATH, headers, me: 'b', nonces: new NonceCache() }), null);
        assert.equal(verifyHeaders(SECRET, { method: 'POST', path: CALL_PATH, headers, me: 'c', nonces: new NonceCache() }), 'addressed to another instance');
        assert.equal(verifyHeaders(crypto.randomBytes(32), { method: 'POST', path: CALL_PATH, headers, me: 'b', nonces: new NonceCache() }), 'bad signature');
        assert.equal(verifyHeaders(SECRET, { method: 'POST', path: CALL_PATH, headers: {}, me: 'b', nonces: new NonceCache() }), 'missing signature');
    });

    await t.test('a body hash header swapped for another one breaks the signature', () => {
        const request = signed();
        request.headers['x-ee-cluster-body'] = crypto.createHash('sha256').update('other').digest('hex');
        request.body = Buffer.from('other');
        assert.equal(verifyHeaders(SECRET, request), 'bad signature');
    });

    await t.test('an unsigned call does not use up nonce space', () => {
        const nonces = new NonceCache();
        verifyHeaders(crypto.randomBytes(32), signed({ request: { nonces } }));
        assert.equal(nonces.entries.size, 0);
    });
});

test('toWire()', () => {
    const wired = toWire({ raw: new Uint8Array([1, 2]).buffer, nested: [{ deep: new Uint8Array([3]).buffer }], date: new Date(0), text: 'x' });
    assert.ok(Buffer.isBuffer(wired.raw));
    assert.deepEqual([...wired.raw], [1, 2]);
    assert.ok(Buffer.isBuffer(wired.nested[0].deep));
    assert.ok(wired.date instanceof Date);
});

test('calls between two instances', async t => {
    const port = await freePort();
    const handled = [];
    let slowReadable = null;
    const server = createRpcServer({
        instanceId: 'b',
        getSecret: async () => SECRET,
        logger,
        async handle(message) {
            handled.push(message);
            switch (message.cmd) {
                case 'echo':
                    return { response: { echoed: message.data, raw: message.raw } };
                case 'fail': {
                    const err = new Error('Message not found');
                    err.statusCode = 404;
                    err.code = 'MessageNotFound';
                    throw err;
                }
                case 'download':
                    return {
                        stream: { meta: { headers: { 'content-type': 'text/plain' } }, readable: Readable.from([Buffer.from('hello '), Buffer.from('world')]) }
                    };
                case 'slowDownload': {
                    // The worker gets the download ready only after the caller has given up
                    await new Promise(resolve => setTimeout(resolve, 2500));
                    slowReadable = new Readable({ read() {} });
                    return { stream: { meta: null, readable: slowReadable } };
                }
            }
            throw new Error('unexpected');
        }
    });
    await server.listen(port, '127.0.0.1');
    const client = createRpcClient({ instanceId: 'a', getSecret: async () => SECRET });
    const peer = { id: 'b', address: `127.0.0.1:${port}` };

    t.after(async () => {
        await client.close();
        await server.close();
    });

    await t.test('an answer arrives as the worker gave it, binary content included', async () => {
        const response = await client.call(peer, { cmd: 'echo', data: { list: [1, 'two'], when: new Date(5) }, raw: new Uint8Array([7, 8, 9]).buffer });
        assert.deepEqual(response.echoed, { list: [1, 'two'], when: new Date(5) });
        assert.deepEqual([...response.raw], [7, 8, 9]);
    });

    await t.test('an error keeps its message, status and code', async () => {
        await assert.rejects(
            client.call(peer, { cmd: 'fail' }),
            err => err.message === 'Message not found' && err.statusCode === 404 && err.code === 'MessageNotFound' && err.remote === 'b'
        );
    });

    await t.test('a download streams, with the worker metadata', async () => {
        const { meta, body } = await client.call(peer, { cmd: 'download' }, { stream: true });
        assert.deepEqual(meta, { headers: { 'content-type': 'text/plain' } });
        const chunks = [];
        for await (const chunk of body) {
            chunks.push(chunk);
        }
        assert.equal(Buffer.concat(chunks).toString(), 'hello world');
    });

    await t.test('a download the caller gave up on is released, not piped into the closed response', async () => {
        // The headers have to arrive within the timeout plus the hop margin (2 s)
        await assert.rejects(client.call(peer, { cmd: 'slowDownload' }, { stream: true, timeout: 100 }), err => err.code === 'Timeout');
        await new Promise(resolve => setTimeout(resolve, 1000));
        assert.ok(slowReadable, 'the handler got as far as the download');
        assert.equal(slowReadable.destroyed, true, 'the worker download was released');
    });

    await t.test('a call signed with another key is refused before it runs', async () => {
        const stranger = createRpcClient({ instanceId: 'a', getSecret: async () => crypto.randomBytes(32) });
        const before = handled.length;
        await assert.rejects(stranger.call(peer, { cmd: 'echo' }), err => err.code === 'ClusterAuthFailed');
        assert.equal(handled.length, before);
        await stranger.close();
    });

    await t.test('a stranger is answered before it has sent its body', async () => {
        // Signed with another key and a body that never ends: the answer has to come from the headers
        const headers = signRequest(crypto.randomBytes(32), { method: 'POST', path: CALL_PATH, from: 'a', to: 'b', body: Buffer.alloc(0) });
        const statusCode = await new Promise((resolve, reject) => {
            const req = require('node:http').request({ host: '127.0.0.1', port, method: 'POST', path: CALL_PATH, headers }, res => {
                res.resume();
                resolve(res.statusCode);
                req.destroy();
            });
            req.on('error', reject);
            req.write(Buffer.alloc(64 * 1024));
        });
        assert.equal(statusCode, 401);
    });

    await t.test('a call meant for another instance is refused', async () => {
        await assert.rejects(client.call({ id: 'c', address: peer.address }, { cmd: 'echo' }), err => err.code === 'ClusterAuthFailed');
    });

    await t.test('an unreachable instance is reported as not delivered', async () => {
        const closed = await freePort();
        await assert.rejects(
            client.call({ id: 'b', address: `127.0.0.1:${closed}` }, { cmd: 'echo' }),
            err => err.code === 'ClusterUnreachable' && err.notDelivered === true
        );
    });

    await t.test('anything but the call path is not found', async () => {
        const res = await fetch(`http://${peer.address}/`);
        assert.equal(res.status, 404);
    });
});
