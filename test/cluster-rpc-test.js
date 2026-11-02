'use strict';

// Calls between instances (lib/cluster/rpc.js): what a receiver accepts, and that answers, errors
// and downloads arrive the way a local worker call would have produced them.

const test = require('node:test');
const assert = require('node:assert').strict;
const crypto = require('node:crypto');
const net = require('node:net');
const { Readable } = require('node:stream');
const { finished } = require('node:stream/promises');

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

const { createMockLogger } = require('./helpers/mock-logger');

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

test('NonceCache forgets expired nonces oldest first, and only those', () => {
    const nonces = new NonceCache(1000);
    const start = 1000000;
    // Entries live two windows; these expire at start + 2000, start + 2500 and start + 3000
    nonces.remember('first', start);
    nonces.remember('second', start + 500);
    nonces.remember('third', start + 1000);

    nonces.prune(start + 2600);
    assert.deepEqual([...nonces.entries.keys()], ['third'], 'the scan drops the expired ones and ends at the first still alive');
    assert.equal(nonces.remember('third', start + 2700), false, 'still a replay');

    // remember() prunes as it goes
    assert.equal(nonces.remember('fourth', start + 3100), true);
    assert.deepEqual([...nonces.entries.keys()], ['fourth']);
});

test('toWire()', () => {
    const wired = toWire({ raw: new Uint8Array([1, 2]).buffer, nested: [{ deep: new Uint8Array([3]).buffer }], date: new Date(0), text: 'x' });
    assert.ok(Buffer.isBuffer(wired.raw));
    assert.deepEqual([...wired.raw], [1, 2]);
    assert.ok(Buffer.isBuffer(wired.nested[0].deep));
    assert.ok(wired.date instanceof Date);

    const plain = { list: [1, { a: 'b' }], buffer: Buffer.from('x') };
    assert.equal(toWire(plain), plain, 'nothing to convert: the value itself, not a copy');

    const original = { keep: { a: 1 }, convert: [new Uint8Array([4]).buffer] };
    const converted = toWire(original);
    assert.notEqual(converted, original);
    assert.equal(converted.keep, original.keep, 'an unchanged branch is shared, not copied');
    assert.ok(original.convert[0] instanceof ArrayBuffer, 'the original is left as it was');
});

test('calls between two instances', async t => {
    const port = await freePort();
    const handled = [];
    let slowReadable = null;
    const serverLogger = createMockLogger();
    const server = createRpcServer({
        instanceId: 'b',
        getSecret: async () => SECRET,
        logger: serverLogger,
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

    await t.test('a refused signed call is logged at warn, a request without a signature at debug', async () => {
        // The two refusals above were signed: a peer with the wrong key or the wrong address is
        // something an operator has to see
        const refused = level =>
            serverLogger.entries.filter(entry => entry.level === level && entry.msg === 'Refused a cluster call').map(entry => entry.reason);
        assert.deepEqual(refused('warn'), ['bad signature', 'bad signature', 'addressed to another instance']);
        assert.deepEqual(refused('debug'), []);

        // A scanner on the pod network is not
        const res = await fetch(`http://${peer.address}${CALL_PATH}`, { method: 'POST', body: 'hello' });
        assert.equal(res.status, 401);
        assert.deepEqual(refused('debug'), ['missing signature']);
        assert.equal(refused('warn').length, 3);
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

test('closing the listener', async t => {
    // A shutdown waits for close(), and the callers keep their connections open for a minute: one
    // that was answering a call when close() came must not hold the shutdown up for that long
    await t.test('a call in flight finishes, and its connection does not keep close() waiting', async () => {
        const port = await freePort();
        let release;
        const server = createRpcServer({
            instanceId: 'b',
            getSecret: async () => SECRET,
            logger,
            handle: async () => {
                await new Promise(resolve => {
                    release = resolve;
                });
                return { response: 'done' };
            }
        });
        await server.listen(port, '127.0.0.1');
        const client = createRpcClient({ instanceId: 'a', getSecret: async () => SECRET });
        try {
            const peer = { id: 'b', address: `127.0.0.1:${port}` };
            const answer = client.call(peer, { cmd: 'slow' }, { timeout: 5000 });
            while (!release) {
                await new Promise(resolve => setTimeout(resolve, 10));
            }
            let closed = false;
            const closing = server.close().then(() => {
                closed = true;
            });
            release();
            assert.equal(await answer, 'done');
            await Promise.race([closing, new Promise(resolve => setTimeout(resolve, 2000))]);
            assert.ok(closed, 'close() resolved once the call was answered');
        } finally {
            await client.close();
        }
    });

    await t.test('a download that had started before close() does not keep it waiting either', async () => {
        const port = await freePort();
        const readable = new Readable({ read() {} });
        // Headers go out with the first chunk
        readable.push('hel');
        const server = createRpcServer({
            instanceId: 'b',
            getSecret: async () => SECRET,
            logger,
            handle: async () => ({ stream: { meta: { size: 5 }, readable } })
        });
        await server.listen(port, '127.0.0.1');
        const client = createRpcClient({ instanceId: 'a', getSecret: async () => SECRET });
        try {
            const { body } = await client.call({ id: 'b', address: `127.0.0.1:${port}` }, { cmd: 'download' }, { timeout: 5000, stream: true });
            let closed = false;
            const closing = server.close().then(() => {
                closed = true;
            });
            readable.push('lo');
            readable.push(null);
            const chunks = [];
            for await (const chunk of body) {
                chunks.push(chunk);
            }
            assert.equal(Buffer.concat(chunks).toString(), 'hello');
            await Promise.race([closing, new Promise(resolve => setTimeout(resolve, 2000))]);
            assert.ok(closed, 'close() resolved once the download ended');
        } finally {
            await client.close();
        }
    });

    await t.test('a download that does not end is cut once the close timeout runs out', async () => {
        // A forwarded download of a large attachment held the shutdown up for as long as it ran, past
        // an orchestrator's grace period, with the workers not even drained yet
        const port = await freePort();
        const readable = new Readable({ read() {} });
        readable.push('hel');
        const server = createRpcServer({
            instanceId: 'b',
            getSecret: async () => SECRET,
            logger,
            handle: async () => ({ stream: { meta: { size: 5 }, readable } })
        });
        await server.listen(port, '127.0.0.1');
        const client = createRpcClient({ instanceId: 'a', getSecret: async () => SECRET });
        try {
            const { body } = await client.call({ id: 'b', address: `127.0.0.1:${port}` }, { cmd: 'download' }, { timeout: 5000, stream: true });
            body.resume();
            const reading = finished(body);
            const startedAt = Date.now();
            let closed = false;
            const closing = server.close(200).then(() => {
                closed = true;
            });
            await Promise.race([closing, new Promise(resolve => setTimeout(resolve, 2000))]);
            assert.ok(closed, 'close() resolved without the download ending');
            assert.ok(Date.now() - startedAt >= 150, 'the download had its grace period first');
            await assert.rejects(reading, 'the caller sees a cut transfer');
            // The caller can see the cut before the listener's pipeline has torn the source down
            if (!readable.destroyed) {
                await Promise.race([new Promise(resolve => readable.once('close', resolve)), new Promise(resolve => setTimeout(resolve, 1000))]);
            }
            assert.ok(readable.destroyed, 'the source of the download was released');
        } finally {
            await client.close();
        }
    });
});
