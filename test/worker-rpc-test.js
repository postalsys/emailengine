'use strict';

// lib/worker-rpc.js over a real MessageChannel, so postMessage clones (and refuses to clone) the
// way it does between a worker and the main thread.

const test = require('node:test');
const assert = require('node:assert').strict;
const { MessageChannel } = require('node:worker_threads');

const { createRpcClient, respond, isCall } = require('../lib/worker-rpc');
const exitWhenStandalone = require('./helpers/exit-standalone');
const { createMockLogger } = require('./helpers/mock-logger');

// The far end of a channel, answering every call with what `answer` returns
function farEnd(port, answer) {
    port.on('message', message => {
        if (message && message.cmd === 'call') {
            port.postMessage(Object.assign({ cmd: 'resp', mid: message.mid }, answer(message.message)));
        }
    });
}

const nextMessage = port => new Promise(resolve => port.once('message', resolve));

test('worker RPC client', async t => {
    const channels = [];
    const channel = () => {
        const ch = new MessageChannel();
        channels.push(ch);
        return ch;
    };
    t.after(() => {
        for (const ch of channels) {
            ch.port1.close();
            ch.port2.close();
        }
    });

    const connect = (answer, opts = {}) => {
        const { port1, port2 } = channel();
        const client = createRpcClient(Object.assign({ port: port1, defaultTimeout: 1000, timeoutTag: 'TX' }, opts));
        port1.on('message', message => client.handleResponse(message));
        farEnd(port2, answer);
        return client;
    };

    await t.test('resolves with the response', async () => {
        const client = connect(command => ({ response: { echo: command.value } }));
        assert.deepEqual(await client.call({ cmd: 'echo', value: 42 }), { echo: 42 });
        assert.equal(client.pendingCount(), 0);
    });

    await t.test('rebuilds an error with every field the delivery classification reads', async () => {
        const client = connect(() => ({ error: 'Greylisted', code: 'EENVELOPE', statusCode: 450, responseCode: 450, permanent: false, info: { a: 1 } }));
        await assert.rejects(client.call({ cmd: 'send' }), err => {
            assert.equal(err.message, 'Greylisted');
            assert.equal(err.code, 'EENVELOPE');
            assert.equal(err.responseCode, 450);
            assert.equal(err.permanent, false);
            assert.deepEqual(err.info, { a: 1 });
            return true;
        });
    });

    await t.test('times out after the longer of the default and the requested timeout', async () => {
        const { port1 } = channel();
        const client = createRpcClient({ port: port1, defaultTimeout: 20, timeoutTag: 'TX' });
        const started = Date.now();
        await assert.rejects(client.call({ cmd: 'never', timeout: 60 }), err => {
            assert.equal(err.message, 'Timeout waiting for command response [TX]');
            assert.equal(err.statusCode, 504);
            assert.equal(err.code, 'Timeout');
            assert.equal(err.ttl, 60);
            return true;
        });
        assert.ok(Date.now() - started >= 55);
        assert.equal(client.pendingCount(), 0);
    });

    await t.test('a command that cannot be sent rejects at once and leaves nothing pending', async () => {
        const { port1 } = channel();
        const client = createRpcClient({ port: port1, defaultTimeout: 10000, timeoutTag: 'TX' });
        await assert.rejects(client.call({ cmd: 'x', fn: () => {} }), /could not be cloned/);
        assert.equal(client.pendingCount(), 0);
    });

    await t.test('a response for no pending call is not claimed', () => {
        const { port1 } = channel();
        const client = createRpcClient({ port: port1, defaultTimeout: 10, timeoutTag: 'TX' });
        assert.equal(client.handleResponse({ cmd: 'resp', mid: 'unknown' }), false);
        assert.equal(client.handleResponse({ cmd: 'call', mid: 'x' }), false);
        assert.equal(client.handleResponse(null), false);
    });
});

test('worker RPC responder', async t => {
    const { port1, port2 } = new MessageChannel();
    t.after(() => {
        port1.close();
        port2.close();
    });

    const run = async (handler, opts) => {
        const reply = nextMessage(port2);
        await respond(port1, { cmd: 'call', mid: 'm1', message: { cmd: 'test' } }, handler, Object.assign({ logger: createMockLogger() }, opts));
        return reply;
    };

    await t.test('recognises a call', () => {
        assert.equal(isCall({ cmd: 'call', mid: 'm1' }), true);
        assert.equal(isCall({ cmd: 'resp', mid: 'm1' }), false);
        assert.equal(isCall({ cmd: 'call' }), false);
        assert.equal(isCall(undefined), false);
    });

    await t.test('sends the handler result', async () => {
        assert.deepEqual(await run(async command => ({ got: command.cmd })), { cmd: 'resp', mid: 'm1', response: { got: 'test' } });
    });

    await t.test('accepts a handler that is not async', async () => {
        assert.deepEqual(await run(() => 7), { cmd: 'resp', mid: 'm1', response: 7 });
    });

    await t.test('sends a thrown error with its fields', async () => {
        const reply = await run(async () => {
            throw Object.assign(new Error('Rejected'), { code: 'EMESSAGE', statusCode: 550, responseCode: 550, permanent: true });
        });
        assert.deepEqual(reply, { cmd: 'resp', mid: 'm1', error: 'Rejected', code: 'EMESSAGE', statusCode: 550, responseCode: 550, permanent: true });
    });

    await t.test('a rejection that is not an Error is still sent as an error', async () => {
        assert.deepEqual(await run(() => Promise.reject(undefined)), { cmd: 'resp', mid: 'm1', error: 'undefined' });
        assert.deepEqual(await run(() => Promise.reject('plain string')), { cmd: 'resp', mid: 'm1', error: 'plain string' });
    });

    await t.test('an error without a message does not arrive as a success', async () => {
        const reply = await run(async () => {
            throw new Error('');
        });
        assert.equal(reply.error, 'Error');
    });

    await t.test('a response postMessage cannot clone is answered with the clone error', async () => {
        const reply = await run(async () => ({ fn: () => {} }));
        assert.equal(reply.mid, 'm1');
        assert.match(reply.error, /could not be cloned/);
        assert.equal('response' in reply, false);
    });

    await t.test('an error carrying uncloneable info is still answered', async () => {
        const reply = await run(async () => {
            throw Object.assign(new Error('Boom'), { info: { fn: () => {} } });
        });
        assert.match(reply.error, /could not be cloned/);
    });

    await t.test('onError sees the error before it is sent and can set its status', async () => {
        const seen = [];
        const reply = await run(
            async () => {
                throw Object.assign(new Error('Throttled'), { code: 'ETHROTTLE' });
            },
            {
                onError(err) {
                    seen.push(err.code);
                    err.statusCode = 429;
                }
            }
        );
        assert.deepEqual(seen, ['ETHROTTLE']);
        assert.equal(reply.statusCode, 429);
    });

    await t.test('answering over a closed port does not reject', async () => {
        const { port1: closed, port2: other } = new MessageChannel();
        other.close();
        closed.close();
        await assert.doesNotReject(respond(closed, { cmd: 'call', mid: 'm2', message: {} }, async () => 1, { logger: createMockLogger() }));
    });
});

exitWhenStandalone();
