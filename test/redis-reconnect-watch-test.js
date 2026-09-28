'use strict';

// lib/db.js watchRedisReconnect(): the IMAP worker exits for a clean restart when Redis comes back
// after a lost connection. It used to wait for 'end', which ioredis 6 emits only on a final close
// (retryStrategy returning a non-number, which lib/db.js never does), so an ordinary reconnect
// (close -> reconnecting -> ready) never triggered the restart (WORK-2). Driven with a stub client
// emitting the event sequences ioredis produces.

const test = require('node:test');
const assert = require('node:assert').strict;
const { EventEmitter } = require('node:events');

const { redis, watchRedisReconnect, logBullErrors } = require('../lib/db');
const registerRedisTeardown = require('./helpers/redis-teardown');

registerRedisTeardown(redis);

function stubClient(status) {
    const client = new EventEmitter();
    client.status = status;
    return client;
}

function watch(client) {
    const calls = { reconnect: 0, disconnect: 0 };
    watchRedisReconnect(
        client,
        () => calls.reconnect++,
        () => calls.disconnect++
    );
    return calls;
}

test('an ordinary ioredis reconnect triggers the restart', () => {
    const client = stubClient('ready');
    const calls = watch(client);

    // What ioredis 6 emits when the server restarts: no 'end' anywhere in it
    client.emit('close');
    client.emit('reconnecting', 1000);
    client.emit('connect');
    client.emit('ready');

    assert.equal(calls.disconnect, 1, 'the lost connection is reported once');
    assert.equal(calls.reconnect, 1, 'the reconnect is detected');
});

test('the first connection is not a reconnect', () => {
    const client = stubClient('connecting');
    const calls = watch(client);

    // A failed first attempt before the client was ever ready
    client.emit('close');
    client.emit('reconnecting', 1000);
    client.emit('ready');

    assert.equal(calls.reconnect, 0);
    assert.equal(calls.disconnect, 0);

    // ...but once it has been ready, losing it counts
    client.emit('close');
    client.emit('ready');
    assert.equal(calls.reconnect, 1);
});

test('a final close still counts as a lost connection', () => {
    const client = stubClient('ready');
    const calls = watch(client);
    client.emit('end');
    assert.equal(calls.disconnect, 1);
});

test('logBullErrors() gives a BullMQ object an error listener', () => {
    const emitter = new EventEmitter();
    assert.equal(logBullErrors(emitter, 'test'), emitter);
    // With no listener this emit would throw
    assert.doesNotThrow(() => emitter.emit('error', new Error('connection lost')));
});
