'use strict';

// lib/cluster/bus.js: the broadcast channel is optional at runtime. A Redis user without channel
// access (a Redis 7 ACL user without `allchannels`) used to end the start-up of the instance; now
// the subscribe is logged, retried on a timer and the instance runs without broadcasts meanwhile.
// Pure: the Redis clients are stand-ins, so this needs no Redis.

const test = require('node:test');
const assert = require('node:assert').strict;
const EventEmitter = require('node:events');

const msgpack = require('../lib/msgpack');
const { ClusterBus } = require('../lib/cluster/bus');
const { createMockLogger } = require('./helpers/mock-logger');

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const logged = (logger, level) => logger.entries.filter(entry => entry.level === level);

/** A subscriber whose subscribe() fails the first `failures` times, as NOPERM does until the ACL is fixed */
function fakeSubscriber({ failures = 0 } = {}) {
    const subscriber = new EventEmitter();
    subscriber.attempts = 0;
    subscriber.subscribed = false;
    subscriber.subscribe = async () => {
        subscriber.attempts++;
        if (subscriber.attempts <= failures) {
            throw new Error('NOPERM No permissions to access a channel');
        }
        subscriber.subscribed = true;
    };
    subscriber.unsubscribe = async () => {
        subscriber.subscribed = false;
    };
    return subscriber;
}

function fakePublisher() {
    const published = [];
    return {
        published,
        async publish(channel, payload) {
            published.push({ channel, payload });
        }
    };
}

function startBus({ failures = 0, retryInterval = 50 } = {}) {
    const subscriber = fakeSubscriber({ failures });
    const publisher = fakePublisher();
    const logger = createMockLogger();
    const received = [];
    const bus = new ClusterBus({
        publisher,
        subscriber,
        channel: 'cluster:bus',
        instanceId: 'me',
        logger,
        retryInterval,
        onMessage: (type, data, from) => received.push({ type, data, from })
    });
    return { bus, subscriber, publisher, logger, received };
}

test('cluster bus', async t => {
    await t.test('a subscribe that fails does not fail start(), and is retried until it works', async () => {
        const { bus, subscriber, publisher, logger } = startBus({ failures: 2 });

        await bus.start();
        assert.equal(bus.isConnected(), false);
        assert.equal(subscriber.attempts, 1);

        // Said once where an operator sees it, with the remedy
        assert.equal(logged(logger, 'error').length, 1);
        assert.match(logged(logger, 'error')[0].msg, /running without it/);
        assert.match(logged(logger, 'error')[0].msg, /allchannels/);

        // Nothing goes out meanwhile: publishing needs the same channel access
        bus.publish('settings', { logs: true });
        assert.deepEqual(publisher.published, []);

        await sleep(200);
        assert.ok(subscriber.attempts >= 3, `retried: ${subscriber.attempts} attempts`);
        assert.equal(bus.isConnected(), true);
        assert.equal(subscriber.subscribed, true);
        // The later failures were not repeated at error level
        assert.equal(logged(logger, 'error').length, 1);
        assert.equal(logged(logger, 'info').length, 1);
        assert.match(logged(logger, 'info')[0].msg, /connected/);

        bus.publish('settings', { logs: true });
        assert.equal(publisher.published.length, 1);
        assert.deepEqual(msgpack.decode(publisher.published[0].payload), { f: 'me', t: 'settings', d: { logs: true } });

        await bus.stop();
        assert.equal(subscriber.subscribed, false);
    });

    await t.test('messages of another instance are dispatched, its own are not', async () => {
        const { bus, subscriber, received } = startBus();
        await bus.start();
        assert.equal(bus.isConnected(), true);

        subscriber.emit('messageBuffer', Buffer.from('cluster:bus'), msgpack.encode({ f: 'other', t: 'claim', d: { to: 'me', accounts: ['a'] } }));
        subscriber.emit('messageBuffer', Buffer.from('cluster:bus'), msgpack.encode({ f: 'me', t: 'claim', d: { to: 'other', accounts: ['b'] } }));
        subscriber.emit('messageBuffer', Buffer.from('another:channel'), msgpack.encode({ f: 'other', t: 'claim', d: null }));
        await sleep(10);

        assert.deepEqual(received, [{ type: 'claim', data: { to: 'me', accounts: ['a'] }, from: 'other' }]);
        await bus.stop();
    });

    await t.test('stop() ends a pending retry', async () => {
        const { bus, subscriber } = startBus({ failures: 100, retryInterval: 20 });
        await bus.start();
        await bus.stop();
        const attempts = subscriber.attempts;
        await sleep(100);
        assert.equal(subscriber.attempts, attempts, 'no retry after stop()');
        assert.equal(bus.isConnected(), false);
    });
});
