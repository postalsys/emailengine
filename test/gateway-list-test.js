'use strict';

// Gateway.listGateways() never outputs a password, so it must not need one: an entry whose stored
// password no longer decrypts (a rotated EENGINE_SECRET, a corrupt value) used to throw out of
// unserialize() and turn the whole listing into a 500.

const test = require('node:test');
const assert = require('node:assert').strict;

const { redis } = require('../lib/db');
const registerRedisTeardown = require('./helpers/redis-teardown');
const msgpack = require('../lib/msgpack');
const { encrypt } = require('../lib/encrypt');
const { Gateway } = require('../lib/gateway');

registerRedisTeardown(redis);

// A client answering only what listGateways() asks: the index set and one HGETALL per entry
function stubRedis(entries) {
    return {
        async smembers() {
            return Object.keys(entries);
        },
        multi() {
            const queued = [];
            const chain = {
                hgetallBuffer(key) {
                    queued.push(key.split(':').pop());
                    return chain;
                },
                async exec() {
                    return queued.map(id => [null, entries[id]]);
                }
            };
            return chain;
        }
    };
}

function storedGateway(id, pass) {
    return {
        gateway: Buffer.from(id),
        name: msgpack.encode(`Gateway ${id}`),
        host: msgpack.encode('smtp.example.com'),
        deliveries: Buffer.from('3'),
        pass: Buffer.from(pass)
    };
}

test('gateway listing survives a password that does not decrypt', async () => {
    const entries = {
        good: storedGateway('good', encrypt('secret', 'current-secret')),
        rotated: storedGateway('rotated', encrypt('secret', 'some-older-secret'))
    };

    const gateway = new Gateway({ redis: stubRedis(entries), secret: 'current-secret' });
    const list = await gateway.listGateways(0, 20);

    assert.strictEqual(list.total, 2);
    assert.deepStrictEqual(list.gateways.map(g => g.gateway).sort(), ['good', 'rotated']);
    for (const entry of list.gateways) {
        assert.strictEqual(entry.deliveries, 3);
        assert.ok(!('pass' in entry));
    }
});

test('loading a single gateway still decrypts its password', async () => {
    const entries = { good: storedGateway('good', encrypt('secret', 'current-secret')) };
    const gateway = new Gateway({ redis: stubRedis(entries), secret: 'current-secret', gateway: 'good' });
    assert.strictEqual(gateway.unserialize(entries.good).pass, 'secret');
});
