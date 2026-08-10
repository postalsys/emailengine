'use strict';

const test = require('node:test');
const assert = require('node:assert').strict;

const msgpack = require('../lib/msgpack');

// Blobs encoded with msgpack5 6.0.2, the library used before lib/msgpack. They mirror the
// persisted shapes (Redis token/listing/log/append-list entries, EENGINE_PREPARED_TOKEN),
// so this test is what proves data written by earlier releases stays readable.
const MSGPACK5_FIXTURES = {
    // API token entry (lib/tokens.js)
    token: '85a76163636f756e74af6578616d706c652d6163636f756e74ab6465736372697074696f6eaa5465737420746f6b656ea673636f70657391a3617069a763726561746564cf000001988efcf800ac7265737472696374696f6e7382a961646472657373657391ac3132372e302e302e312f3332a972656665727265727390',
    // license-style payload with a binary key (lib/tools.js msgpackDecode does val.k.toString('base64'))
    binkey: '85a161ab656d61696c656e67696e65a16bc41000112233445566778899aabbccddeeffa16ea9546573742055736572a163cf000001988efcf800a174c3',
    // mailbox listing cache meta (lib/tools.js unserialize: [msgid, [flags], [labels]])
    listing: '93aa6d73672d69642d31323392a85c466c6167676564a6637573746f6d91a76c6162656c2d61',
    // log row with a Date (ext -1 timestamp)
    dated: '82a474696d65d7ff5f5e10006a79a5eea36d7367a86c6f67206c696e65',
    // two concatenated values (lib/append-list.js hash field)
    stream: '82a373657101a576616c7565a5666972737482a373657102a576616c7565a67365636f6e64',
    // own '__proto__' key - msgpack5 refused to decode this, the new library must too
    protoKey: '82a95f5f70726f746f5f5f81a8706f6c6c75746564c3a47361666501'
};

test('msgpack wrapper compatibility tests', async t => {
    await t.test('decodes a msgpack5-encoded token entry', () => {
        let tokenData = msgpack.decode(Buffer.from(MSGPACK5_FIXTURES.token, 'hex'));
        assert.deepStrictEqual(tokenData, {
            account: 'example-account',
            description: 'Test token',
            scopes: ['api'],
            created: 1754745600000,
            restrictions: { addresses: ['127.0.0.1/32'], referrers: [] }
        });
    });

    await t.test('decodes msgpack5-encoded bin values to Buffers', () => {
        let licenseData = msgpack.decode(Buffer.from(MSGPACK5_FIXTURES.binkey, 'hex'));
        assert.ok(Buffer.isBuffer(licenseData.k), 'k must be a Buffer, call sites use toString(encoding)');
        assert.strictEqual(licenseData.k.toString('hex'), '00112233445566778899aabbccddeeff');
        assert.strictEqual(licenseData.a, 'emailengine');
        assert.strictEqual(licenseData.c, 1754745600000);
        assert.strictEqual(licenseData.t, true);
    });

    await t.test('decodes a msgpack5-encoded listing meta array', () => {
        assert.deepStrictEqual(msgpack.decode(Buffer.from(MSGPACK5_FIXTURES.listing, 'hex')), ['msg-id-123', ['\\Flagged', 'custom'], ['label-a']]);
    });

    await t.test('decodes a msgpack5-encoded timestamp extension to a Date', () => {
        let entry = msgpack.decode(Buffer.from(MSGPACK5_FIXTURES.dated, 'hex'));
        assert.ok(entry.time instanceof Date);
        assert.strictEqual(entry.time.getTime(), new Date('2026-08-10T10:20:30.400Z').getTime());
        assert.strictEqual(entry.msg, 'log line');
    });

    await t.test('decodeMulti() reads a concatenated msgpack5 stream', () => {
        assert.deepStrictEqual(msgpack.decodeMulti(Buffer.from(MSGPACK5_FIXTURES.stream, 'hex')), [
            { seq: 1, value: 'first' },
            { seq: 2, value: 'second' }
        ]);
    });

    await t.test('refuses to decode an own __proto__ key, like msgpack5 did', () => {
        assert.throws(() => msgpack.decode(Buffer.from(MSGPACK5_FIXTURES.protoKey, 'hex')));
        assert.ok(!('polluted' in Object.prototype), 'decode must not pollute the prototype before throwing');
    });

    await t.test('decode() reads the first value and ignores trailing bytes, like msgpack5 did', () => {
        // corrupt stored entries whose first byte is a valid type marker decode to a primitive;
        // listing-diff.js and oauth2-apps.js shape checks rely on that instead of an exception
        assert.strictEqual(msgpack.decode(Buffer.from('not msgpack at all')), 110);
    });

    await t.test('decode() throws on unparseable input', () => {
        assert.throws(() => msgpack.decode(Buffer.from([0xc1, 0x00])), /Unrecognized type byte/);
        assert.throws(() => msgpack.decode(Buffer.alloc(0)), /Unable to decode/);
        // truncated blob
        assert.throws(() => msgpack.decode(msgpack.encode({ a: 'hello world' }).subarray(0, 5)));
    });

    await t.test('encode() returns a Buffer', () => {
        let encoded = msgpack.encode({ folder: 'INBOX', uid: 123 });
        assert.ok(Buffer.isBuffer(encoded), "call sites use .toString('base64url'), Buffer.concat and hsetBuffer");
        assert.strictEqual(msgpack.decode(Buffer.from(encoded.toString('base64url'), 'base64url')).folder, 'INBOX');
    });

    await t.test('encode() omits undefined properties, like msgpack5 did', () => {
        assert.deepStrictEqual(msgpack.decode(msgpack.encode({ type: 'log', error: undefined, value: 1 })), { type: 'log', value: 1 });
    });

    await t.test('encoded output round-trips Buffers, Dates, and nested structures', () => {
        let sample = {
            id: 'abc',
            key: Buffer.from('deadbeef', 'hex'),
            time: new Date('2026-01-02T03:04:05.678Z'),
            counters: [1, 2.5, -3, 2 ** 40],
            nested: { flag: true, missing: null }
        };
        let restored = msgpack.decode(msgpack.encode(sample));
        assert.ok(Buffer.isBuffer(restored.key));
        assert.ok(restored.time instanceof Date);
        assert.strictEqual(restored.time.getTime(), sample.time.getTime());
        assert.deepStrictEqual(restored, sample);
    });
});
