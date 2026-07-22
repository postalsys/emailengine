'use strict';

const test = require('node:test');
const assert = require('node:assert').strict;

const { packRpcError, unpackRpcError } = require('../lib/worker-rpc-error');

test('worker RPC error serialization', async t => {
    await t.test('packs the message and every present field', () => {
        let err = new Error('Rejected');
        err.code = 'EENVELOPE';
        err.statusCode = 550;
        err.responseCode = 550;
        err.info = { networkRouting: { localAddress: '10.0.0.1' } };

        let packed = packRpcError(err);
        assert.strictEqual(packed.error, 'Rejected');
        assert.strictEqual(packed.code, 'EENVELOPE');
        assert.strictEqual(packed.statusCode, 550);
        assert.strictEqual(packed.responseCode, 550);
        assert.deepStrictEqual(packed.info, { networkRouting: { localAddress: '10.0.0.1' } });
    });

    await t.test('a round-trip preserves responseCode (the field delivery classification depends on)', () => {
        // Guards the exact contract lib/delivery-error.js relies on: responseCode must survive the
        // imap-worker -> main -> submit-worker relay, or a transient 4xx would be misclassified.
        let err = new Error('450 greylisted');
        err.code = 'EENVELOPE';
        err.responseCode = 450;
        err.statusCode = 450;

        let rebuilt = unpackRpcError(packRpcError(err));
        assert.strictEqual(rebuilt.message, '450 greylisted');
        assert.strictEqual(rebuilt.code, 'EENVELOPE');
        assert.strictEqual(rebuilt.responseCode, 450);
        assert.strictEqual(rebuilt.statusCode, 450);
    });

    await t.test('omits absent fields rather than serializing undefined', () => {
        let err = new Error('No active handler');
        err.statusCode = 503;

        let packed = packRpcError(err);
        assert.strictEqual(packed.error, 'No active handler');
        assert.strictEqual(packed.statusCode, 503);
        assert.ok(!('code' in packed), 'absent code must not appear in the payload');
        assert.ok(!('responseCode' in packed), 'absent responseCode must not appear in the payload');

        let rebuilt = unpackRpcError(packed);
        assert.strictEqual(rebuilt.code, undefined);
        assert.strictEqual(rebuilt.responseCode, undefined);
    });
});
