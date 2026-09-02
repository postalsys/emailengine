'use strict';

// The vendored imap-core used to ship a self-signed localhost key pair as the fallback TLS
// material for a server configured without a certificate - the same private key in every copy
// of the library. That fallback is gone; this pins it gone. Pure module, no Redis.

const test = require('node:test');
const assert = require('node:assert').strict;

const getTLSOptions = require('../lib/imapproxy/imap-core/lib/tls-options');

test('imap-core TLS defaults', async t => {
    await t.test('carry no built-in key or certificate', () => {
        const defaults = getTLSOptions();
        assert.equal(defaults.key, undefined, 'a private key shipped in the source is not a secret');
        assert.equal(defaults.cert, undefined);
    });

    await t.test('pass the configured material through untouched', () => {
        const options = getTLSOptions({ key: 'KEY', cert: 'CERT', secure: true });
        assert.equal(options.key, 'KEY');
        assert.equal(options.cert, 'CERT');
        assert.equal(options.honorCipherOrder, true, 'the remaining defaults still apply');
    });
});
