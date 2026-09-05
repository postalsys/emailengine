'use strict';

const test = require('node:test');
const assert = require('node:assert').strict;
const { Writable } = require('node:stream');
const pino = require('pino');
const { REDACTED_LOG_KEYS } = require('../lib/consts');

// The logger instances in lib/logger.js and workers/api.js are created with this list, so a key
// missing from it is a secret in the log stream; these cases pin the ones that carry credentials.
test('REDACTED_LOG_KEYS', async t => {
    const lines = [];
    const logger = pino(
        { redact: REDACTED_LOG_KEYS },
        new Writable({
            write(chunk, encoding, callback) {
                lines.push(chunk.toString());
                callback();
            }
        })
    );

    t.beforeEach(() => {
        lines.length = 0;
    });

    await t.test('a URL parse error does not log the URL it rejected', () => {
        let err;
        try {
            new URL('socks5://user:s3cret@proxy.example.com:99999');
        } catch (parseError) {
            err = parseError;
        }
        assert.ok(err, 'the port is out of range, so the parser must have refused the URL');

        logger.error({ msg: 'Failed to create HTTP proxy agent', err });

        assert.equal(lines.length, 1);
        assert.ok(lines[0].includes('Invalid URL'), 'the error message is kept');
        assert.ok(!lines[0].includes('s3cret'), 'the credential must not reach the log');
    });

    await t.test('request credentials are redacted', () => {
        logger.info({ msg: 'request', req: { headers: { authorization: 'Bearer top-secret', cookie: 'ee=abc' }, query: { access_token: 'tok-secret' } } });

        assert.equal(lines.length, 1);
        assert.ok(!lines[0].includes('top-secret'));
        assert.ok(!lines[0].includes('ee=abc'));
        assert.ok(!lines[0].includes('tok-secret'));
    });
});
