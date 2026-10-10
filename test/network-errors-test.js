'use strict';

// lib/network-errors.js: undici raises every connection failure as a generic TypeError with the
// real code on err.cause. A Pub/Sub pull whose body stalled reached error tracking as
// "TypeError: terminated" because the pull loop read err.code alone, and seven Pub/Sub management
// checks in lib/oauth2-apps.js missed transient failures the same way. The OAuth2 clients now
// promote the code onto the error they throw, and the transient check walks the cause chain.

const test = require('node:test');
const assert = require('node:assert').strict;
const net = require('node:net');

const { isTransientNetworkError, promoteCauseCode } = require('../lib/network-errors');
const { GmailOauth } = require('../lib/oauth/gmail');
const { OutlookOauth } = require('../lib/oauth/outlook');
const { MailRuOauth } = require('../lib/oauth/mail-ru');
const { redis } = require('../lib/db');
const registerRedisTeardown = require('./helpers/redis-teardown');

registerRedisTeardown(redis);

const undiciFailure = (message, code) => new TypeError(message, { cause: Object.assign(new Error(code), { code }) });

test('isTransientNetworkError()', async t => {
    await t.test('finds a network code anywhere down the cause chain', () => {
        assert.equal(isTransientNetworkError(undiciFailure('terminated', 'UND_ERR_BODY_TIMEOUT')), true);
        assert.equal(isTransientNetworkError(new Error('wrapped', { cause: undiciFailure('fetch failed', 'ECONNRESET') })), true);
        assert.equal(isTransientNetworkError(Object.assign(new Error('x'), { code: 'ETIMEDOUT' })), true);
    });

    await t.test('is false for anything else, and survives a self-referencing chain', () => {
        assert.equal(isTransientNetworkError(undiciFailure('fetch failed', 'ERR_TLS_CERT_ALTNAME_INVALID')), false);
        assert.equal(isTransientNetworkError(new TypeError('x is not a function')), false);
        const loop = new Error('loop');
        loop.cause = loop;
        assert.equal(isTransientNetworkError(loop), false);
    });
});

test('promoteCauseCode()', async t => {
    await t.test('copies the cause code onto the error', () => {
        assert.equal(promoteCauseCode(undiciFailure('terminated', 'UND_ERR_BODY_TIMEOUT')).code, 'UND_ERR_BODY_TIMEOUT');
    });

    await t.test('leaves an error that has a code of its own alone', () => {
        const err = Object.assign(undiciFailure('fetch failed', 'ECONNRESET'), { code: 'EOWN' });
        assert.equal(promoteCauseCode(err).code, 'EOWN');
    });
});

test('OAuth2 provider requests surface the network code on the error they throw', async () => {
    // A port nothing listens on: the connect fails with ECONNREFUSED, reported by undici on err.cause
    const port = await new Promise(resolve => {
        const probe = net.createServer().listen(0, '127.0.0.1', () => {
            const { port } = probe.address();
            probe.close(() => resolve(port));
        });
    });
    const url = `http://127.0.0.1:${port}/api`;
    const opts = { clientId: 'test-id', clientSecret: 'test-secret', redirectUrl: 'http://localhost/callback', setFlag: async () => {} };

    for (const client of [new GmailOauth(opts), new OutlookOauth({ ...opts, authority: 'common' }), new MailRuOauth(opts)]) {
        await assert.rejects(client.request('token', url), err => err.code === 'ECONNREFUSED', client.constructor.name);
    }
});
