'use strict';

// Integration tests for fail-closed service-secret signature verification on the tracking and
// unsubscribe endpoints (/open.gif, /redirect, /unsubscribe). All three now share
// tools.verifyServiceSignature. This is the regression guard for that refactor: a validly-signed
// request must still be accepted (open/click/unsubscribe tracking keeps working) while a forged or
// missing signature must be rejected. Blobs are signed directly with the known test serviceSecret
// ("a cat" from config/test.toml), so the test needs no lib/db handle.
//
// Runs against the shared test server (config/test.toml).

require('dotenv').config({ quiet: true });

const config = require('@zone-eu/wild-config');
const supertest = require('supertest');
const test = require('node:test');
const assert = require('node:assert').strict;
const { signBlob } = require('./helpers');

const baseUrl = `http://127.0.0.1:${config.api.port}`;

test('Tracking endpoints enforce (and accept) service-secret signatures', async t => {
    await t.test('/open.gif accepts a valid signature and rejects a forged one', async () => {
        const { data, sig } = signBlob({ act: 'open', acc: 'sig-test', msg: 'm1' });

        const ok = await supertest(baseUrl).get('/open.gif').query({ data, sig });
        assert.equal(ok.status, 200, `valid signature should be accepted, got ${ok.status}`);
        assert.match(ok.headers['content-type'] || '', /image\/gif/);

        const bad = await supertest(baseUrl).get('/open.gif').query({ data, sig: 'forged-signature' });
        assert.equal(bad.status, 403, `forged signature should be rejected, got ${bad.status}`);
    });

    await t.test('/redirect accepts a valid signature and rejects a forged one', async () => {
        const target = 'https://example.com/landing';
        const { data, sig } = signBlob({ act: 'click', url: target, acc: 'sig-test', msg: 'm1' });

        const ok = await supertest(baseUrl).get('/redirect').query({ data, sig }).redirects(0);
        assert.equal(ok.status, 302, `valid signature should redirect, got ${ok.status}`);
        assert.equal(ok.headers.location, target);

        const bad = await supertest(baseUrl).get('/redirect').query({ data, sig: 'forged-signature' }).redirects(0);
        assert.equal(bad.status, 403, `forged signature should be rejected, got ${bad.status}`);
    });

    await t.test('/unsubscribe accepts a valid signature and rejects a forged one', async () => {
        // A non-"unsub" act makes the handler stop at the act check ("not ok") right after a
        // successful signature verification, so this asserts only the verify branch. The route
        // requires the RFC 8058 one-click body, so send it to get past payload validation.
        const { data, sig } = signBlob({ act: 'noop', acc: 'sig-test' });
        const body = { 'List-Unsubscribe': 'One-Click' };

        const ok = await supertest(baseUrl).post('/unsubscribe').query({ data, sig }).type('form').send(body);
        assert.notEqual(ok.text, 'data validation failed', 'valid signature must pass verification');

        const bad = await supertest(baseUrl).post('/unsubscribe').query({ data, sig: 'forged-signature' }).type('form').send(body);
        assert.equal(bad.text, 'data validation failed', 'forged signature must fail verification');
    });
});
