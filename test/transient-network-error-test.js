'use strict';

// Pins the SHAPE of a failed undici fetch, which is what every OAuth2 token-endpoint call in
// lib/oauth/* goes through.
//
// This exists because the shape was assumed rather than checked. The transient-token classifier in
// base-client.js tested `err.code` against a list of errnos; undici rejects with a generic
// `TypeError: fetch failed` and hangs the real errno off `err.cause`, so `err.code` is undefined and
// the branch was dead - a DNS outage was still reported to the operator as bad credentials. The
// unit suite stayed green throughout, because the tests that covered the classifier built their
// error objects by hand with the field the classifier happened to read.
//
// Asserting against a real rejection is the only version of this test that cannot drift.

const test = require('node:test');
const assert = require('node:assert').strict;
const { fetch: fetchCmd } = require('undici');

const { TRANSIENT_NETWORK_CODES } = require('../lib/consts');

// .invalid is reserved by RFC 2606 and guaranteed never to resolve, so this fails at DNS without
// depending on outbound connectivity.
const UNRESOLVABLE_URL = 'https://token-endpoint.invalid/token';

test('transient network error shape', async t => {
    await t.test('a failed undici fetch carries its errno on err.cause, not err.code', async () => {
        let err;
        try {
            await fetchCmd(UNRESOLVABLE_URL);
            assert.fail('the request was expected to fail');
        } catch (fetchErr) {
            err = fetchErr;
        }

        assert.strictEqual(err.name, 'TypeError', 'undici surfaces connection failures as a generic TypeError');
        assert.ok(err.cause, 'the underlying error is attached as err.cause');
        assert.ok(
            TRANSIENT_NETWORK_CODES.has(err.cause.code),
            `err.cause.code (${err.cause.code}) should be a known transient network code - update TRANSIENT_NETWORK_CODES if a new errno appears`
        );
    });

    await t.test('reading err.code alone misses it, which is why the classifier must unwrap err.cause', async () => {
        let err;
        try {
            await fetchCmd(UNRESOLVABLE_URL);
            assert.fail('the request was expected to fail');
        } catch (fetchErr) {
            err = fetchErr;
        }

        // Guards the regression directly: if this ever starts being defined, the extra unwrapping in
        // loadOAuth2LoginCredentials becomes redundant rather than load-bearing, and this test says so.
        assert.strictEqual(err.code, undefined, 'undici does not set a top-level err.code');

        const classifies = codeSource => TRANSIENT_NETWORK_CODES.has(codeSource);
        assert.strictEqual(classifies(err.code), false, 'testing err.code alone does not classify a real fetch failure');
        assert.strictEqual(classifies(err.cause?.code), true, 'testing err.cause.code does');
    });
});
