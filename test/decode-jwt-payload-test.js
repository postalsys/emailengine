'use strict';

// Tests for lib/oauth/decode-jwt-payload.js. The contract that matters is that it NEVER throws: the OAuth2
// callback decodes id_tokens from three providers on an unauthenticated route, and a malformed token has
// to degrade to "no claims available", not to a 500.

const test = require('node:test');
const assert = require('node:assert').strict;

const { decodeJwtPayload, MAX_PAYLOAD_LENGTH } = require('../lib/oauth/decode-jwt-payload');

const encode = value => Buffer.from(JSON.stringify(value)).toString('base64url');
const jwt = payload => `header.${encode(payload)}.signature`;

test('decodeJwtPayload()', async t => {
    await t.test('returns the claims of a well-formed token', () => {
        const payload = { email: 'user@example.com', name: 'Nyan Cat', preferred_username: 'nyan@example.com' };
        assert.deepEqual(decodeJwtPayload(jwt(payload)), payload);
    });

    await t.test('returns null for tokens it cannot decode', () => {
        assert.equal(decodeJwtPayload(''), null);
        assert.equal(decodeJwtPayload('not-a-jwt'), null);
        assert.equal(decodeJwtPayload('header..signature'), null);
        assert.equal(decodeJwtPayload('header.!!!not-base64!!!.signature'), null);
        assert.equal(decodeJwtPayload(`header.${Buffer.from('not json').toString('base64url')}.signature`), null);
    });

    await t.test('returns null for a payload that is not a claims object', () => {
        // A bare string or array decodes as valid JSON but is not a claims set, and returning it would
        // hand callers a value that breaks on property access.
        for (const value of ['a string', 42, null, true, ['a', 'b']]) {
            assert.equal(decodeJwtPayload(jwt(value)), null);
        }
    });

    await t.test('returns null for non-string input', () => {
        for (const value of [undefined, null, 42, {}, [], Buffer.from('x')]) {
            assert.equal(decodeJwtPayload(value), null);
        }
    });

    await t.test('refuses to decode an oversized payload segment', () => {
        const huge = 'a'.repeat(MAX_PAYLOAD_LENGTH + 1);
        assert.equal(decodeJwtPayload(`header.${huge}.signature`), null);
    });
});
