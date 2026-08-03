'use strict';

const test = require('node:test');
const assert = require('node:assert').strict;

const { matchesExpectedOAuthIdentity } = require('../lib/oauth/expected-identity');

test('matchesExpectedOAuthIdentity', async t => {
    await t.test('matches provider identities case-insensitively', () => {
        assert.equal(matchesExpectedOAuthIdentity(' Owner@Example.com ', ['owner@example.com']), true);
    });

    await t.test('accepts a secondary provider identity such as a Microsoft UPN', () => {
        assert.equal(matchesExpectedOAuthIdentity('principal@example.com', ['mail-alias@example.com', 'principal@example.com']), true);
    });

    await t.test('rejects an identity that was not returned by the provider', () => {
        assert.equal(matchesExpectedOAuthIdentity('hint@example.com', ['actual@example.com']), false);
    });

    await t.test('rejects empty expected or provider identities', () => {
        assert.equal(matchesExpectedOAuthIdentity('', ['actual@example.com']), false);
        assert.equal(matchesExpectedOAuthIdentity('owner@example.com', [null, undefined, '']), false);
    });
});
