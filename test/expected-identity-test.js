'use strict';

// Tests for lib/account/expected-identity.js - the comparison and precedence rules shared by the OAuth2
// callback (workers/api.js) and the IMAP arm of the hosted form (lib/ui-routes/account-routes.js).

const test = require('node:test');
const assert = require('node:assert').strict;

const { normalizeEmail, matchesExpectedIdentity, pendingSetupExpectation, resolveExpectedIdentity } = require('../lib/account/expected-identity');

test('matchesExpectedIdentity()', async t => {
    await t.test('matches case-insensitively and ignores surrounding whitespace', () => {
        assert.equal(matchesExpectedIdentity(' Owner@Example.com ', ['owner@example.com']), true);
        assert.equal(matchesExpectedIdentity('owner@example.com', ['  OWNER@EXAMPLE.COM']), true);
    });

    await t.test('accepts any one of several provider identities', () => {
        // Microsoft returns both a mailbox address and a user principal name, and either can be the
        // stable identity for a tenant.
        const identities = ['nyan@contoso.com', 'nyan@contoso.onmicrosoft.com'];
        assert.equal(matchesExpectedIdentity('nyan@contoso.onmicrosoft.com', identities), true);
        assert.equal(matchesExpectedIdentity('nyan@contoso.com', identities), true);
    });

    await t.test('rejects an address the provider did not return', () => {
        assert.equal(matchesExpectedIdentity('owner@example.com', ['attacker@example.com']), false);
    });

    await t.test('fails closed when there is no identity evidence at all', () => {
        // A provider case that collects nothing must reject rather than admit. This is what keeps a future
        // provider that forgets to report its identities from silently disabling the constraint.
        assert.equal(matchesExpectedIdentity('owner@example.com', []), false);
        assert.equal(matchesExpectedIdentity('owner@example.com', [null, undefined, '', false, 0]), false);
    });

    await t.test('fails closed on an empty expectation or a non-array identity list', () => {
        assert.equal(matchesExpectedIdentity('', ['owner@example.com']), false);
        assert.equal(matchesExpectedIdentity(null, ['owner@example.com']), false);
        assert.equal(matchesExpectedIdentity('   ', ['owner@example.com']), false);
        assert.equal(matchesExpectedIdentity('owner@example.com', null), false);
        assert.equal(matchesExpectedIdentity('owner@example.com', 'owner@example.com'), false);
    });

    await t.test('does not treat a substring or a lookalike as a match', () => {
        assert.equal(matchesExpectedIdentity('owner@example.com', ['owner@example.com.evil.test']), false);
        assert.equal(matchesExpectedIdentity('owner@example.com', ['owner@example.co']), false);
        assert.equal(matchesExpectedIdentity('owner@example.com', ['xowner@example.com']), false);
    });
});

test('resolveExpectedIdentity()', async t => {
    // Records reads so the tests can assert that Redis is touched only when it has to be.
    const stubRedis = stored => {
        const reads = [];
        return {
            reads,
            hget: async (key, field) => {
                reads.push({ key, field });
                return stored;
            }
        };
    };

    await t.test('prefers the expectation carried by the signed form blob', async () => {
        // A freshly signed blob is a deliberate re-statement by the authenticated caller, which is how a
        // legitimate mailbox migration gets through a pinned account.
        const redis = stubRedis('old@example.com');
        assert.equal(await resolveExpectedIdentity(redis, { account: 'acc', blobExpectation: 'new@example.com' }), 'new@example.com');
        // And the stored value is never even read, since it could not have changed the answer.
        assert.deepEqual(redis.reads, []);
    });

    await t.test('falls back to the expectation stored on the account', async () => {
        // A link with no expectation of its own (an older link, or the admin re-authenticate blob) must
        // inherit the pin rather than clear it - otherwise the constraint would not outlive one link.
        for (const blobExpectation of [undefined, '', '  ']) {
            const redis = stubRedis('owner@example.com');
            assert.equal(await resolveExpectedIdentity(redis, { account: 'acc', blobExpectation }), 'owner@example.com');
            assert.deepEqual(redis.reads, [{ key: 'iad:acc', field: 'expectedEmail' }]);
        }
    });

    await t.test('treats the cleared marker on the account as no expectation', async () => {
        // serializeAccountData writes '' to clear a pin rather than deleting the field.
        const redis = stubRedis('');
        assert.equal(await resolveExpectedIdentity(redis, { account: 'acc' }), null);
    });

    await t.test('returns null when neither side pins an identity', async () => {
        assert.equal(await resolveExpectedIdentity(stubRedis(null), { account: 'acc' }), null);
        // No account to look up: no read at all.
        const redis = stubRedis('owner@example.com');
        assert.equal(await resolveExpectedIdentity(redis, {}), null);
        assert.equal(await resolveExpectedIdentity(redis), null);
        assert.deepEqual(redis.reads, []);
    });
});

test('pendingSetupExpectation()', async t => {
    // Two entry points build the pending OAuth2 record differently, and reading only one of them skipped
    // the check entirely on the other - on the setup that decides which mailbox gets bound, while still
    // persisting the pin afterwards so it looked active. Both shapes must be honored.
    await t.test('reads the hosted form shape, where the pin sits in _meta', () => {
        assert.equal(pendingSetupExpectation({ account: 'acc' }, { expectedEmail: 'owner@example.com' }), 'owner@example.com');
    });

    await t.test('reads the POST /v1/account shape, where the pin stays at the top level', () => {
        assert.equal(
            pendingSetupExpectation({ account: 'acc', expectedEmail: 'owner@example.com' }, { redirectUrl: 'https://app.example.com' }),
            'owner@example.com'
        );
    });

    await t.test('prefers _meta when a record somehow carries both', () => {
        assert.equal(pendingSetupExpectation({ expectedEmail: 'top@example.com' }, { expectedEmail: 'meta@example.com' }), 'meta@example.com');
    });

    await t.test('returns null when neither shape carries one', () => {
        assert.equal(pendingSetupExpectation({ account: 'acc' }, {}), null);
        assert.equal(pendingSetupExpectation(null, null), null);
        assert.equal(pendingSetupExpectation(), null);
    });
});

test('normalizeEmail()', async t => {
    await t.test('lowercases and trims strings, and maps everything else to an empty string', () => {
        assert.equal(normalizeEmail('  User@Example.COM '), 'user@example.com');
        for (const value of [null, undefined, 42, {}, [], true]) {
            assert.equal(normalizeEmail(value), '');
        }
    });
});
