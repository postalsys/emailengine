'use strict';

// Tests for lib/oauth/retry-setup.js.
//
// The property under test is what a retry INHERITS from the attempt that was rejected. By the time a
// retry is offered, the provider branches have rewritten the pending record from whoever actually signed
// in, so carrying that forward binds the wrong mailbox or keeps the wrong name, while rebuilding from
// scratch drops what the caller asked for. Both are silent - the retry reports success either way.

const test = require('node:test');
const assert = require('node:assert').strict;

const { buildRetrySetup } = require('../lib/oauth/retry-setup');

// Shaped like accountData at the point a rejection is detected: the caller's fields already overwritten
// with the rejected identity, and that identity's tokens attached.
const rejectedAttempt = extra =>
    Object.assign(
        {
            account: 'acc1',
            email: 'wrong-person@example.com',
            name: 'Wrong Person',
            oauth2: {
                provider: 'app-id',
                accessToken: 'ACCESS',
                refreshToken: 'REFRESH',
                auth: { user: 'wrong-person@example.com' }
            }
        },
        extra
    );

test('buildRetrySetup()', async t => {
    await t.test('drops the tokens the rejected attempt obtained', () => {
        const retry = buildRetrySetup(rejectedAttempt(), { email: 'owner@example.com' }, 'app-id', {});

        assert.deepEqual(retry.oauth2, { provider: 'app-id' });
        assert.equal(retry.oauth2.accessToken, undefined);
        assert.equal(retry.oauth2.refreshToken, undefined);
    });

    await t.test('keeps a delegated mailbox target, which names a mailbox rather than a credential', () => {
        // Losing this turns a shared-mailbox setup into a personal one: the retry would bind the
        // principal's own mailbox and report success.
        const retry = buildRetrySetup(rejectedAttempt(), { email: 'support@corp.com', name: 'Support', delegatedUser: 'support@corp.com' }, 'app-id', {});

        assert.equal(retry.oauth2.auth.delegatedUser, 'support@corp.com');
        assert.equal(retry.oauth2.provider, 'app-id');
        assert.equal(retry.oauth2.accessToken, undefined, 'the delegation target must not drag the tokens back in');
        // Both Outlook delegation paths key on email, so the shared mailbox has to survive too.
        assert.equal(retry.email, 'support@corp.com');
    });

    await t.test('restores the caller fields the rejected identity had overwritten', () => {
        const retry = buildRetrySetup(rejectedAttempt(), { email: 'owner@example.com', name: 'Owner' }, 'app-id', {});

        assert.equal(retry.email, 'owner@example.com');
        assert.equal(retry.name, 'Owner');
    });

    await t.test('leaves the fields empty when the caller supplied none', () => {
        // Rather than inheriting the rejected user's address and display name, which would otherwise stick
        // to the account and become its outgoing From name.
        const retry = buildRetrySetup(rejectedAttempt(), {}, 'app-id', {});

        assert.equal(retry.email, undefined);
        assert.equal(retry.name, undefined);
    });

    await t.test('carries _meta through unchanged so the setup keeps its identity pin and nonce', () => {
        const accountMeta = { redirectUrl: 'https://app.example.com/done', expectedEmail: 'owner@example.com', n: 'nonce', t: 1 };
        const retry = buildRetrySetup(rejectedAttempt(), { email: 'owner@example.com' }, 'app-id', accountMeta);

        assert.deepEqual(retry._meta, accountMeta);
    });

    await t.test('preserves unrelated account fields and does not mutate the input', () => {
        const attempt = rejectedAttempt({ delegated: true, notifyFrom: '2026-01-01T00:00:00.000Z' });
        const retry = buildRetrySetup(attempt, { email: 'support@corp.com' }, 'app-id', {});

        assert.equal(retry.delegated, true);
        assert.equal(retry.notifyFrom, '2026-01-01T00:00:00.000Z');
        assert.equal(retry.account, 'acc1');
        assert.equal(attempt.email, 'wrong-person@example.com', 'the caller keeps using accountData afterwards');
        assert.equal(attempt.oauth2.accessToken, 'ACCESS');
    });

    await t.test('tolerates a missing requestedSetup', () => {
        const retry = buildRetrySetup(rejectedAttempt(), undefined, 'app-id', {});
        assert.deepEqual(retry.oauth2, { provider: 'app-id' });
    });
});
