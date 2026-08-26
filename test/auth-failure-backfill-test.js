'use strict';

// Coverage for the 2.79.3 -> 2.79.4 bridge in lib/account/auth-failure-backfill.js.
//
// 2.79.3 parked accounts by writing `imap.disabled` alone. 2.79.4 reads a separate marker to tell
// its own park from the operator's send-only switch, and every recovery surface is gated on it - so
// without a backfill, an OAuth2 account parked during the 2.79.3 window reads as deliberately
// switched off and re-authorizing it lifts nothing.
//
// The seeds below are the stored hash shapes, spelled out rather than produced by running the old
// code, because the old code is what this bridges away from. Two of them guard the edges of the
// signature: a password account carrying the same threshold error state has been reachable since
// v2.46.0 and must NOT be stamped with a park time of today, and neither must an account an
// operator switched off.

const test = require('node:test');
const assert = require('node:assert').strict;
const crypto = require('crypto');

const { Account } = require('../lib/account');
const { redis } = require('../lib/db');
const registerRedisTeardown = require('./helpers/redis-teardown');
const { accountKeyFor, noopLogger } = require('./helpers/auth-failure');
const { backfillAuthFailureDisabled, isLegacyPark, BACKFILL_KEY } = require('../lib/account/auth-failure-backfill');
const { REDIS_PREFIX, AUTH_FAILURE_DISABLED_FIELD } = require('../lib/consts');

const ACCOUNTS_KEY = `${REDIS_PREFIX}ia:accounts`;

// Unique per run, so the scan below cannot collide with an account another test file left behind
const suffix = crypto.randomBytes(4).toString('hex');
const idFor = name => `backfill-${name}-${suffix}`;

const createdAccounts = new Set();

// The park 2.79.3 left behind: the flag, the threshold error state, an OAuth2 credential, no marker
const legacyErrorState = JSON.stringify({
    description: 'IMAP was disabled for the account due to exceeding the authentication error threshold',
    response: 'invalid_grant'
});
const oauth2Credential = JSON.stringify({ provider: 'gmail', auth: { user: 'user@example.com' } });

// SCAN_FIELDS order: imap, marker, lastErrorState, oauth2
const row = ({ imap = null, marker = null, errorState = legacyErrorState, oauth2 = oauth2Credential } = {}) => [
    imap === null ? null : JSON.stringify(imap),
    marker,
    errorState,
    oauth2
];

async function seedAccount(name, fields) {
    const account = idFor(name);
    createdAccounts.add(account);

    const accountKey = accountKeyFor(account);
    const values = { account };
    for (const [field, value] of Object.entries(fields)) {
        values[field] = typeof value === 'string' ? value : JSON.stringify(value);
    }

    await redis.multi().hmset(accountKey, values).sadd(ACCOUNTS_KEY, account).exec();
    return { account, accountKey };
}

const markerOf = accountKey => redis.hget(accountKey, AUTH_FAILURE_DISABLED_FIELD);
const imapOf = async accountKey => JSON.parse(await redis.hget(accountKey, 'imap'));

registerRedisTeardown(redis, async () => {
    const txn = redis.multi().del(BACKFILL_KEY);
    for (const account of createdAccounts) {
        txn.del(accountKeyFor(account)).srem(ACCOUNTS_KEY, account);
    }
    await txn.exec();
});

test('isLegacyPark', async t => {
    await t.test('matches the blob 2.79.3 synthesized for an OAuth2 account', () => {
        assert.strictEqual(isLegacyPark(row({ imap: { disabled: true } })), true);
    });

    await t.test('ignores an account that already carries the marker', () => {
        // Parked by 2.79.4 or later, and its recorded time is the real one
        assert.strictEqual(isLegacyPark(row({ imap: { disabled: true }, marker: '2026-08-25T10:00:00.000Z' })), false);
    });

    await t.test('ignores a password account wearing the same error state', () => {
        // The safety net has parked these since v2.46.0. They were never stuck - the account page
        // renders the disable checkbox, and clearing it is an explicit `disabled: false` that no
        // marker gates - so stamping them would only backdate a two-year-old park to today.
        assert.strictEqual(isLegacyPark(row({ imap: { host: 'imap.test', port: 993, disabled: true }, oauth2: null })), false);
        assert.strictEqual(isLegacyPark(row({ imap: { host: 'imap.test', port: 993, disabled: true } })), false);
    });

    await t.test('ignores a disable with no threshold error state beside it', () => {
        // The operator's send-only switch. Reading `imap.disabled` alone here is exactly the
        // conflation 2.79.4 introduced the marker to end.
        assert.strictEqual(isLegacyPark(row({ imap: { disabled: true }, errorState: null })), false);
        assert.strictEqual(isLegacyPark(row({ imap: { disabled: true }, errorState: JSON.stringify({ response: 'timeout' }) })), false);
    });

    await t.test('ignores an account that is not switched off', () => {
        assert.strictEqual(isLegacyPark(row({ imap: { disabled: false } })), false);
        assert.strictEqual(isLegacyPark(row({ imap: null })), false);
    });

    await t.test('ignores blobs that do not parse or cannot hold a flag', () => {
        assert.strictEqual(isLegacyPark(['not json', null, legacyErrorState, oauth2Credential]), false);
        assert.strictEqual(isLegacyPark(['true', null, legacyErrorState, oauth2Credential]), false);
        assert.strictEqual(isLegacyPark([JSON.stringify({ disabled: true }), null, 'not json', oauth2Credential]), false);
    });
});

test('backfillAuthFailureDisabled', async t => {
    await redis.del(BACKFILL_KEY);

    const legacy = await seedAccount('legacy', {
        oauth2: oauth2Credential,
        imap: { disabled: true },
        lastErrorState: legacyErrorState
    });

    const operator = await seedAccount('operator', {
        oauth2: oauth2Credential,
        imap: { disabled: true }
    });

    const password = await seedAccount('password', {
        imap: { host: 'imap.test', port: 993, disabled: true },
        lastErrorState: legacyErrorState
    });

    const marked = await seedAccount('marked', {
        oauth2: oauth2Credential,
        imap: { disabled: true },
        lastErrorState: legacyErrorState,
        [AUTH_FAILURE_DISABLED_FIELD]: '2026-08-24T21:00:00.000Z'
    });

    const healthy = await seedAccount('healthy', {
        oauth2: oauth2Credential,
        imap: { disabled: false }
    });

    await t.test('the OAuth2 accounts 2.79.3 parked get the marker, and nothing else does', async () => {
        const backfilled = await backfillAuthFailureDisabled({ redis, logger: noopLogger });
        assert.ok(backfilled >= 1, 'at least the seeded park was backfilled');

        const disabledAt = await markerOf(legacy.accountKey);
        assert.ok(disabledAt, 'the legacy park is now recognisable as ours');
        assert.ok(!Number.isNaN(Date.parse(disabledAt)), 'and carries a readable timestamp');

        assert.strictEqual(await markerOf(operator.accountKey), null, "the operator's send-only switch is left alone");
        assert.strictEqual(await markerOf(password.accountKey), null, 'a password account keeps its own recovery path');
        assert.strictEqual(await markerOf(healthy.accountKey), null, 'an account that is not switched off is left alone');
        assert.strictEqual(await markerOf(marked.accountKey), '2026-08-24T21:00:00.000Z', 'a real park time is not overwritten with the backfill time');

        assert.strictEqual((await imapOf(legacy.accountKey)).disabled, true, 'the backfill records provenance, it does not resume anything');
    });

    await t.test('a backfilled account is recoverable by re-authorization', async () => {
        // The call both Account.create() and Account.update() reach through
        // resolveAuthFailureDisable() when fresh credentials arrive. Before the backfill it
        // returned false here, which is what left a re-authorized account silently switched off.
        const accountObject = new Account({ redis, account: legacy.account, logger: noopLogger });

        assert.strictEqual(await accountObject.clearAuthFailureDisable(), true, 'the disable is lifted');
        assert.strictEqual((await imapOf(legacy.accountKey)).disabled, false, 'and the account may sync again');
        assert.strictEqual(await markerOf(legacy.accountKey), null, 'the marker goes with it');
    });

    await t.test('it does not run a second time', async () => {
        const late = await seedAccount('late', {
            oauth2: oauth2Credential,
            imap: { disabled: true },
            lastErrorState: legacyErrorState
        });

        assert.strictEqual(await backfillAuthFailureDisabled({ redis, logger: noopLogger }), 0, 'the completion key stops the scan');
        assert.strictEqual(await markerOf(late.accountKey), null, 'so nothing is scanned again');
        assert.ok(await redis.get(BACKFILL_KEY), 'and the completion key records when it ran');
    });
});
