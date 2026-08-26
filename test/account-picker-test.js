'use strict';

// The data behind the admin account picker (views/partials/ui/account-picker.hbs): the summary
// lookup in lib/account.js and the two formatters in lib/ui-routes/route-helpers.js that every page
// carrying the control renders through.
//
// Needs Redis (the summary reads an account hash) but no server and no worker, so it writes the
// hash it reads directly rather than creating an account.

const test = require('node:test');
const assert = require('node:assert').strict;

const { redis } = require('../lib/db');
const registerRedisTeardown = require('./helpers/redis-teardown');
const { REDIS_PREFIX, AUTH_FAILURE_DISABLED_LEGACY_DESCRIPTION } = require('../lib/consts');
const { accountSummary } = require('../lib/account');
const { accountPickerEntry, accountPickerSelection, formatAccountData } = require('../lib/ui-routes/route-helpers');

const ACCOUNT = 'picker-test-account';
const ACCOUNT_KEY = `${REDIS_PREFIX}iad:${ACCOUNT}`;

registerRedisTeardown(redis, () => redis.del(ACCOUNT_KEY));

test('accountSummary', async t => {
    await t.test('reads the display fields of a stored account', async () => {
        await redis.hmset(ACCOUNT_KEY, { account: ACCOUNT, name: 'Jane Roe', email: 'jane@example.com', state: 'connected' });

        assert.deepEqual(await accountSummary(redis, ACCOUNT), {
            account: ACCOUNT,
            name: 'Jane Roe',
            email: 'jane@example.com',
            state: 'connected'
        });
    });

    await t.test('fills in for the fields a record does not carry', async () => {
        await redis.del(ACCOUNT_KEY);
        await redis.hmset(ACCOUNT_KEY, { account: ACCOUNT });

        assert.deepEqual(await accountSummary(redis, ACCOUNT), { account: ACCOUNT, name: '', email: '', state: 'init' });
    });

    await t.test('answers null rather than a blank record for an account that does not exist', async () => {
        // A hash key that is simply absent answers nulls for every field, which would otherwise
        // render as an account with no name - the picker has to be able to tell the two apart
        assert.equal(await accountSummary(redis, 'no-such-account-at-all'), null);
        assert.equal(await accountSummary(redis, ''), null);
    });
});

test('accountPickerEntry', async t => {
    await t.test('carries the three things a person recognises an account by', () => {
        assert.deepEqual(accountPickerEntry({ account: 'acct-1', name: 'Jane Roe', email: 'jane@example.com', state: 'connected' }), {
            account: 'acct-1',
            name: 'Jane Roe',
            email: 'jane@example.com',
            state: { type: 'success', name: 'Connected' }
        });
    });

    await t.test('describes a connection the same way the account listings do', () => {
        assert.deepEqual(accountPickerEntry({ account: 'acct-1', state: 'authenticationError' }).state, {
            type: 'error',
            name: 'Connection failed'
        });
        assert.deepEqual(accountPickerEntry({ account: 'acct-1', state: 'unset' }).state, { type: 'neutral', name: 'Not syncing' });
        // An unknown state is a state, not a crash: the badge falls back rather than the page
        assert.deepEqual(accountPickerEntry({ account: 'acct-1', state: 'something-new' }).state, { type: 'neutral', name: 'N/A' });
    });

    await t.test('turns absent name and address into empty strings', () => {
        // The browser picks the title from these, and undefined would render as the word
        const entry = accountPickerEntry({ account: 'acct-1', state: 'connected' });
        assert.equal(entry.name, '');
        assert.equal(entry.email, '');
    });
});

test('accountPickerSelection', async t => {
    await t.test('resolves the account a form already holds', async () => {
        await redis.del(ACCOUNT_KEY);
        await redis.hmset(ACCOUNT_KEY, { account: ACCOUNT, name: 'Jane Roe', email: 'jane@example.com', state: 'syncing' });

        assert.deepEqual(await accountPickerSelection(ACCOUNT), {
            account: ACCOUNT,
            name: 'Jane Roe',
            email: 'jane@example.com',
            state: { type: 'info', name: 'Syncing' }
        });
    });

    await t.test('answers null for an empty field and for a deleted account', async () => {
        // Both render the same way in the browser - the empty search box, or the id shown back as
        // one the picker could not resolve - and neither is an error the page should fail on
        assert.equal(await accountPickerSelection(''), null);
        assert.equal(await accountPickerSelection(null), null);
        assert.equal(await accountPickerSelection('no-such-account-at-all'), null);
    });
});

test('formatAccountData state badge for a switched-off account', async t => {
    const gt = { gettext: text => text };
    const legacyPark = () => ({
        account: 'legacy-park',
        state: 'unset',
        imap: { host: 'imap.example.com', disabled: true },
        lastErrorState: { description: AUTH_FAILURE_DISABLED_LEGACY_DESCRIPTION }
    });

    await t.test('a park recorded before the marker existed is still badged as switched off', () => {
        // Password accounts the safety net parked between v2.46.0 and 2.79.3 carry no marker and
        // are deliberately not backfilled with one. They used to be badged with the threshold text;
        // keying the badge on the marker alone rendered them as a neutral "Not syncing".
        const account = formatAccountData(legacyPark(), gt);
        assert.strictEqual(account.stateLabel.type, 'error');
        assert.strictEqual(account.stateLabel.name, 'Syncing switched off');
        assert.strictEqual(account.stateLabel.error, AUTH_FAILURE_DISABLED_LEGACY_DESCRIPTION);
    });

    await t.test('a send-only account that once failed to connect is not', () => {
        const account = formatAccountData(Object.assign(legacyPark(), { lastErrorState: { response: 'connection refused' } }), gt);
        assert.notStrictEqual(account.stateLabel.name, 'Syncing switched off');
    });
});
