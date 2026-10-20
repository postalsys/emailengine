'use strict';

const test = require('node:test');
const assert = require('node:assert').strict;

const { resolveOutlookMailbox } = require('../lib/oauth/outlook-mailbox');

const signedIn = { email: 'user@example.com' };

test('resolveOutlookMailbox', async t => {
    await t.test('oauth2.auth.delegatedUser names the shared mailbox and fills in a missing address', () => {
        const accountData = { oauth2: { auth: { delegatedUser: 'shared@example.com' } } };
        assert.deepStrictEqual(resolveOutlookMailbox(accountData, signedIn), { email: 'shared@example.com', delegatedUser: 'shared@example.com' });
    });

    await t.test('oauth2.auth.delegatedUser keeps an address the setup named', () => {
        const accountData = { email: 'alias@example.com', oauth2: { auth: { delegatedUser: 'shared@example.com' } } };
        assert.deepStrictEqual(resolveOutlookMailbox(accountData, signedIn), { email: 'alias@example.com', delegatedUser: 'shared@example.com' });
    });

    await t.test('oauth2.auth.delegatedUser wins over the legacy delegated flag', () => {
        const accountData = { email: 'other@example.com', delegated: true, oauth2: { auth: { delegatedUser: 'shared@example.com' } } };
        assert.deepStrictEqual(resolveOutlookMailbox(accountData, signedIn), { email: 'other@example.com', delegatedUser: 'shared@example.com' });
    });

    await t.test('the legacy delegated flag makes a different address the shared mailbox', () => {
        const accountData = { email: 'shared@example.com', delegated: true, oauth2: { auth: {} } };
        assert.deepStrictEqual(resolveOutlookMailbox(accountData, signedIn), { email: 'shared@example.com', delegatedUser: 'shared@example.com' });
    });

    await t.test('the legacy delegated flag with the signed-in address is the own mailbox', () => {
        const accountData = { email: 'user@example.com', delegated: true };
        assert.deepStrictEqual(resolveOutlookMailbox(accountData, signedIn), { email: 'user@example.com', delegatedUser: undefined });
    });

    await t.test('the legacy delegated flag without an address is the own mailbox', () => {
        const accountData = { delegated: true };
        assert.deepStrictEqual(resolveOutlookMailbox(accountData, signedIn), { email: 'user@example.com', delegatedUser: undefined });
    });

    await t.test('a plain setup takes the signed-in address over the one it named', () => {
        const accountData = { email: 'typed@example.com', oauth2: { provider: 'outlook' } };
        assert.deepStrictEqual(resolveOutlookMailbox(accountData, signedIn), { email: 'user@example.com', delegatedUser: undefined });
    });

    await t.test('a plain setup with no resolved address leaves the address unset', () => {
        assert.deepStrictEqual(resolveOutlookMailbox({}, {}), { email: undefined, delegatedUser: undefined });
    });

    await t.test('the account data is not modified', () => {
        const accountData = { oauth2: { auth: { delegatedUser: 'shared@example.com' } } };
        resolveOutlookMailbox(accountData, signedIn);
        assert.deepStrictEqual(accountData, { oauth2: { auth: { delegatedUser: 'shared@example.com' } } });
    });
});
