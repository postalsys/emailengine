'use strict';

// Trust-boundary tests for lib/oauth/outlook-identity.js.
//
// The property under test is not "the right name comes out", it is WHICH SOURCE is allowed to decide the
// identity. Microsoft's `client_info` reaches the OAuth2 callback as an unsigned query parameter on the
// front channel, so whoever drives the callback URL writes it; the id_token and the Graph profile arrive
// over the back channel. Because the default MS365 base scopes (`openid profile`, no `email`) mean the
// id_token usually has no `email` claim, a client_info value used to be able to survive as the account's
// email address - and would have satisfied an expectedEmail constraint. These tests pin that shut.

const test = require('node:test');
const assert = require('node:assert').strict;

const { resolveOutlookUserInfo } = require('../lib/oauth/outlook-identity');

test('resolveOutlookUserInfo()', async t => {
    await t.test('never treats a client_info value as identity evidence', () => {
        // The exact shape of the attack: consent as attacker@example.com, then hand-edit the callback URL
        // so client_info claims the owner. The id_token carries no `email` claim, which is the norm.
        const userInfo = resolveOutlookUserInfo({
            clientInfo: { name: 'Owner', preferred_username: 'owner@example.com' },
            idTokenPayload: { name: 'Attacker', preferred_username: 'attacker@example.com' }
        });

        assert.deepEqual(userInfo.verifiedIdentities, ['attacker@example.com']);
        assert.ok(!userInfo.verifiedIdentities.includes('owner@example.com'), 'a client_info address must never be verified evidence');
        // It must not win the persisted address either - that feeds the default From address.
        assert.equal(userInfo.email, 'attacker@example.com');
        assert.equal(userInfo.username, 'attacker@example.com');
    });

    await t.test('a back-channel address wins over client_info for the account email', () => {
        const userInfo = resolveOutlookUserInfo({
            clientInfo: { preferred_username: 'spoofed@example.com' },
            idTokenPayload: { email: 'real@example.com', xms_edov: true, preferred_username: 'real@example.onmicrosoft.com' }
        });

        assert.equal(userInfo.email, 'real@example.com');
        assert.deepEqual(userInfo.verifiedIdentities, ['real@example.com', 'real@example.onmicrosoft.com']);
    });

    await t.test('never takes the account address from client_info, even when nothing else has one', () => {
        // client_info used to fill the address in when no back-channel source had one, and the login
        // fell back to that address, so the browser chose both. The name is still taken as a display
        // hint.
        const userInfo = resolveOutlookUserInfo({
            clientInfo: { name: 'Legacy User', preferred_username: 'legacy@example.com' }
        });

        assert.equal(userInfo.email, null);
        assert.equal(userInfo.name, 'Legacy User');
        assert.deepEqual(userInfo.verifiedIdentities, []);
        assert.equal(userInfo.username, null);
    });

    await t.test('offers both the mailbox address and the user principal name from the Graph profile', () => {
        // Either can be the stable identity for a tenant, and they routinely differ.
        const userInfo = resolveOutlookUserInfo({
            profile: { displayName: 'Nyan Cat', mail: 'nyan@contoso.com', userPrincipalName: 'nyan@contoso.onmicrosoft.com' },
            verifiedDomains: ['contoso.com', 'contoso.onmicrosoft.com']
        });

        assert.equal(userInfo.name, 'Nyan Cat');
        assert.equal(userInfo.email, 'nyan@contoso.com');
        assert.equal(userInfo.username, 'nyan@contoso.onmicrosoft.com');
        assert.deepEqual(userInfo.verifiedIdentities, ['nyan@contoso.com', 'nyan@contoso.onmicrosoft.com']);
    });

    await t.test('keeps a user principal name that is not email-shaped as the login credential', () => {
        // username is what XOAUTH2 authenticates with, so it is passed through as-is. It is not offered as
        // identity evidence, because the comparison is against an email address.
        const userInfo = resolveOutlookUserInfo({
            profile: { mail: 'nyan@contoso.com', userPrincipalName: 'CONTOSO\\nyan' },
            verifiedDomains: ['contoso.com']
        });

        assert.equal(userInfo.username, 'CONTOSO\\nyan');
        assert.deepEqual(userInfo.verifiedIdentities, ['nyan@contoso.com']);
    });

    await t.test('deduplicates identities so the same address is not reported twice', () => {
        const userInfo = resolveOutlookUserInfo({
            idTokenPayload: { email: 'same@example.com', preferred_username: 'same@example.com' }
        });

        assert.deepEqual(userInfo.verifiedIdentities, ['same@example.com']);
    });

    await t.test('drops values that are not email addresses instead of passing them through', () => {
        const userInfo = resolveOutlookUserInfo({
            clientInfo: { name: 42, preferred_username: 'not-an-address' },
            idTokenPayload: { email: 'also-not-an-address' }
        });

        assert.equal(userInfo.email, null);
        assert.equal(userInfo.name, null);
        assert.deepEqual(userInfo.verifiedIdentities, []);
    });

    // Entra ID lets a tenant administrator set `mail` to any address, in a domain the tenant never
    // verified, and Graph returns it unchanged (confirmed against a real tenant on 2026-11-07). Such an
    // address used to sort first in verifiedIdentities, so it satisfied an expectedEmail pin for an
    // address its holder does not own and became the account's address.
    await t.test('a mailbox address in a domain the tenant has not verified is not evidence', () => {
        const userInfo = resolveOutlookUserInfo({
            profile: { mail: 'victim@victim-corp.com', userPrincipalName: 'attacker@attacker.onmicrosoft.com' },
            verifiedDomains: ['attacker.onmicrosoft.com']
        });

        assert.deepEqual(userInfo.verifiedIdentities, ['attacker@attacker.onmicrosoft.com']);
        assert.equal(userInfo.email, 'attacker@attacker.onmicrosoft.com');
        assert.equal(userInfo.username, 'attacker@attacker.onmicrosoft.com');
    });

    await t.test('without the tenant domain list only the user principal name domain vouches', () => {
        assert.deepEqual(resolveOutlookUserInfo({ profile: { mail: 'Nyan@Contoso.com', userPrincipalName: 'nyan@contoso.com' } }).verifiedIdentities, [
            'Nyan@Contoso.com',
            'nyan@contoso.com'
        ]);
        assert.deepEqual(
            resolveOutlookUserInfo({ profile: { mail: 'nyan@contoso.com', userPrincipalName: 'nyan@contoso.onmicrosoft.com' } }).verifiedIdentities,
            ['nyan@contoso.onmicrosoft.com']
        );
    });

    await t.test('an id_token email counts in the user principal name domain or with xms_edov', () => {
        const spoofed = resolveOutlookUserInfo({
            idTokenPayload: { email: 'victim@victim-corp.com', preferred_username: 'attacker@attacker.onmicrosoft.com' }
        });
        assert.deepEqual(spoofed.verifiedIdentities, ['attacker@attacker.onmicrosoft.com']);

        const unverified = resolveOutlookUserInfo({
            idTokenPayload: { email: 'victim@victim-corp.com', xms_edov: false, preferred_username: 'attacker@attacker.onmicrosoft.com' }
        });
        assert.deepEqual(unverified.verifiedIdentities, ['attacker@attacker.onmicrosoft.com']);

        const marked = resolveOutlookUserInfo({
            idTokenPayload: { email: 'nyan@contoso.com', xms_edov: true, preferred_username: 'nyan@contoso.onmicrosoft.com' }
        });
        assert.deepEqual(marked.verifiedIdentities, ['nyan@contoso.com', 'nyan@contoso.onmicrosoft.com']);
    });

    await t.test('tolerates missing and malformed input', () => {
        for (const sources of [undefined, {}, { clientInfo: null, idTokenPayload: null, profile: null }, { profile: 'nope' }]) {
            const userInfo = resolveOutlookUserInfo(sources);
            assert.equal(userInfo.email, null);
            assert.equal(userInfo.username, null);
            assert.deepEqual(userInfo.verifiedIdentities, []);
        }
    });
});

test('readTenantVerifiedDomains()', async t => {
    const { readTenantVerifiedDomains } = require('../lib/oauth/outlook-identity');
    const logger = { warn() {} };
    const client = response => ({
        apiBase: 'https://graph.microsoft.com',
        async request(token, url) {
            assert.equal(token, 'access-token');
            assert.equal(url, 'https://graph.microsoft.com/v1.0/organization?$select=verifiedDomains');
            if (response instanceof Error) {
                throw response;
            }
            return response;
        }
    });

    await t.test('lists the domain names of every organization returned', async () => {
        const domains = await readTenantVerifiedDomains(
            client({ value: [{ verifiedDomains: [{ name: 'contoso.com' }, { name: 'contoso.onmicrosoft.com' }, {}] }] }),
            'access-token',
            logger
        );
        assert.deepEqual(domains, ['contoso.com', 'contoso.onmicrosoft.com']);
    });

    await t.test('a failed or empty answer yields no domains, so only the login domain vouches', async () => {
        assert.deepEqual(await readTenantVerifiedDomains(client(new Error('Forbidden')), 'access-token', logger), []);
        assert.deepEqual(await readTenantVerifiedDomains(client({ value: [] }), 'access-token', logger), []);
        assert.deepEqual(await readTenantVerifiedDomains(client(null), 'access-token', logger), []);
    });
});
