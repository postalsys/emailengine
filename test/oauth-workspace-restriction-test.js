'use strict';

// The "Accept only Google Workspace accounts" restriction of a Gmail OAuth2 application has two halves,
// and for its first four years only the first one existed.
//
// `hd=*` on the authorization URL filters the account chooser Google SHOWS. Nothing stops a link being
// assembled without it, or a user switching account inside the chooser, so the restriction could only
// ever be enforced on the way back: the hosted-domain claim of the ID token, which Google sets only for
// an account that belongs to a Workspace or Cloud organization. Both halves are pinned here so neither
// can be removed on its own.
//
// Hermetic: no network, no Redis.

const test = require('node:test');
const assert = require('node:assert').strict;

const { GmailOauth, workspaceDomainOf } = require('../lib/oauth/gmail');

const APP = { clientId: 'client-id', clientSecret: 'client-secret', redirectUrl: 'https://ee.example.com/oauth' };

test('workspaceDomainOf()', async t => {
    await t.test('reports the hosted domain of a Workspace account', () => {
        assert.equal(workspaceDomainOf({ email: 'user@example.com', hd: 'example.com' }), 'example.com');
    });

    // Every one of these is what a personal Google account looks like on the callback, and every one of
    // them used to complete the setup of a Workspace-only application
    await t.test('reports nothing for a consumer account', () => {
        assert.equal(workspaceDomainOf({ email: 'user@gmail.com' }), null);
        assert.equal(workspaceDomainOf({ email: 'user@gmail.com', hd: '' }), null);
        assert.equal(workspaceDomainOf({ email: 'user@gmail.com', hd: '   ' }), null);
    });

    await t.test('reports nothing when there is no token to read', () => {
        // decodeJwtPayload() answers null for a token it cannot decode, and an application whose
        // scopes never asked for openid gets no id_token at all
        assert.equal(workspaceDomainOf(null), null);
        assert.equal(workspaceDomainOf(undefined), null);
    });

    await t.test('refuses a claim that is not a domain string', () => {
        // The claim is read off a token this process decoded without verifying the signature, so a
        // non-string must not become a truthy domain
        assert.equal(workspaceDomainOf({ hd: true }), null);
        assert.equal(workspaceDomainOf({ hd: ['example.com'] }), null);
        assert.equal(workspaceDomainOf({ hd: 1 }), null);
    });

    await t.test('keeps the domain of a Workspace account on a gmail.com-looking address', () => {
        assert.equal(workspaceDomainOf({ hd: 'example.com', email: 'user@gmail.example.com' }), 'example.com');
    });
});

test('the Workspace restriction is enforceable on the way back', async t => {
    await t.test('a restricted application still hints the chooser with hd=*', () => {
        const url = new URL(new GmailOauth(Object.assign({ workspaceAccounts: true }, APP)).generateAuthUrl({}));
        assert.equal(url.searchParams.get('hd'), '*');
    });

    await t.test('an unrestricted application sends no hd argument', () => {
        const url = new URL(new GmailOauth(Object.assign({}, APP)).generateAuthUrl({}));
        assert.equal(url.searchParams.get('hd'), null);
    });

    await t.test('three-legged OAuth always requests the scopes the claim arrives with', () => {
        // The check in the /oauth callback refuses a token that names no domain, which is only safe
        // because an id_token is always asked for here - the constructor adds the OpenID scopes to
        // every non-service-account application whatever its configured scopes are
        const client = new GmailOauth(Object.assign({ scopes: ['https://mail.google.com/'], workspaceAccounts: true }, APP));
        for (const scope of ['openid', 'email', 'profile']) {
            assert.ok(client.scopes.includes(scope), scope);
        }
    });
});
