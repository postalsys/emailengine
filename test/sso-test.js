'use strict';

// Hermetic unit tests for lib/sso.js pure helpers. No DB or network - discovery
// fetching (fetchOidcDiscovery) is intentionally not exercised here.

const test = require('node:test');
const { after } = require('node:test');
const assert = require('node:assert').strict;

const sso = require('../lib/sso');

after(() => {
    // Force exit after tests to prevent hanging on Redis connections pulled in by
    // lib/sso -> lib/tools -> lib/settings. Same pattern as test/tools-test.js.
    setTimeout(() => process.exit(), 1000).unref();
});

test('parseScopes', async t => {
    await t.test('defaults when empty', () => {
        assert.deepEqual(sso.parseScopes(''), ['openid', 'profile', 'email']);
        assert.deepEqual(sso.parseScopes(null), ['openid', 'profile', 'email']);
        assert.deepEqual(sso.parseScopes(undefined), ['openid', 'profile', 'email']);
    });

    await t.test('splits on whitespace and commas', () => {
        assert.deepEqual(sso.parseScopes('openid profile email'), ['openid', 'profile', 'email']);
        assert.deepEqual(sso.parseScopes('openid, profile ,email'), ['openid', 'profile', 'email']);
    });

    await t.test('forces openid in when omitted', () => {
        assert.deepEqual(sso.parseScopes('profile email'), ['openid', 'profile', 'email']);
    });

    await t.test('does not duplicate openid', () => {
        assert.deepEqual(sso.parseScopes('openid custom'), ['openid', 'custom']);
    });
});

test('parseAllowList', async t => {
    await t.test('empty inputs yield empty list', () => {
        assert.deepEqual(sso.parseAllowList(''), []);
        assert.deepEqual(sso.parseAllowList(null), []);
        assert.deepEqual(sso.parseAllowList(undefined), []);
    });

    await t.test('parses emails and domains, lowercased and trimmed', () => {
        assert.deepEqual(sso.parseAllowList(' Alice@Example.com , @Corp.Example.com ,, '), [
            { type: 'email', value: 'alice@example.com' },
            { type: 'domain', value: 'corp.example.com' }
        ]);
    });
});

test('isAllowedUser', async t => {
    await t.test('empty allow-list allows everyone', () => {
        assert.equal(sso.isAllowedUser({ email: 'anyone@example.com' }, []), true);
        assert.equal(sso.isAllowedUser({}, []), true);
        assert.equal(sso.isAllowedUser({ email: 'anyone@example.com' }, null), true);
    });

    await t.test('exact email match (case-insensitive)', () => {
        const list = sso.parseAllowList('alice@example.com');
        assert.equal(sso.isAllowedUser({ email: 'Alice@Example.com' }, list), true);
        assert.equal(sso.isAllowedUser({ email: 'bob@example.com' }, list), false);
    });

    await t.test('domain match', () => {
        const list = sso.parseAllowList('@corp.example.com');
        assert.equal(sso.isAllowedUser({ email: 'anyone@corp.example.com' }, list), true);
        assert.equal(sso.isAllowedUser({ email: 'anyone@other.example.com' }, list), false);
    });

    await t.test('falls back to username when email is absent', () => {
        const list = sso.parseAllowList('@corp.example.com');
        assert.equal(sso.isAllowedUser({ username: 'anyone@corp.example.com' }, list), true);
    });

    await t.test('non-empty list with no usable identifier denies', () => {
        const list = sso.parseAllowList('alice@example.com');
        assert.equal(sso.isAllowedUser({}, list), false);
        assert.equal(sso.isAllowedUser({ email: '' }, list), false);
        assert.equal(sso.isAllowedUser(null, list), false);
    });
});

test('getDiscoveryUrl', async t => {
    await t.test('appends well-known path', () => {
        assert.equal(sso.getDiscoveryUrl('https://idp.example.com/realms/main'), 'https://idp.example.com/realms/main/.well-known/openid-configuration');
    });

    await t.test('strips trailing slashes', () => {
        assert.equal(sso.getDiscoveryUrl('https://idp.example.com/app/o/ee/'), 'https://idp.example.com/app/o/ee/.well-known/openid-configuration');
        assert.equal(sso.getDiscoveryUrl('https://idp.example.com///'), 'https://idp.example.com/.well-known/openid-configuration');
    });
});

test('validateDiscoveryDocument', async t => {
    const issuer = 'https://idp.example.com/realms/main';
    const good = {
        issuer,
        authorization_endpoint: `${issuer}/protocol/openid-connect/auth`,
        token_endpoint: `${issuer}/protocol/openid-connect/token`,
        userinfo_endpoint: `${issuer}/protocol/openid-connect/userinfo`
    };

    await t.test('accepts a valid document', () => {
        assert.equal(sso.validateDiscoveryDocument(good, issuer), good);
    });

    await t.test('accepts an issuer differing only by trailing slash', () => {
        assert.doesNotThrow(() => sso.validateDiscoveryDocument(Object.assign({}, good, { issuer: `${issuer}/` }), issuer));
    });

    await t.test('rejects a non-object', () => {
        assert.throws(() => sso.validateDiscoveryDocument(null, issuer), /empty or not an object/);
    });

    await t.test('rejects a missing endpoint', () => {
        for (const key of ['authorization_endpoint', 'token_endpoint', 'userinfo_endpoint']) {
            const doc = Object.assign({}, good);
            delete doc[key];
            assert.throws(() => sso.validateDiscoveryDocument(doc, issuer), new RegExp(`missing "${key}"`));
        }
    });

    await t.test('rejects an issuer mismatch', () => {
        const doc = Object.assign({}, good, { issuer: 'https://evil.example.com' });
        assert.throws(() => sso.validateDiscoveryDocument(doc, issuer), /issuer mismatch/);
    });
});

test('mapUserinfoProfile', async t => {
    await t.test('maps standard claims', () => {
        assert.deepEqual(sso.mapUserinfoProfile({ sub: 'abc', email: 'alice@example.com', name: 'Alice A' }), {
            id: 'abc',
            username: 'alice@example.com',
            displayName: 'Alice A',
            email: 'alice@example.com'
        });
    });

    await t.test('username precedence email > preferred_username > sub', () => {
        assert.equal(sso.mapUserinfoProfile({ sub: 's', preferred_username: 'p', email: 'e@x' }).username, 'e@x');
        assert.equal(sso.mapUserinfoProfile({ sub: 's', preferred_username: 'p' }).username, 'p');
        assert.equal(sso.mapUserinfoProfile({ sub: 's' }).username, 's');
    });

    await t.test('displayName precedence name > preferred_username > email', () => {
        assert.equal(sso.mapUserinfoProfile({ sub: 's', name: 'N', preferred_username: 'p', email: 'e@x' }).displayName, 'N');
        assert.equal(sso.mapUserinfoProfile({ sub: 's', preferred_username: 'p', email: 'e@x' }).displayName, 'p');
        assert.equal(sso.mapUserinfoProfile({ sub: 's', email: 'e@x' }).displayName, 'e@x');
    });

    await t.test('tolerates empty input', () => {
        assert.deepEqual(sso.mapUserinfoProfile(), { id: undefined, username: undefined, displayName: undefined, email: undefined });
    });
});

test('buildOidcBellProvider', async t => {
    const doc = {
        issuer: 'https://idp.example.com',
        authorization_endpoint: 'https://idp.example.com/auth',
        token_endpoint: 'https://idp.example.com/token',
        userinfo_endpoint: 'https://idp.example.com/userinfo'
    };

    await t.test('maps endpoints and enables PKCE S256', () => {
        const provider = sso.buildOidcBellProvider(doc);
        assert.equal(provider.protocol, 'oauth2');
        assert.equal(provider.useParamsAuth, true);
        assert.equal(provider.pkce, 'S256');
        assert.equal(provider.auth, doc.authorization_endpoint);
        assert.equal(provider.token, doc.token_endpoint);
        assert.deepEqual(provider.scope, ['openid', 'profile', 'email']);
        assert.equal(typeof provider.profile, 'function');
    });

    await t.test('honors a scope override and still forces openid', () => {
        const provider = sso.buildOidcBellProvider(doc, { scopes: 'profile groups' });
        assert.deepEqual(provider.scope, ['openid', 'profile', 'groups']);
    });

    await t.test('profile() fetches userinfo and maps it onto credentials', async () => {
        const provider = sso.buildOidcBellProvider(doc);
        let requestedUrl = null;
        const get = async url => {
            requestedUrl = url;
            return { sub: 'abc', email: 'alice@example.com', name: 'Alice A' };
        };
        const credentials = {};
        await provider.profile(credentials, {}, get);
        assert.equal(requestedUrl, doc.userinfo_endpoint);
        assert.deepEqual(credentials.profile, {
            id: 'abc',
            username: 'alice@example.com',
            displayName: 'Alice A',
            email: 'alice@example.com'
        });
    });
});
