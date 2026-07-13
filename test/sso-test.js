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

test('parseGroupList', async t => {
    await t.test('empty inputs yield empty list', () => {
        assert.deepEqual(sso.parseGroupList(''), []);
        assert.deepEqual(sso.parseGroupList(null), []);
        assert.deepEqual(sso.parseGroupList(undefined), []);
    });

    await t.test('trims, strips leading slashes, drops empties (case preserved)', () => {
        assert.deepEqual(sso.parseGroupList(' /emailengine-admins , Ops ,, //Nested '), ['emailengine-admins', 'Ops', 'Nested']);
    });
});

test('extractGroups', async t => {
    await t.test('reads a top-level groups array and normalizes', () => {
        assert.deepEqual(sso.extractGroups({ groups: ['/emailengine-admins', 'Ops'] }, 'groups'), ['emailengine-admins', 'Ops']);
    });

    await t.test('defaults to the "groups" claim', () => {
        assert.deepEqual(sso.extractGroups({ groups: ['a'] }), ['a']);
    });

    await t.test('accepts a single string value', () => {
        assert.deepEqual(sso.extractGroups({ groups: '/solo' }, 'groups'), ['solo']);
    });

    await t.test('supports a dotted claim path', () => {
        assert.deepEqual(sso.extractGroups({ realm_access: { roles: ['admin', 'user'] } }, 'realm_access.roles'), ['admin', 'user']);
    });

    await t.test('missing claim yields empty array', () => {
        assert.deepEqual(sso.extractGroups({}, 'groups'), []);
        assert.deepEqual(sso.extractGroups({ realm_access: {} }, 'realm_access.roles'), []);
        assert.deepEqual(sso.extractGroups(null, 'groups'), []);
    });

    await t.test('ignores non-string entries', () => {
        assert.deepEqual(sso.extractGroups({ groups: ['ok', 42, null, { x: 1 }] }, 'groups'), ['ok']);
    });
});

test('isAuthorized', async t => {
    const emails = sso.parseAllowList('alice@example.com, @corp.example.com');
    const groups = sso.parseGroupList('emailengine-admins');

    await t.test('no constraints allows everyone', () => {
        assert.equal(sso.isAuthorized({ email: 'anyone@example.com' }, [], []), true);
        assert.equal(sso.isAuthorized({}, null, null), true);
    });

    await t.test('email allow-list: exact and domain match (case-insensitive)', () => {
        assert.equal(sso.isAuthorized({ email: 'Alice@Example.com' }, emails, []), true);
        assert.equal(sso.isAuthorized({ email: 'someone@corp.example.com' }, emails, []), true);
        assert.equal(sso.isAuthorized({ email: 'bob@other.com' }, emails, []), false);
    });

    await t.test('falls back to username when email is absent', () => {
        assert.equal(sso.isAuthorized({ username: 'someone@corp.example.com' }, emails, []), true);
    });

    await t.test('group allow-list matches on membership (slash-insensitive)', () => {
        assert.equal(sso.isAuthorized({ email: 'x@nope.com', groups: ['/emailengine-admins'] }, [], groups), true);
        assert.equal(sso.isAuthorized({ email: 'x@nope.com', groups: ['other'] }, [], groups), false);
        assert.equal(sso.isAuthorized({ email: 'x@nope.com' }, [], groups), false);
    });

    await t.test('email OR group: matching either grants access', () => {
        // email fails, group passes
        assert.equal(sso.isAuthorized({ email: 'bob@other.com', groups: ['emailengine-admins'] }, emails, groups), true);
        // group fails, email passes
        assert.equal(sso.isAuthorized({ email: 'alice@example.com', groups: ['nope'] }, emails, groups), true);
        // neither matches
        assert.equal(sso.isAuthorized({ email: 'bob@other.com', groups: ['nope'] }, emails, groups), false);
    });

    await t.test('non-empty constraints with no usable identity denies', () => {
        assert.equal(sso.isAuthorized({}, emails, groups), false);
        assert.equal(sso.isAuthorized(null, emails, groups), false);
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
    await t.test('maps standard claims and groups', () => {
        assert.deepEqual(sso.mapUserinfoProfile({ sub: 'abc', email: 'alice@example.com', name: 'Alice A', groups: ['/ops'] }, 'groups'), {
            id: 'abc',
            username: 'alice@example.com',
            displayName: 'Alice A',
            email: 'alice@example.com',
            groups: ['ops']
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
        assert.deepEqual(sso.mapUserinfoProfile(), { id: undefined, username: undefined, displayName: undefined, email: undefined, groups: [] });
    });
});

test('buildLogoutUrl', async t => {
    const endpoint = 'https://idp.example.com/realms/main/protocol/openid-connect/logout';

    await t.test('returns null without an endpoint', () => {
        assert.equal(sso.buildLogoutUrl(null, { idToken: 'x' }), null);
        assert.equal(sso.buildLogoutUrl('', {}), null);
    });

    await t.test('includes id_token_hint, client_id and post_logout_redirect_uri', () => {
        const url = new URL(
            sso.buildLogoutUrl(endpoint, {
                idToken: 'tok123',
                clientId: 'emailengine',
                postLogoutRedirectUri: 'https://app.example.com/admin/login?loggedout=1'
            })
        );
        assert.equal(url.origin + url.pathname, endpoint);
        assert.equal(url.searchParams.get('id_token_hint'), 'tok123');
        assert.equal(url.searchParams.get('client_id'), 'emailengine');
        assert.equal(url.searchParams.get('post_logout_redirect_uri'), 'https://app.example.com/admin/login?loggedout=1');
    });

    await t.test('omits id_token_hint when no id token is available', () => {
        const url = new URL(sso.buildLogoutUrl(endpoint, { clientId: 'emailengine' }));
        assert.equal(url.searchParams.has('id_token_hint'), false);
        assert.equal(url.searchParams.get('client_id'), 'emailengine');
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

    await t.test('profile() fetches userinfo and maps it (incl. groups) onto credentials', async () => {
        const provider = sso.buildOidcBellProvider(doc);
        let requestedUrl = null;
        const get = async url => {
            requestedUrl = url;
            return { sub: 'abc', email: 'alice@example.com', name: 'Alice A', groups: ['/emailengine-admins'] };
        };
        const credentials = {};
        await provider.profile(credentials, {}, get);
        assert.equal(requestedUrl, doc.userinfo_endpoint);
        assert.deepEqual(credentials.profile, {
            id: 'abc',
            username: 'alice@example.com',
            displayName: 'Alice A',
            email: 'alice@example.com',
            groups: ['emailengine-admins']
        });
    });

    await t.test('profile() honors a custom groupsClaim (dotted path)', async () => {
        const provider = sso.buildOidcBellProvider(doc, { groupsClaim: 'realm_access.roles' });
        const get = async () => ({ sub: 'abc', realm_access: { roles: ['admin'] } });
        const credentials = {};
        await provider.profile(credentials, {}, get);
        assert.deepEqual(credentials.profile.groups, ['admin']);
    });
});
