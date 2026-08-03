'use strict';

// `useAuthServer` means an external service owns the account's credentials. On the `imap` and
// `smtp` blocks that has always worked, but on the `oauth2` block it was only honored by
// Account.getActiveAccessTokenData(), which serves the API transports (Gmail API, MS Graph) and the
// token endpoints. The IMAP and SMTP paths went through BaseClient.loadOAuth2LoginCredentials(),
// which never looked at the flag and renewed from a stored refresh token instead - a token an
// auth-server-backed account does not have. Setting the flag on an OAuth2 account that syncs over
// IMAP was therefore accepted, stored, and silently ignored.

const test = require('node:test');
const assert = require('node:assert').strict;

const registerRedisTeardown = require('./helpers/redis-teardown');

// The resolveCredentials stub has to land before base-client is required, because base-client
// destructures it at load time and would not see a later mutation. Neither stub is restored - the
// process exits at the end of the file - so anything added here gets the stubbed versions.
const toolsPath = require.resolve('../lib/tools');
const realTools = require(toolsPath);

const authServerCalls = [];
let authServerResponse = { user: 'from-auth-server@example.com', accessToken: 'ACCESS-TOKEN-FROM-AUTH-SERVER' };
let authServerError = null;

realTools.resolveCredentials = async (account, proto) => {
    authServerCalls.push({ account, proto });
    if (authServerError) {
        throw authServerError;
    }
    return authServerResponse;
};

const appsPath = require.resolve('../lib/oauth2-apps');
const realApps = require(appsPath);
realApps.oauth2Apps.get = async () => ({ id: 'app-1', provider: 'gmail', baseScopes: 'imap' });

const { BaseClient } = require('../lib/email-client/base-client');

// base-client pulls in lib/db (Redis + queues), whose handles keep the process alive.
registerRedisTeardown();

const noopLogger = {
    trace() {},
    debug() {},
    info() {},
    warn() {},
    error() {},
    fatal() {},
    child() {
        return noopLogger;
    }
};

function makeFixture(oauth2Overrides) {
    const renewCalls = [];
    const notifications = [];

    const accountData = {
        account: 'auth-server-account',
        oauth2: Object.assign(
            {
                provider: 'app-1',
                auth: { user: 'stored-user@example.com' }
            },
            oauth2Overrides
        )
    };

    const accountObject = {
        account: 'auth-server-account',
        async renewAccessToken() {
            renewCalls.push(true);
            accountData.oauth2.accessToken = 'TOKEN-RENEWED-BY-EMAILENGINE';
            return accountData;
        }
    };

    const ctx = {
        logger: noopLogger,
        state: null,
        async notify(mailbox, event, data) {
            notifications.push({ event, data });
        }
    };

    const client = { logger: noopLogger, options: {}, account: 'auth-server-account' };

    return { accountData, accountObject, ctx, client, renewCalls, notifications };
}

const load = (fixture, target) =>
    BaseClient.prototype.loadOAuth2LoginCredentials.call(fixture.client, fixture.accountObject, fixture.accountData, fixture.ctx, target);

test('OAuth2 accounts honor useAuthServer on the IMAP and SMTP paths', async t => {
    t.beforeEach(() => {
        authServerCalls.length = 0;
        authServerError = null;
        authServerResponse = { user: 'from-auth-server@example.com', accessToken: 'ACCESS-TOKEN-FROM-AUTH-SERVER' };
    });

    await t.test('IMAP: fetches the token from the auth server instead of renewing', async () => {
        const fixture = makeFixture({ useAuthServer: true });

        const credentials = await load(fixture, 'imap');

        assert.deepStrictEqual(authServerCalls, [{ account: 'auth-server-account', proto: 'imap' }]);
        assert.strictEqual(fixture.renewCalls.length, 0, 'EmailEngine must not renew the token itself');
        assert.strictEqual(credentials.accessToken, 'ACCESS-TOKEN-FROM-AUTH-SERVER');
        assert.strictEqual(credentials.oauth2User, 'from-auth-server@example.com', 'the auth server owns the username too');
        assert.strictEqual(credentials.oauth2App.id, 'app-1', 'the app is still resolved, for the provider host and port');
    });

    await t.test('SMTP: asks the auth server for the smtp protocol', async () => {
        const fixture = makeFixture({ useAuthServer: true });

        await load(fixture, 'smtp');

        assert.deepStrictEqual(authServerCalls, [{ account: 'auth-server-account', proto: 'smtp' }]);
        assert.strictEqual(fixture.renewCalls.length, 0);
    });

    await t.test('a stored access token is ignored while the flag is set', async () => {
        // A token left over from before the flag was set must not be preferred over the auth server.
        const fixture = makeFixture({
            useAuthServer: true,
            accessToken: 'STALE-STORED-TOKEN',
            expires: new Date(Date.now() + 3600 * 1000)
        });

        const credentials = await load(fixture, 'imap');

        assert.strictEqual(credentials.accessToken, 'ACCESS-TOKEN-FROM-AUTH-SERVER');
        assert.strictEqual(authServerCalls.length, 1);
    });

    await t.test('without the flag, EmailEngine still manages the token itself', async () => {
        const fixture = makeFixture({});

        const credentials = await load(fixture, 'imap');

        assert.strictEqual(authServerCalls.length, 0, 'the auth server must not be consulted');
        assert.strictEqual(fixture.renewCalls.length, 1);
        assert.strictEqual(credentials.accessToken, 'TOKEN-RENEWED-BY-EMAILENGINE');
        assert.strictEqual(credentials.oauth2User, 'stored-user@example.com');
    });

    await t.test('a shared mailbox asks the auth server for the delegated account, not the shared one', async () => {
        // Delegation authenticates with the delegating account's credentials and then presents the
        // shared mailbox as the IMAP user. The auth server must therefore be asked for the account
        // whose token is actually being used, or a tenant would receive another tenant's token.
        const delegated = makeFixture({ useAuthServer: true });
        delegated.accountData.account = 'delegated-account';
        delegated.accountObject.account = 'delegated-account';

        const shared = makeFixture({ auth: { user: 'shared-owner@example.com', delegatedUser: 'shared@example.com', delegatedAccount: 'delegated-account' } });

        const client = {
            logger: noopLogger,
            options: {},
            account: 'shared-account',
            delegatedAccountObject: delegated.accountObject,
            async getDelegatedAccount() {
                return delegated.accountData;
            },
            loadOAuth2LoginCredentials: BaseClient.prototype.loadOAuth2LoginCredentials
        };

        const credentials = await BaseClient.prototype.loadOAuth2AccountCredentials.call(client, shared.accountData, shared.ctx, 'imap');

        assert.deepStrictEqual(authServerCalls, [{ account: 'delegated-account', proto: 'imap' }], 'the delegating account owns the token');
        assert.strictEqual(credentials.accessToken, 'ACCESS-TOKEN-FROM-AUTH-SERVER');
        assert.strictEqual(credentials.oauth2User, 'shared@example.com', 'the shared mailbox is still the IMAP user');
    });

    await t.test('a shared mailbox on the same token keeps the configured delegatedUser', async () => {
        // delegatedUser without delegatedAccount means the shared mailbox is opened with this
        // account's own token. The auth server supplies the token, but the account record still
        // decides which mailbox is opened - otherwise the account would sync the wrong mail.
        const fixture = makeFixture({
            useAuthServer: true,
            auth: { user: 'owner@example.com', delegatedUser: 'shared@example.com' }
        });

        const credentials = await load(fixture, 'imap');

        assert.strictEqual(credentials.accessToken, 'ACCESS-TOKEN-FROM-AUTH-SERVER');
        assert.strictEqual(credentials.oauth2User, 'shared@example.com');
    });

    await t.test('an auth server failure is reported as an authentication error', async () => {
        const fixture = makeFixture({ useAuthServer: true });
        authServerError = new Error('Invalid response: 500 Internal Server Error');

        await assert.rejects(
            () => load(fixture, 'imap'),
            err => {
                assert.strictEqual(err.authenticationFailed, true);
                return true;
            }
        );

        assert.strictEqual(fixture.notifications.length, 1);
        assert.strictEqual(fixture.notifications[0].event, 'authenticationError');
        assert.strictEqual(fixture.notifications[0].data.serverResponseCode, 'HTTPRequestError');
        assert.strictEqual(fixture.ctx.state, 'authenticationError');
    });

    await t.test('an unreachable auth server is a connection error, not an authentication failure', async () => {
        // Reporting a DNS or connect failure as an authentication error would webhook and park
        // every account on the instance over a brief auth-server outage.
        const fixture = makeFixture({ useAuthServer: true });
        authServerError = Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' });

        await assert.rejects(
            () => load(fixture, 'imap'),
            err => {
                assert.strictEqual(err.authenticationFailed, undefined, 'must not be marked as an authentication failure');
                return true;
            }
        );

        assert.strictEqual(fixture.notifications.length, 0, 'no authenticationError webhook for a transient failure');
        assert.strictEqual(fixture.ctx.state, null, 'the account state is left alone');
    });
});
