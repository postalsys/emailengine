'use strict';

// `useAuthServer` means an external service owns the account's credentials. On the `imap` and
// `smtp` blocks that has always worked, but on the `oauth2` block it was only honored by
// Account.getActiveAccessTokenData(), which serves the API transports (Gmail API, MS Graph) and the
// token endpoints. The IMAP and SMTP paths went through BaseClient.loadOAuth2LoginCredentials(),
// which never looked at the flag and renewed from a stored refresh token instead - a token an
// auth-server-backed account does not have. Setting the flag on an OAuth2 account that syncs over
// IMAP was therefore accepted, stored, and silently ignored.
//
// Because the flag used to be ignored, long-lived instances carry it on accounts that were never
// auth-server backed and sync fine on their stored tokens. Honoring such a stale flag on an
// instance with no auth server configured can only fail, so useAuthServerForOAuth2() ignores it
// and the stored tokens win - the fallback cases below pin that down.

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

// shouldUseAuthServer() reads the `authServer` setting to decide whether a stale flag can be
// honored at all. Configured by default so the tests above the fallback cases keep their meaning.
const settingsPath = require.resolve('../lib/settings');
const realSettings = require(settingsPath);
const realSettingsGet = realSettings.get.bind(realSettings);
let configuredAuthServer = 'https://auth.example.com/creds';
realSettings.get = async key => (key === 'authServer' ? configuredAuthServer : realSettingsGet(key));

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

// What the credential paths report a failure on: a logger, a notify() and a state field. The
// subconnection shape in production is the same three.
function makeCtx() {
    const notifications = [];
    return {
        notifications,
        ctx: {
            logger: noopLogger,
            state: null,
            async notify(mailbox, event, data) {
                notifications.push({ event, data });
            }
        }
    };
}

// A transient failure has to leave no trace: no flag for the caller to park on, no webhook, and the
// account state untouched.
async function assertLeftForRetry(fixture, run) {
    await assert.rejects(run, err => {
        assert.strictEqual(err.authenticationFailed, undefined, 'must not be marked as an authentication failure');
        return true;
    });

    assert.strictEqual(fixture.notifications.length, 0, 'a transient failure must not send an authenticationError webhook');
    assert.strictEqual(fixture.ctx.state, null, 'the account state must be left alone');
}

function makeFixture(oauth2Overrides) {
    const renewCalls = [];
    const { ctx, notifications } = makeCtx();

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
        configuredAuthServer = 'https://auth.example.com/creds';
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

    await t.test('a stored access token is ignored while the flag is set and an auth server is configured', async () => {
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

    await t.test('a stale flag with no auth server configured falls back to the stored access token', async () => {
        configuredAuthServer = null;
        const fixture = makeFixture({
            useAuthServer: true,
            accessToken: 'STORED-TOKEN',
            expires: new Date(Date.now() + 3600 * 1000)
        });

        const credentials = await load(fixture, 'imap');

        assert.strictEqual(authServerCalls.length, 0, 'there is no auth server to consult');
        assert.strictEqual(fixture.renewCalls.length, 0, 'the stored token is still valid');
        assert.strictEqual(credentials.accessToken, 'STORED-TOKEN');
        assert.strictEqual(credentials.oauth2User, 'stored-user@example.com');
    });

    await t.test('a stale flag with no auth server configured renews from the stored refresh token', async () => {
        configuredAuthServer = null;
        const fixture = makeFixture({
            useAuthServer: true,
            refreshToken: 'STORED-REFRESH-TOKEN'
        });

        const credentials = await load(fixture, 'imap');

        assert.strictEqual(authServerCalls.length, 0);
        assert.strictEqual(fixture.renewCalls.length, 1, 'EmailEngine renews the token itself');
        assert.strictEqual(credentials.accessToken, 'TOKEN-RENEWED-BY-EMAILENGINE');
    });

    await t.test('no auth server and no stored tokens still surfaces the configuration error', async () => {
        // With nothing to fall back to, the flag must stay in force so the operator sees the
        // missing auth server instead of a silent no-op.
        configuredAuthServer = null;
        const fixture = makeFixture({ useAuthServer: true });
        authServerError = new Error('Authentication server requested but not set');

        await assert.rejects(
            () => load(fixture, 'imap'),
            err => {
                assert.strictEqual(err.authenticationFailed, true);
                return true;
            }
        );

        assert.strictEqual(authServerCalls.length, 1, 'the auth server path is still taken');
        assert.strictEqual(fixture.notifications.length, 1);
        assert.strictEqual(fixture.notifications[0].event, 'authenticationError');
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
        authServerError = Object.assign(new Error('Invalid response: 403 Forbidden'), { code: 'HTTPRequestError', authRequest: { status: 403 } });

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

        await assertLeftForRetry(fixture, () => load(fixture, 'imap'));
    });

    await t.test('an auth server answering 5xx is a connection error too', async () => {
        // It answered, so it is reachable - but it has not refused the credential either, and the
        // whole instance shares one auth server. resolveCredentials() puts the status on the error
        // for exactly this test.
        const fixture = makeFixture({ useAuthServer: true });
        authServerError = Object.assign(new Error('Invalid response: 503 Service Unavailable'), { code: 'HTTPRequestError', authRequest: { status: 503 } });

        await assertLeftForRetry(fixture, () => load(fixture, 'imap'));
    });

    await t.test('a throttled token endpoint is a connection error, not an authentication failure', async () => {
        // The renewal path, not the auth server one: Microsoft and Google both throttle and 5xx
        // their token endpoints, and reporting that as a refused refresh token webhooked
        // authenticationError and parked the account until the next attempt contradicted it.
        const fixture = makeFixture({});
        configuredAuthServer = null;
        fixture.accountObject.renewAccessToken = async () => {
            throw Object.assign(new Error('Token request failed'), { code: 'ETokenRefresh', statusCode: 429 });
        };

        await assertLeftForRetry(fixture, () => load(fixture, 'imap'));
    });

    await t.test('a rejected refresh token is still an authentication failure', async () => {
        // 400 invalid_grant is the expired or revoked refresh token this event exists to report.
        const fixture = makeFixture({});
        configuredAuthServer = null;
        fixture.accountObject.renewAccessToken = async () => {
            throw Object.assign(new Error('Token request failed'), { code: 'ETokenRefresh', statusCode: 400 });
        };

        await assert.rejects(
            () => load(fixture, 'imap'),
            err => {
                assert.strictEqual(err.authenticationFailed, true);
                return true;
            }
        );

        assert.strictEqual(fixture.notifications.length, 1);
        assert.strictEqual(fixture.notifications[0].event, 'authenticationError');
        assert.strictEqual(fixture.notifications[0].data.serverResponseCode, 'OauthRenewError');
        assert.strictEqual(fixture.ctx.state, 'authenticationError');
    });
});

// The IMAP client has its own copy of the auth-server branch, for password accounts. It had no
// transient guard at all, so an auth-server blip webhooked authenticationError for every account.
test('IMAPClient.getImapConfig resolves credentials from the auth server', async t => {
    const { IMAPClient } = require('../lib/email-client/imap-client');

    function makeImapFixture() {
        const { ctx, notifications } = makeCtx();

        const accountData = {
            account: 'auth-server-account',
            imap: { host: 'imap.example.com', port: 993, secure: true, useAuthServer: true }
        };

        const client = Object.assign(Object.create(IMAPClient.prototype), {
            account: 'auth-server-account',
            logger: noopLogger
        });

        return { client, ctx, accountData, notifications };
    }

    const buildConfig = fixture => IMAPClient.prototype.getImapConfig.call(fixture.client, fixture.accountData, fixture.ctx);

    t.beforeEach(() => {
        authServerCalls.length = 0;
        authServerError = null;
        configuredAuthServer = 'https://auth.example.com/creds';
    });

    await t.test('an unreachable auth server is not an authentication failure', async () => {
        const fixture = makeImapFixture();
        authServerError = Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' });

        await assertLeftForRetry(fixture, () => buildConfig(fixture));

        assert.deepStrictEqual(authServerCalls, [{ account: 'auth-server-account', proto: 'imap' }]);
    });

    await t.test('an auth server answering 5xx is not an authentication failure', async () => {
        const fixture = makeImapFixture();
        authServerError = Object.assign(new Error('Invalid response: 502 Bad Gateway'), { code: 'HTTPRequestError', authRequest: { status: 502 } });

        await assertLeftForRetry(fixture, () => buildConfig(fixture));
    });

    await t.test('a refused account is still an authentication failure', async () => {
        const fixture = makeImapFixture();
        authServerError = Object.assign(new Error('Invalid response: 403 Forbidden'), { code: 'HTTPRequestError', authRequest: { status: 403 } });

        await assert.rejects(
            () => buildConfig(fixture),
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
});

// The API surface. resolveCredentials() carries the authentication server's HTTP status for
// classification, and getActiveAccessTokenData() used to let it through untouched: a 401 from the
// operator's own auth server reached an SDK holding a valid EmailEngine token as "your token is
// bad", and a 404 as "no such account".
test('Account.getActiveAccessTokenData translates auth server failures', async t => {
    const { Account } = require('../lib/account');

    function makeAccount() {
        return {
            account: 'auth-server-account',
            logger: noopLogger,
            async loadAccountData() {
                return {
                    account: 'auth-server-account',
                    oauth2: {
                        provider: 'app-1',
                        useAuthServer: true,
                        auth: { user: 'stored-user@example.com' }
                    }
                };
            }
        };
    }

    const getToken = () => Account.prototype.getActiveAccessTokenData.call(makeAccount());

    t.beforeEach(() => {
        authServerCalls.length = 0;
        authServerError = null;
        configuredAuthServer = 'https://auth.example.com/creds';
    });

    await t.test('a refused account is a 403, not the auth server 401', async () => {
        authServerError = Object.assign(new Error('Invalid response: 401 Unauthorized'), { code: 'HTTPRequestError', authRequest: { status: 401 } });

        await assert.rejects(getToken, err => {
            assert.strictEqual(err.output.statusCode, 403);
            assert.strictEqual(err.output.payload.code, 'AuthServerError');
            assert.strictEqual(err.output.payload.authenticationFailed, true);
            return true;
        });
    });

    await t.test('an auth server 404 does not become a missing account', async () => {
        authServerError = Object.assign(new Error('Invalid response: 404 Not Found'), { code: 'HTTPRequestError', authRequest: { status: 404 } });

        await assert.rejects(getToken, err => {
            assert.strictEqual(err.output.statusCode, 403);
            assert.strictEqual(err.output.payload.code, 'AuthServerError');
            return true;
        });
    });

    await t.test('a transient failure is a 503 the client can retry', async () => {
        authServerError = Object.assign(new Error('Invalid response: 503 Service Unavailable'), { code: 'HTTPRequestError', authRequest: { status: 503 } });

        await assert.rejects(getToken, err => {
            assert.strictEqual(err.output.statusCode, 503);
            assert.strictEqual(err.output.payload.code, 'AuthServerUnavailable');
            assert.strictEqual(err.output.payload.authenticationFailed, undefined, 'a bad minute is not a refused credential');
            return true;
        });
    });

    await t.test('a throttled auth server is transient as well', async () => {
        authServerError = Object.assign(new Error('Invalid response: 429 Too Many Requests'), { code: 'HTTPRequestError', authRequest: { status: 429 } });

        await assert.rejects(getToken, err => {
            assert.strictEqual(err.output.statusCode, 503);
            return true;
        });
    });

    await t.test('resolved credentials are returned unchanged', async () => {
        const tokenData = await getToken();

        assert.deepStrictEqual(authServerCalls, [{ account: 'auth-server-account', proto: 'api' }]);
        assert.strictEqual(tokenData.accessToken, 'ACCESS-TOKEN-FROM-AUTH-SERVER');
        assert.strictEqual(tokenData.user, 'from-auth-server@example.com');
        assert.strictEqual(tokenData.cached, false);
    });
});
