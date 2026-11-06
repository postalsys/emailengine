'use strict';

// Exchange Online ends an IMAP session when the access token it logged in with expires: the next
// command (the DONE of an API request breaking IDLE) is answered with `* BYE Session invalidated -
// AccessTokenExpired`, and the request failed with a 500. Reported by a customer on 2.87.0 as a 500
// every one to three hours per Microsoft 365 account.
//
// ImapFlow closes such a connection before the expiry while nothing runs on it (its own tests pin
// that). What is pinned here is EmailEngine's half:
// - which sessions get ImapFlow's sessionExpires option, and with what lead (session-expiry.js)
// - getImapConfig() hands it to the connections it configures
// - a login on such a provider renews a token with less than LOGIN_MIN_VALIDITY left, and reports
//   the expiry of the token it used
// - a connection that went away under a command answers 503, not 500

const test = require('node:test');
const assert = require('node:assert').strict;

require('./helpers/mock-db').installDbMock();

const settings = require('../lib/settings');
const { oauth2Apps } = require('../lib/oauth2-apps');
const { IMAPClient } = require('../lib/email-client/imap-client');
const { BaseClient } = require('../lib/email-client/base-client');
const { OAUTH_TOKEN_MIN_VALIDITY, STABLE_CONNECTION_TIME } = require('../lib/consts');
const { assignRelayStatus } = require('../lib/email-client/imap/connection-errors');
const {
    LOGIN_MIN_VALIDITY,
    REAUTH_LEAD,
    REAUTH_JITTER,
    REAUTH_MIN_DELAY,
    minTokenValidity,
    sessionExpiryOptions
} = require('../lib/email-client/imap/session-expiry');
const { noopLogger } = require('./helpers/auth-failure');

require('./helpers/redis-teardown')();

const MINUTE = 60 * 1000;
const NOW = Date.parse('2026-11-06T10:00:00.000Z');

test('session-expiry rules', async t => {
    await t.test('only an IMAP login on a Microsoft account asks for more token lifetime', () => {
        assert.equal(minTokenValidity('outlook', 'imap'), LOGIN_MIN_VALIDITY);
        assert.equal(minTokenValidity('outlook', 'smtp'), OAUTH_TOKEN_MIN_VALIDITY);
        assert.equal(minTokenValidity('outlook', 'api'), OAUTH_TOKEN_MIN_VALIDITY);
        assert.equal(minTokenValidity('gmail', 'imap'), OAUTH_TOKEN_MIN_VALIDITY);
        assert.equal(minTokenValidity(undefined, 'imap'), OAUTH_TOKEN_MIN_VALIDITY);
    });

    await t.test('a Microsoft session gets the expiry of its token and a jittered lead', () => {
        const expires = new Date(NOW + 60 * MINUTE);
        assert.deepEqual(
            sessionExpiryOptions('outlook', expires, NOW, () => 0),
            { sessionExpires: expires.getTime(), sessionExpiryLead: REAUTH_LEAD }
        );
        assert.deepEqual(
            sessionExpiryOptions('outlook', expires.toISOString(), NOW, () => 1),
            {
                sessionExpires: expires.getTime(),
                sessionExpiryLead: REAUTH_LEAD + REAUTH_JITTER
            }
        );
    });

    await t.test('no other session gets one', () => {
        const expires = new Date(NOW + 60 * MINUTE);
        assert.equal(sessionExpiryOptions('gmail', expires, NOW), null);
        assert.equal(sessionExpiryOptions('outlook', null, NOW), null);
        assert.equal(sessionExpiryOptions('outlook', 'not a date', NOW), null);
    });

    await t.test('a short-lived token is not chased with a reconnect loop', () => {
        // with the longest lead, the session has to live REAUTH_MIN_DELAY before it is replaced
        const shortest = NOW + REAUTH_LEAD + REAUTH_JITTER + REAUTH_MIN_DELAY;
        assert.ok(sessionExpiryOptions('outlook', shortest, NOW, () => 1));
        assert.equal(
            sessionExpiryOptions('outlook', shortest - 1, NOW, () => 1),
            null
        );
    });

    await t.test('every login with a freshly checked token gets a deadline', () => {
        // the renewal compares before the connection is configured, a little time passes in between
        assert.ok(LOGIN_MIN_VALIDITY - REAUTH_LEAD - REAUTH_JITTER - REAUTH_MIN_DELAY >= MINUTE);
        assert.ok(sessionExpiryOptions('outlook', NOW + LOGIN_MIN_VALIDITY, NOW + 30 * 1000, () => 1));
    });

    await t.test('a replaced primary connection is old enough to reconnect at once', () => {
        // younger closes are throttled by the close handler as a connection that died young
        assert.ok(REAUTH_MIN_DELAY > STABLE_CONNECTION_TIME);
    });
});

test('a command failure gets the status the API answers with', async t => {
    await t.test('a connection that went away is a 503', () => {
        for (const code of ['NoConnection', 'EConnectionClosed', 'IMAPConnectionClosing']) {
            const err = Object.assign(new Error('Connection not available'), { code });
            assignRelayStatus(err);
            assert.equal(err.statusCode, 503, code);
        }
    });

    await t.test('throttling is a 429', () => {
        const err = Object.assign(new Error('Throttled'), { code: 'ETHROTTLE' });
        assignRelayStatus(err);
        assert.equal(err.statusCode, 429);
    });

    await t.test('an existing status and any other code are left alone', () => {
        const withStatus = Object.assign(new Error('x'), { code: 'NoConnection', statusCode: 404 });
        assignRelayStatus(withStatus);
        assert.equal(withStatus.statusCode, 404);

        const other = Object.assign(new Error('x'), { code: 'Whatever' });
        assignRelayStatus(other);
        assert.equal(other.statusCode, undefined);

        assert.equal(assignRelayStatus(undefined), undefined);
        assert.equal(assignRelayStatus('text'), 'text');
    });
});

test('an IMAP login renews a token whose session would end too soon', async t => {
    const origGet = oauth2Apps.get;
    t.after(() => {
        oauth2Apps.get = origGet;
    });
    let provider = 'outlook';
    oauth2Apps.get = async () => ({ id: 'app-1', provider, baseScopes: 'imap' });

    function fixture(lifetime) {
        const renewCalls = [];
        const accountData = {
            account: 'acc',
            oauth2: {
                provider: 'app-1',
                auth: { user: 'user@example.com' },
                accessToken: 'STORED',
                refreshToken: 'RT',
                expires: new Date(Date.now() + lifetime)
            }
        };
        const renewedExpires = new Date(Date.now() + 75 * MINUTE);
        const accountObject = {
            account: 'acc',
            async renewAccessToken(oauth2Opts, opts) {
                renewCalls.push(opts);
                return { oauth2: Object.assign({}, accountData.oauth2, { accessToken: 'RENEWED', expires: renewedExpires }) };
            }
        };
        const client = { logger: noopLogger, options: {}, account: 'acc' };
        const ctx = { logger: noopLogger, notify: async () => {} };
        const load = target => BaseClient.prototype.loadOAuth2LoginCredentials.call(client, accountObject, accountData, ctx, target);
        return { load, renewCalls, accountData, renewedExpires };
    }

    t.beforeEach(() => {
        provider = 'outlook';
    });

    await t.test('Microsoft: a token with ten minutes left is renewed before the login', async () => {
        const { load, renewCalls, renewedExpires } = fixture(10 * MINUTE);
        const credentials = await load('imap');
        assert.deepEqual(renewCalls, [{ minValidity: LOGIN_MIN_VALIDITY }]);
        assert.equal(credentials.accessToken, 'RENEWED');
        assert.equal(credentials.expires, renewedExpires, 'the expiry of the token the session logs in with');
    });

    await t.test('Microsoft: a token with an hour left is used as is', async () => {
        const { load, renewCalls, accountData } = fixture(60 * MINUTE);
        const credentials = await load('imap');
        assert.equal(renewCalls.length, 0);
        assert.equal(credentials.accessToken, 'STORED');
        assert.equal(credentials.expires, accountData.oauth2.expires);
    });

    await t.test('Microsoft SMTP keeps the usual margin', async () => {
        const { load, renewCalls } = fixture(10 * MINUTE);
        await load('smtp');
        assert.equal(renewCalls.length, 0);
    });

    await t.test('Gmail keeps the usual margin', async () => {
        provider = 'gmail';
        const { load, renewCalls } = fixture(10 * MINUTE);
        const credentials = await load('imap');
        assert.equal(renewCalls.length, 0);
        assert.equal(credentials.accessToken, 'STORED');
    });
});

test('the installed ImapFlow acts on sessionExpires', () => {
    // An older ImapFlow ignores the option silently, so the sessions would end with the server's BYE
    // again. 2.11.0 is the first release with it
    const { ImapFlow } = require('imapflow');
    const [major, minor] = require('imapflow/package.json').version.split('.').map(Number);
    assert.ok(major > 2 || (major === 2 && minor >= 11), 'imapflow 2.11.0 or newer');
    assert.equal(typeof ImapFlow.prototype.armSessionExpiry, 'function');
});

test('getImapConfig() hands the session deadline to the connections it configures', async t => {
    // the settings the configuration reads, none of which matters here
    const origSettingsGet = settings.get;
    t.after(() => {
        settings.get = origSettingsGet;
    });
    settings.get = async () => undefined;

    function makeClient(provider, expires) {
        const client = new IMAPClient('test-account', {
            logger: noopLogger,
            accountLogger: { enabled: false, log() {}, reload: async () => {} },
            redis: {}
        });
        client.getLearnedIdleInterval = async () => null;
        client.loadOAuth2AccountCredentials = async () => ({ oauth2User: 'u@example.com', accessToken: 'AT', oauth2App: { provider }, expires });
        return client;
    }
    const accountData = { account: 'test-account', oauth2: { auth: { user: 'u@example.com' } } };

    await t.test('a Microsoft session', async () => {
        const expires = new Date(Date.now() + 60 * MINUTE);
        const config = await makeClient('outlook', expires).getImapConfig(accountData);
        assert.equal(config.sessionExpires, expires.getTime());
        assert.ok(config.sessionExpiryLead >= REAUTH_LEAD && config.sessionExpiryLead <= REAUTH_LEAD + REAUTH_JITTER);
        assert.equal(config.auth.accessToken, 'AT');
    });

    await t.test('a Gmail session', async () => {
        const config = await makeClient('gmail', new Date(Date.now() + 60 * MINUTE)).getImapConfig(accountData);
        assert.equal(config.sessionExpires, undefined);
        assert.equal(config.sessionExpiryLead, undefined);
    });
});
