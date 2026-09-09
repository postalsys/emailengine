'use strict';

// The three account-level connection events - `authenticationError`, `connectError` and
// `authenticationSuccess` - all pass through BaseClient, and two decisions there had been wrong for
// as long as they existed.
//
// A credential service that answers 429 or a 5xx is unavailable, it has not refused the credential.
// Reporting it as an authentication failure webhooks `authenticationError`, parks the account and
// stops the API clients retrying init(), and the next attempt then contradicts it with
// `authenticationSuccess`. Microsoft and Google throttle their token endpoints often enough for
// that to be a steady stream of events on a busy instance - isTransientCredentialError() is the
// line between the two.
//
// And `lastErrorState` is written by BOTH error events, so the recovery path could not tell an
// authentication failure from a name-resolution blip and announced every recovery as
// `authenticationSuccess`. setErrorState() now records which event wrote it, and
// notifyAuthenticationSuccess() reads it back to decide both what to announce and what to clear.

const test = require('node:test');
const assert = require('node:assert').strict;

const { isTransientCredentialError, credentialErrorStatus } = require('../lib/email-client/credential-errors');
const { LAST_ERROR_EVENT_FIELD } = require('../lib/consts');
const { redis } = require('../lib/db');
const registerRedisTeardown = require('./helpers/redis-teardown');
const { createErrorStateClient, accountKeyFor, noopLogger } = require('./helpers/auth-failure');

const createdKeys = new Set();

// A BaseClient stand-in bound to its own account hash, collecting the webhooks it would send.
function makeClient(account) {
    const accountKey = accountKeyFor(account);
    createdKeys.add(accountKey);

    const client = createErrorStateClient({ redis, account, logger: noopLogger });
    client.notifications = [];
    client.notify = async (mailbox, event, data) => {
        client.notifications.push({ event, data });
    };
    return { client, accountKey };
}

// The hash has to exist at all for hSetExists to write into it.
const seedAccount = (accountKey, fields = {}) => redis.hset(accountKey, Object.assign({ account: accountKey }, fields));

registerRedisTeardown(redis, async () => {
    for (const key of createdKeys) {
        try {
            await redis.del(key);
        } catch (err) {
            // ignore
        }
    }
});

test('credentialErrorStatus', async t => {
    await t.test('reads the status the OAuth2 clients attach', () => {
        assert.equal(credentialErrorStatus(Object.assign(new Error('Token request failed'), { statusCode: 503 })), 503);
    });

    await t.test('falls back to the token request record', () => {
        // mail-ru builds the record but sets no statusCode of its own
        assert.equal(credentialErrorStatus(Object.assign(new Error('Token request failed'), { tokenRequest: { status: 429 } })), 429);
    });

    await t.test('falls back to the API request record', () => {
        // What the Graph and Gmail transports carry
        assert.equal(credentialErrorStatus(Object.assign(new Error('API request failed'), { oauthRequest: { status: 500 } })), 500);
    });

    await t.test('ignores a Boom wrapper', () => {
        // getActiveAccessTokenData() boomifies every renewal failure as 403. Reading that would
        // mask the status the token endpoint actually answered with.
        const err = Object.assign(new Error('Token request failed'), { statusCode: 503, output: { statusCode: 403 } });
        assert.equal(credentialErrorStatus(err), 503);
    });

    await t.test('reports zero when the request never reached a response', () => {
        assert.equal(credentialErrorStatus(Object.assign(new Error('fetch failed'), { code: 'ECONNREFUSED' })), 0);
        assert.equal(credentialErrorStatus(null), 0);
    });
});

test('isTransientCredentialError', async t => {
    const withStatus = status => Object.assign(new Error('Token request failed'), { code: 'ETokenRefresh', statusCode: status });

    await t.test('a socket-level failure is transient', () => {
        assert.equal(isTransientCredentialError(Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' })), true);
        assert.equal(isTransientCredentialError(Object.assign(new TypeError('fetch failed'), { cause: { code: 'EAI_AGAIN' } })), true);
    });

    await t.test('a throttled or failing endpoint is transient', () => {
        for (const status of [408, 429, 500, 502, 503, 504]) {
            assert.equal(isTransientCredentialError(withStatus(status)), true, `${status} must be transient`);
        }
    });

    await t.test('a refused credential is not transient', () => {
        // 400 invalid_grant is an expired or revoked refresh token, 401/403 a rejected one. These
        // are the failures that genuinely need a human to re-authorize the account.
        for (const status of [400, 401, 403, 404]) {
            assert.equal(isTransientCredentialError(withStatus(status)), false, `${status} must stay an authentication failure`);
        }
    });

    await t.test('a failure carrying no status at all is not transient', () => {
        // Nothing is known about it, so it keeps the reporting it has always had
        assert.equal(isTransientCredentialError(new Error('Failed to renew token')), false);
        assert.equal(isTransientCredentialError(null), false);
    });
});

test('BaseClient.setErrorState records which event wrote the error state', async t => {
    await t.test('an authentication error', async () => {
        const { client, accountKey } = makeClient('errevent-auth');
        await seedAccount(accountKey);

        await client.setErrorState('authenticationError', { serverResponseCode: 'AUTHENTICATIONFAILED' });

        assert.equal(await redis.hget(accountKey, LAST_ERROR_EVENT_FIELD), 'authenticationError');
    });

    await t.test('a connection error', async () => {
        const { client, accountKey } = makeClient('errevent-connect');
        await seedAccount(accountKey);

        await client.setErrorState('connectError', { serverResponseCode: 'ETIMEDOUT' });

        assert.equal(await redis.hget(accountKey, LAST_ERROR_EVENT_FIELD), 'connectError');
    });

    await t.test('the marker follows the latest event', async () => {
        const { client, accountKey } = makeClient('errevent-latest');
        await seedAccount(accountKey);

        await client.setErrorState('connectError', { serverResponseCode: 'ETIMEDOUT' });
        await client.setErrorState('authenticationError', { serverResponseCode: 'AUTHENTICATIONFAILED' });

        assert.equal(await redis.hget(accountKey, LAST_ERROR_EVENT_FIELD), 'authenticationError');
    });

    await t.test('the webhook payload is left alone', async () => {
        // `data` is what the webhook carries and what GET /v1/account/{id} reports as `lastError`.
        // The marker is a separate field precisely so it cannot ride along into either.
        const { client, accountKey } = makeClient('errevent-payload');
        await seedAccount(accountKey);
        const data = { response: 'Invalid credentials', serverResponseCode: 'AUTHENTICATIONFAILED' };

        await client.setErrorState('authenticationError', data);

        assert.deepEqual(data, { response: 'Invalid credentials', serverResponseCode: 'AUTHENTICATIONFAILED' });
        assert.deepEqual(JSON.parse(await redis.hget(accountKey, 'lastErrorState')), data);
    });
});

test('BaseClient.notifyAuthenticationSuccess', async t => {
    await t.test('announces the first login of a new account', async () => {
        const { client, accountKey } = makeClient('authok-first');
        await seedAccount(accountKey, { 'state:count:connected': '0' });

        assert.equal(await client.notifyAuthenticationSuccess('user@example.com'), true);
        assert.deepEqual(client.notifications, [{ event: 'authenticationSuccess', data: { user: 'user@example.com' } }]);
    });

    await t.test('announces a recovery from an authentication failure', async () => {
        const { client, accountKey } = makeClient('authok-recovered');
        await seedAccount(accountKey, {
            'state:count:connected': '7',
            lastErrorState: JSON.stringify({ serverResponseCode: 'AUTHENTICATIONFAILED' }),
            [LAST_ERROR_EVENT_FIELD]: 'authenticationError'
        });

        assert.equal(await client.notifyAuthenticationSuccess('user@example.com'), true);
        assert.equal(client.notifications.length, 1);
    });

    await t.test('says nothing about a recovery from a connection error', async () => {
        // The account never had an authentication problem, so calling this an authentication
        // success is both wrong and, for an account that keeps dropping, a webhook per cycle.
        const { client, accountKey } = makeClient('authok-connecterror');
        await seedAccount(accountKey, {
            'state:count:connected': '7',
            lastErrorState: JSON.stringify({ serverResponseCode: 'ETIMEDOUT' }),
            [LAST_ERROR_EVENT_FIELD]: 'connectError'
        });

        assert.equal(await client.notifyAuthenticationSuccess('user@example.com'), false);
        assert.deepEqual(client.notifications, []);
        assert.equal(await redis.hget(accountKey, 'lastErrorState'), null, 'the error state is still cleared');
    });

    await t.test('leaves a failure a login says nothing about for its owner', async () => {
        // A login clears every failure that stood between the account and a session, which is what
        // BaseClient assumes of all of them - a client that reports one a login does not answer
        // overrides isSelfClearedErrorState() to keep it. The Graph client's change subscription is
        // that case: the tenants that hit it refresh tokens and log in perfectly throughout, so
        // every reconnect used to erase a live failure, leaving the account reporting healthy with
        // no lastError while it synced nothing, and re-announcing it once the state was rewritten.
        const { client, accountKey } = makeClient('authok-subscription');
        client.isSelfClearedErrorState = parsed => parsed?.serverResponseCode === 'SubscriptionSetupError';
        await seedAccount(accountKey, {
            'state:count:connected': '7',
            lastErrorState: JSON.stringify({ response: 'The service principal is disabled.', serverResponseCode: 'SubscriptionSetupError' }),
            [LAST_ERROR_EVENT_FIELD]: 'connectError',
            'lastError:errorCount': '2'
        });

        assert.equal(await client.notifyAuthenticationSuccess('user@example.com'), false);
        assert.deepEqual(client.notifications, []);

        const left = await redis.hmget(accountKey, 'lastErrorState', LAST_ERROR_EVENT_FIELD, 'lastError:errorCount');
        assert.equal(JSON.parse(left[0]).serverResponseCode, 'SubscriptionSetupError', 'the report stands until a subscription works');
        assert.deepEqual(left.slice(1), ['connectError', '2'], 'and so does the run it belongs to');
    });

    await t.test('clears a failure nothing claimed, whatever reported it', async () => {
        // The hook defaults to false, so a client that says nothing keeps nothing: a run only its
        // reporter can lift has to be declared by the reporter, not listed here.
        const { client, accountKey } = makeClient('authok-subscription-base');
        await seedAccount(accountKey, {
            'state:count:connected': '7',
            lastErrorState: JSON.stringify({ response: 'The service principal is disabled.', serverResponseCode: 'SubscriptionSetupError' }),
            [LAST_ERROR_EVENT_FIELD]: 'connectError'
        });

        assert.equal(await client.notifyAuthenticationSuccess('user@example.com'), false);
        assert.equal(await redis.hget(accountKey, 'lastErrorState'), null, 'the error state is cleared like any other');
    });

    await t.test('clears the whole error run it recovered from', async () => {
        const { client, accountKey } = makeClient('authok-clears');
        await seedAccount(accountKey, {
            'state:count:connected': '7',
            lastErrorState: JSON.stringify({ serverResponseCode: 'AUTHENTICATIONFAILED' }),
            [LAST_ERROR_EVENT_FIELD]: 'authenticationError',
            'lastError:errorCount': '4',
            'lastError:first': new Date().toISOString()
        });

        await client.notifyAuthenticationSuccess('user@example.com');

        const left = await redis.hmget(accountKey, 'lastErrorState', LAST_ERROR_EVENT_FIELD, 'lastError:errorCount', 'lastError:first');
        assert.deepEqual(left, [null, null, null, null], 'the error run must not outlive the error');
    });

    await t.test('reads an error state written before the marker existed as an authentication failure', async () => {
        // Upgrade case. An account already in an error state when the field shipped carries no
        // marker, and silently dropping the recovery it had been promised is the worse guess.
        const { client, accountKey } = makeClient('authok-legacy');
        await seedAccount(accountKey, {
            'state:count:connected': '7',
            lastErrorState: JSON.stringify({ serverResponseCode: 'AUTHENTICATIONFAILED' })
        });

        assert.equal(await client.notifyAuthenticationSuccess('user@example.com'), true);
    });

    await t.test('ignores an empty stored error state', async () => {
        const { client, accountKey } = makeClient('authok-empty');
        await seedAccount(accountKey, { 'state:count:connected': '7', lastErrorState: '{}', [LAST_ERROR_EVENT_FIELD]: 'authenticationError' });

        assert.equal(await client.notifyAuthenticationSuccess('user@example.com'), false);
    });

    await t.test('announces a recovery once, not again on the next login', async () => {
        // The clear and the read are one step, so a reconnect that follows cannot re-announce the
        // same recovery. The IMAP client used to clear the state only after a completed folder
        // sync, so a login that could not sync read the same error again every time.
        const { client, accountKey } = makeClient('authok-once');
        await seedAccount(accountKey, {
            'state:count:connected': '7',
            lastErrorState: JSON.stringify({ serverResponseCode: 'AUTHENTICATIONFAILED' }),
            [LAST_ERROR_EVENT_FIELD]: 'authenticationError'
        });

        assert.equal(await client.notifyAuthenticationSuccess('user@example.com'), true);
        assert.equal(await client.notifyAuthenticationSuccess('user@example.com'), false);
        assert.equal(client.notifications.length, 1);
    });

    await t.test('says nothing about an ordinary reconnect', async () => {
        const { client, accountKey } = makeClient('authok-reconnect');
        await seedAccount(accountKey, { 'state:count:connected': '7' });

        assert.equal(await client.notifyAuthenticationSuccess('user@example.com'), false);
        assert.deepEqual(client.notifications, []);
    });

    await t.test('announces a first login only once, however often the login is repeated', async () => {
        // The connected-session counter only moves once the account reaches `connected`, which for
        // an IMAP account means a completed folder sync. An account that authenticates but cannot
        // sync leaves it at zero, and used to re-announce its first login on every reconnect.
        const { client, accountKey } = makeClient('authok-nosync');
        await seedAccount(accountKey, { 'state:count:connected': '0' });

        assert.equal(await client.notifyAuthenticationSuccess('user@example.com'), true);
        assert.equal(await client.notifyAuthenticationSuccess('user@example.com'), false);
        assert.equal(await client.notifyAuthenticationSuccess('user@example.com'), false);
        assert.equal(client.notifications.length, 1);
    });

    await t.test('still announces a later authentication failure recovery', async () => {
        // The once-only flag covers the first-login test alone; a real recovery has to get through.
        const { client, accountKey } = makeClient('authok-nosync-recovers');
        await seedAccount(accountKey, { 'state:count:connected': '0' });

        assert.equal(await client.notifyAuthenticationSuccess('user@example.com'), true);

        await client.setErrorState('authenticationError', { serverResponseCode: 'AUTHENTICATIONFAILED' });
        assert.equal(await client.notifyAuthenticationSuccess('user@example.com'), true);
        assert.equal(client.notifications.length, 2);
    });
});
