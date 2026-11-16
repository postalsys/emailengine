'use strict';

// OutlookClient.init() connects a Graph account: it checks the auth-failure park, builds the
// client (twice for a delegated mailbox, whose token decides the route), probes the profile,
// stores a changed user principal name and the locale, announces a first login BEFORE the state
// flip and only then starts the subscription, the timers and the folder cache. Those services
// start after the connected flip, unlike Gmail's watch, which is renewed before the profile probe.
// The order of the side effects is the behavior, so every collaborator records itself into one
// log and the tests assert the sequence. Every collaborator is a stub: no Redis, no Graph.

const test = require('node:test');
const assert = require('node:assert').strict;

// init() announces the state change through tools.emitChangeEvent, destructured when the client
// module loads, so the spy has to be in place before the client is required
const tools = require('../lib/tools');
let emitted = null;
tools.emitChangeEvent = async (logger, account, type, key) => {
    if (emitted) {
        emitted.push(`emit:${type}:${key}`);
    }
};

const { OutlookClient } = require('../lib/email-client/outlook-client');
const { REDIS_PREFIX } = require('../lib/consts');
const { redis } = require('../lib/db');
const registerRedisTeardown = require('./helpers/redis-teardown');
const { noopLogger } = require('./helpers/auth-failure');

registerRedisTeardown(redis);

const FULL_SCOPES = ['https://graph.microsoft.com/Mail.ReadWrite', 'https://graph.microsoft.com/Mail.Send', 'offline_access'];
const SEND_SCOPES = ['https://graph.microsoft.com/Mail.Send', 'offline_access'];

function makeAccountData(overrides) {
    return Object.assign(
        {
            account: 'test-account',
            oauth2: { provider: 'outlook-app', scope: FULL_SCOPES, auth: { user: 'user@example.com' } },
            locale: 'en'
        },
        overrides
    );
}

/**
 * Builds an OutlookClient whose every collaborator records itself into `log`.
 *
 * @param {Object} opts
 * @param {Object} [opts.accountData] - What loadAccountData() answers
 * @param {Object|Error} [opts.profile] - The Graph profile response, or an error to throw
 * @param {Boolean} [opts.delegated] - Whether prepareDelegatedAccount() finds a delegate
 * @param {Boolean} [opts.clientCredentials] - Whether the app uses the client credentials grant
 * @param {Boolean} [opts.disabled] - Whether the auth-failure safety net parked the account
 * @returns {{outlook: OutlookClient, log: Array<String>, calls: Object}}
 */
function makeInitClient(opts = {}) {
    const log = [];
    emitted = log;
    const calls = { notify: [], update: [], hsetnx: [], warn: [], getClient: [] };

    const fakeRedis = {
        hsetnx: async (key, field, value) => {
            log.push(`redis.hsetnx:${field}`);
            calls.hsetnx.push([key, field, value]);
        }
    };

    const outlook = new OutlookClient('test-account', { redis: fakeRedis });
    outlook.logger = Object.assign({}, noopLogger, { warn: entry => calls.warn.push(entry) });
    outlook.oauth2UserPath = 'me';

    outlook.setStateVal = async () => log.push(`state:${outlook.state}`);
    outlook.getAccount = async () => log.push('getAccount');
    outlook.isSyncDisabled = async () => {
        log.push('isSyncDisabled');
        return !!opts.disabled;
    };
    outlook.getClient = async force => {
        log.push(`getClient:${force}`);
        outlook.oAuth2Client = { provider: 'outlook', useClientCredentials: !!opts.clientCredentials };
    };
    outlook.prepareDelegatedAccount = async () => {
        log.push('prepareDelegatedAccount');
        if (opts.delegated) {
            outlook.delegatedAccountObject = {};
        }
    };
    outlook.request = async url => {
        log.push(`request:${url}`);
        if (opts.profile instanceof Error) {
            throw opts.profile;
        }
        return opts.profile || { userPrincipalName: 'user@example.com', preferredLanguage: 'en-US' };
    };
    outlook.notify = async (mailbox, event, data) => {
        log.push(`notify:${event}`);
        calls.notify.push({ event, data });
    };
    outlook.notifyAuthenticationSuccess = async user => log.push(`notifyAuthenticationSuccess:${user}`);
    outlook.resetSubscriptionRetryState = async () => log.push('resetSubscriptionRetryState');
    outlook.ensureSubscription = async () => log.push('ensureSubscription');
    outlook.setupRenewWatchTimer = () => log.push('setupRenewWatchTimer');
    outlook.setupFallbackPollTimer = arg => log.push(`setupFallbackPollTimer:${JSON.stringify(arg)}`);
    outlook.listMailboxes = async () => {
        log.push('listMailboxes');
        if (opts.listError) {
            throw opts.listError;
        }
    };
    outlook.triggerSync = () => log.push('triggerSync');

    outlook.accountObject = {
        loadAccountData: async () => {
            log.push('loadAccountData');
            return opts.accountData || makeAccountData();
        },
        update: async updates => {
            log.push('accountObject.update');
            calls.update.push(updates);
        }
    };

    return { outlook, log, calls };
}

const refusedError = () =>
    Object.assign(new Error('Unauthorized'), { statusCode: 401, oauthRequest: { status: 401, response: { error: { message: 'Token expired' } } } });

test('OutlookClient.init() on a full access account', async t => {
    await t.test('flips to connected before starting the subscription and the timers', async () => {
        const { outlook, log, calls } = makeInitClient();

        await outlook.init();

        assert.deepEqual(log, [
            'state:connecting',
            'getAccount',
            'isSyncDisabled',
            'getClient:true',
            'prepareDelegatedAccount',
            'loadAccountData',
            'request:/me',
            // a first login is announced while the connected-session counter still reads zero
            'notifyAuthenticationSuccess:user@example.com',
            'state:connected',
            'emit:state:connected',
            'resetSubscriptionRetryState',
            'redis.hsetnx:outlookAnnouncedInSince',
            'ensureSubscription',
            'setupRenewWatchTimer',
            'setupFallbackPollTimer:{"first":true}',
            'listMailboxes',
            'triggerSync'
        ]);
        assert.equal(calls.hsetnx[0][0], `${REDIS_PREFIX}iad:test-account`);
        assert.match(calls.hsetnx[0][2], /^\d+$/);
        assert.deepEqual(calls.update, []);
    });

    await t.test('a delegated mailbox builds the client again once the delegate is known', async () => {
        const { outlook, log } = makeInitClient({ delegated: true });

        await outlook.init();

        assert.deepEqual(log.slice(3, 7), ['getClient:true', 'prepareDelegatedAccount', 'getClient:true', 'loadAccountData']);
    });

    await t.test('stores a changed user principal name and a missing locale in one update', async () => {
        const { outlook, log, calls } = makeInitClient({
            accountData: makeAccountData({ locale: undefined }),
            profile: { userPrincipalName: 'renamed@example.com', preferredLanguage: 'et-EE' }
        });

        await outlook.init();

        assert.equal(calls.update.length, 1);
        assert.equal(calls.update[0].locale, 'et');
        assert.equal(calls.update[0].oauth2.partial, true);
        assert.equal(calls.update[0].oauth2.auth.user, 'renamed@example.com');
        assert.equal(calls.update[0]._oldOAuth2User, undefined, 'Graph does not track the previous user');
        assert.ok(log.indexOf('accountObject.update') < log.indexOf('state:connected'));
    });

    await t.test('reads the locale off an underscore-separated preference too', async () => {
        const { outlook, calls } = makeInitClient({
            accountData: makeAccountData({ locale: undefined }),
            profile: { userPrincipalName: 'user@example.com', preferredLanguage: 'PT_br' }
        });

        await outlook.init();

        assert.deepEqual(calls.update, [{ locale: 'pt' }]);
    });

    await t.test('leaves the user of a delegated mailbox alone', async () => {
        const { outlook, calls } = makeInitClient({
            accountData: makeAccountData({
                oauth2: { provider: 'outlook-app', scope: FULL_SCOPES, auth: { user: 'shared@example.com', delegatedUser: 'owner@example.com' } }
            }),
            profile: { userPrincipalName: 'owner@example.com' }
        });

        await outlook.init();

        assert.deepEqual(calls.update, []);
    });

    await t.test('a client credentials app has full access whatever its scopes say and keeps its user', async () => {
        const { outlook, log, calls } = makeInitClient({
            clientCredentials: true,
            accountData: makeAccountData({ oauth2: { provider: 'outlook-app', scope: SEND_SCOPES, auth: { user: 'user@example.com' } } }),
            profile: { userPrincipalName: 'other@example.com' }
        });

        await outlook.init();

        assert.deepEqual(calls.update, []);
        assert.ok(log.includes('ensureSubscription'), 'treated as a full access account');
    });

    await t.test('a failed folder cache refresh is logged and the sync still starts', async () => {
        const { outlook, log, calls } = makeInitClient({ listError: new Error('nope') });

        await outlook.init();

        assert.ok(calls.warn.some(entry => entry.msg === 'Failed to renew mailbox folder cache'));
        assert.equal(log.at(-1), 'triggerSync');
    });
});

test('OutlookClient.init() on a send-only account', async t => {
    await t.test('connects without the subscription, the timers or a locale', async () => {
        const { outlook, log, calls } = makeInitClient({
            accountData: makeAccountData({ oauth2: { provider: 'outlook-app', scope: SEND_SCOPES, auth: { user: 'user@example.com' } }, locale: undefined })
        });

        await outlook.init();

        assert.deepEqual(log.slice(-4), ['request:/me', 'notifyAuthenticationSuccess:user@example.com', 'state:connected', 'emit:state:connected']);
        assert.deepEqual(calls.update, []);
    });
});

test('OutlookClient.init() when it cannot connect', async t => {
    await t.test('an account the safety net parked stops before any credential work', async () => {
        const { outlook, log } = makeInitClient({ disabled: true });

        await outlook.init();

        assert.deepEqual(log, ['state:connecting', 'getAccount', 'isSyncDisabled', 'state:unset']);
    });

    await t.test('a refused profile request is an authentication error', async () => {
        const err = refusedError();
        const { outlook, log, calls } = makeInitClient({ profile: err });

        await assert.rejects(outlook.init(), thrown => thrown === err);

        assert.equal(err.authenticationFailed, true);
        assert.equal(err.errorNotified, true);
        assert.deepEqual(log.slice(-3), ['request:/me', 'state:authenticationError', 'notify:authenticationError']);
        assert.deepEqual(calls.notify, [{ event: 'authenticationError', data: { response: 'Token expired', serverResponseCode: 'ApiRequestError' } }]);
    });

    await t.test('a refusal already announced is not announced again', async () => {
        const err = Object.assign(refusedError(), { errorNotified: true });
        const { outlook, calls } = makeInitClient({ profile: err });

        await assert.rejects(outlook.init());

        assert.deepEqual(calls.notify, []);
        assert.equal(outlook.state, 'authenticationError');
    });

    await t.test('a transient failure is rethrown unflagged for the worker to retry', async () => {
        const err = Object.assign(new Error('Service Unavailable'), { statusCode: 503, oauthRequest: { status: 503 } });
        const { outlook, log, calls } = makeInitClient({ profile: err });

        await assert.rejects(outlook.init(), thrown => thrown === err);

        assert.equal(err.authenticationFailed, undefined);
        assert.deepEqual(calls.notify, []);
        assert.equal(log.at(-1), 'request:/me');
        assert.equal(outlook.state, 'connecting');
    });
});
