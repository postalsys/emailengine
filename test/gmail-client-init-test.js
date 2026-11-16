'use strict';

// GmailClient.init() connects an API account: it checks the auth-failure park, fetches a token,
// renews the Pub/Sub watch, probes the profile, repairs the stored user and the Pub/Sub routing,
// seeds or replays the history checkpoint, arms the background timers and only then flips the
// account to `connected`. The order of those side effects is the behavior (a webhook announcing a
// first login has to be sent before the state flip, the watch has to exist before the history
// replay), so these tests record every collaborator call into one log and assert the sequence,
// not only the end state. Every collaborator is a stub: no Redis, no Google.

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

const { GmailClient } = require('../lib/email-client/gmail-client');
const { REDIS_PREFIX } = require('../lib/consts');
const { redis } = require('../lib/db');
const registerRedisTeardown = require('./helpers/redis-teardown');
const { noopLogger } = require('./helpers/auth-failure');

registerRedisTeardown(redis);

const FULL_SCOPES = ['https://www.googleapis.com/auth/gmail.modify'];
const SEND_SCOPES = ['https://www.googleapis.com/auth/gmail.send', 'openid', 'email'];
const BINDING_KEY = `${REDIS_PREFIX}oapp:h:gmail-app`;

function makeAccountData(overrides) {
    return Object.assign(
        {
            account: 'test-account',
            oauth2: { provider: 'gmail-app', scope: FULL_SCOPES, auth: { user: 'user@example.com' } },
            googleHistoryId: 100,
            locale: 'en'
        },
        overrides
    );
}

/**
 * Builds a GmailClient whose every collaborator records itself into `log`.
 *
 * @param {Object} opts
 * @param {Object} [opts.accountData] - What loadAccountData() answers, before any update
 * @param {Object} [opts.updatedAccountData] - What loadAccountData() answers after update()
 * @param {Object|Error} [opts.profile] - The Gmail profile response, or an error to throw
 * @param {Object|Error} [opts.userInfo] - The UserInfo response for a send-only account
 * @param {String|null} [opts.boundAccount] - Account the Pub/Sub routing hash names for the user
 * @param {Error} [opts.unboundError] - What assertOAuth2UserUnbound() throws
 * @param {Boolean} [opts.disabled] - Whether the auth-failure safety net parked the account
 * @returns {{gmail: GmailClient, log: Array<String>, calls: Object}}
 */
function makeInitClient(opts = {}) {
    const log = [];
    emitted = log;
    const calls = { notify: [], update: [], hset: [], hSetExists: [], triggerSync: [], warn: [], info: [] };

    let accountData = opts.accountData || makeAccountData();
    let loads = 0;

    const fakeRedis = {
        hget: async (key, field) => {
            log.push(`redis.hget:${field}`);
            return opts.boundAccount === undefined ? 'test-account' : opts.boundAccount;
        },
        hset: async (key, field, value) => {
            log.push(`redis.hset:${field}`);
            calls.hset.push([key, field, value]);
        },
        hSetExists: async (key, field, value) => {
            log.push(`redis.hSetExists:${field}`);
            calls.hSetExists.push([key, field, value]);
        }
    };

    const gmail = new GmailClient('test-account', { redis: fakeRedis });
    gmail.logger = Object.assign({}, noopLogger, {
        warn: entry => calls.warn.push(entry),
        info: entry => calls.info.push(entry)
    });

    gmail.setStateVal = async () => log.push(`state:${gmail.state}`);
    gmail.getAccount = async () => log.push('getAccount');
    gmail.isSyncDisabled = async () => {
        log.push('isSyncDisabled');
        return !!opts.disabled;
    };
    gmail.getClient = async force => log.push(`getClient:${force}`);
    gmail.getToken = async () => {
        log.push('getToken');
        if (opts.tokenError) {
            throw opts.tokenError;
        }
        return 'tok';
    };
    gmail.renewWatch = async () => log.push('renewWatch');
    gmail.request = async url => {
        if (/userinfo/.test(url)) {
            log.push('request:userinfo');
            if (opts.userInfo instanceof Error) {
                throw opts.userInfo;
            }
            return opts.userInfo || { email: 'user@example.com' };
        }
        log.push('request:profile');
        if (opts.profile instanceof Error) {
            throw opts.profile;
        }
        return opts.profile || { emailAddress: 'user@example.com', historyId: '100' };
    };
    gmail.getLocale = async () => {
        log.push('getLocale');
        if (opts.localeError) {
            throw opts.localeError;
        }
        return opts.locale;
    };
    gmail.notify = async (mailbox, event, data) => {
        log.push(`notify:${event}`);
        calls.notify.push({ event, data });
    };
    gmail.notifyAuthenticationSuccess = async user => log.push(`notifyAuthenticationSuccess:${user}`);
    gmail.triggerSync = (from, to) => {
        log.push('triggerSync');
        calls.triggerSync.push([from, to]);
    };
    gmail.setupRenewWatchTimer = () => log.push('setupRenewWatchTimer');
    gmail.setupFallbackPollingTimer = () => log.push('setupFallbackPollingTimer');

    gmail.accountObject = {
        loadAccountData: async () => {
            loads++;
            log.push('loadAccountData');
            return loads > 1 && opts.updatedAccountData ? opts.updatedAccountData : accountData;
        },
        update: async updates => {
            log.push('accountObject.update');
            calls.update.push(updates);
        },
        assertOAuth2UserUnbound: async () => {
            log.push('assertOAuth2UserUnbound');
            if (opts.unboundError) {
                throw opts.unboundError;
            }
        }
    };

    return { gmail, log, calls };
}

const refusedError = () =>
    Object.assign(new Error('Invalid Credentials'), { statusCode: 401, oauthRequest: { status: 401, response: { error: { message: 'Bad token' } } } });

test('GmailClient.init() on a full access account', async t => {
    await t.test('runs every step in order and flips to connected last', async () => {
        const { gmail, log } = makeInitClient();

        await gmail.init();

        assert.deepEqual(log, [
            'state:connecting',
            'getAccount',
            'isSyncDisabled',
            'getClient:true',
            'getToken',
            'loadAccountData',
            // the watch exists before the profile probe reads the checkpoint
            'renewWatch',
            'request:profile',
            'redis.hget:user@example.com',
            'setupRenewWatchTimer',
            'setupFallbackPollingTimer',
            // a first login is announced while the connected-session counter still reads zero
            'notifyAuthenticationSuccess:user@example.com',
            'state:connected',
            'emit:state:connected'
        ]);
        assert.equal(gmail.backgroundTimersArmed, true);
        assert.ok(gmail.lastNotificationTime > 0);
    });

    await t.test('replays the history between the stored and the current checkpoint', async () => {
        const { gmail, calls } = makeInitClient({ profile: { emailAddress: 'user@example.com', historyId: '250' } });

        await gmail.init();

        assert.deepEqual(calls.triggerSync, [[100, 250]]);
        assert.deepEqual(calls.hSetExists, []);
    });

    await t.test('does not replay when the checkpoint has not moved', async () => {
        const { gmail, calls } = makeInitClient({ profile: { emailAddress: 'user@example.com', historyId: '90' } });

        await gmail.init();

        assert.deepEqual(calls.triggerSync, []);
    });

    await t.test('seeds a missing history checkpoint from the profile instead of replaying', async () => {
        const { gmail, log, calls } = makeInitClient({
            accountData: makeAccountData({ googleHistoryId: null }),
            profile: { emailAddress: 'user@example.com', historyId: '300' }
        });

        await gmail.init();

        assert.deepEqual(calls.hSetExists, [[`${REDIS_PREFIX}iad:test-account`, 'googleHistoryId', '300']]);
        assert.deepEqual(calls.triggerSync, [], 'nothing to replay from a checkpoint that was just set');
        assert.ok(log.indexOf('redis.hSetExists:googleHistoryId') < log.indexOf('setupRenewWatchTimer'));
        assert.ok(calls.info.some(entry => entry.msg === 'Re-set missing Google History ID' && entry.historyId === 300));
    });

    await t.test('stores a changed address and reloads the account before using it', async () => {
        const updated = makeAccountData({ oauth2: { provider: 'gmail-app', scope: FULL_SCOPES, auth: { user: 'renamed@example.com' } } });
        const { gmail, log, calls } = makeInitClient({
            profile: { emailAddress: 'renamed@example.com', historyId: '100' },
            updatedAccountData: updated
        });

        await gmail.init();

        assert.equal(calls.update.length, 1);
        assert.equal(calls.update[0]._oldOAuth2User, 'user@example.com', 'the old user is kept for the cleanups');
        assert.equal(calls.update[0].oauth2.partial, true);
        assert.equal(calls.update[0].oauth2.auth.user, 'renamed@example.com');
        assert.deepEqual(log.slice(log.indexOf('request:profile') + 1, log.indexOf('request:profile') + 4), [
            'accountObject.update',
            'loadAccountData',
            'redis.hget:renamed@example.com'
        ]);
        assert.ok(log.includes('notifyAuthenticationSuccess:renamed@example.com'));
    });

    await t.test('resolves a missing locale and stores it with the other updates', async () => {
        const { gmail, log, calls } = makeInitClient({ accountData: makeAccountData({ locale: undefined }), locale: 'et' });

        await gmail.init();

        assert.deepEqual(calls.update, [{ locale: 'et' }]);
        assert.ok(log.indexOf('getLocale') < log.indexOf('accountObject.update'));
    });

    await t.test('a failed locale lookup is logged and does not stop the connection', async () => {
        const { gmail, calls } = makeInitClient({ accountData: makeAccountData({ locale: undefined }), localeError: new Error('nope') });

        await gmail.init();

        assert.deepEqual(calls.update, []);
        assert.ok(calls.warn.some(entry => entry.msg === 'Failed to resolve locale for account'));
        assert.equal(gmail.state, 'connected');
    });
});

test('GmailClient.init() Pub/Sub routing repair', async t => {
    await t.test('re-sets a missing routing entry after checking no other account holds it', async () => {
        const { gmail, log, calls } = makeInitClient({ boundAccount: null });

        await gmail.init();

        assert.deepEqual(calls.hset, [[BINDING_KEY, 'user@example.com', 'test-account']]);
        const at = log.indexOf('redis.hget:user@example.com');
        assert.deepEqual(log.slice(at, at + 3), ['redis.hget:user@example.com', 'assertOAuth2UserUnbound', 'redis.hset:user@example.com']);
    });

    await t.test('looks the user up in lowercase', async () => {
        const { gmail, calls } = makeInitClient({
            boundAccount: null,
            accountData: makeAccountData({ oauth2: { provider: 'gmail-app', scope: FULL_SCOPES, auth: { user: 'User@Example.com' } } }),
            profile: { emailAddress: 'User@Example.com', historyId: '100' }
        });

        await gmail.init();

        assert.deepEqual(calls.hset, [[BINDING_KEY, 'user@example.com', 'test-account']]);
    });

    await t.test('leaves the routing of another live account for the same user alone', async () => {
        const held = Object.assign(new Error('exists'), { output: { payload: { code: 'AccountAlreadyExists', existingAccount: 'other' } } });
        const { gmail, calls } = makeInitClient({ boundAccount: 'other', unboundError: held });

        await gmail.init();

        assert.deepEqual(calls.hset, []);
        assert.ok(
            calls.warn.some(entry => entry.msg === 'Another account holds the Google Pub/Sub routing for this user' && entry.existingAccount === 'other')
        );
        assert.equal(gmail.state, 'connected');
    });

    await t.test('any other failure of the ownership check fails the connection', async () => {
        const { gmail, log } = makeInitClient({ boundAccount: null, unboundError: new Error('Redis is gone') });

        await assert.rejects(gmail.init(), /Redis is gone/);

        assert.ok(!log.includes('state:connected'));
    });
});

test('GmailClient.init() on a send-only account', async t => {
    await t.test('probes UserInfo, skips the watch, history and timers', async () => {
        const { gmail, log } = makeInitClient({
            accountData: makeAccountData({ oauth2: { provider: 'gmail-app', scope: SEND_SCOPES, auth: { user: 'user@example.com' } }, locale: undefined })
        });

        await gmail.init();

        assert.deepEqual(log, [
            'state:connecting',
            'getAccount',
            'isSyncDisabled',
            'getClient:true',
            'getToken',
            'loadAccountData',
            'request:userinfo',
            'redis.hget:user@example.com',
            'notifyAuthenticationSuccess:user@example.com',
            'state:connected',
            'emit:state:connected'
        ]);
        assert.ok(!gmail.backgroundTimersArmed);
    });

    await t.test('stores the UserInfo address when it changed', async () => {
        const { gmail, calls } = makeInitClient({
            accountData: makeAccountData({ oauth2: { provider: 'gmail-app', scope: SEND_SCOPES, auth: { user: 'user@example.com' } } }),
            userInfo: { email: 'renamed@example.com' }
        });

        await gmail.init();

        assert.equal(calls.update[0]._oldOAuth2User, 'user@example.com');
        assert.equal(calls.update[0].oauth2.auth.user, 'renamed@example.com');
    });
});

test('GmailClient.init() when it cannot connect', async t => {
    await t.test('an account the safety net parked stops before any credential work', async () => {
        const { gmail, log } = makeInitClient({ disabled: true });

        await gmail.init();

        assert.deepEqual(log, ['state:connecting', 'getAccount', 'isSyncDisabled', 'state:unset']);
    });

    await t.test('a failed token fetch is logged and rethrown', async () => {
        const { gmail, log, calls } = makeInitClient({ tokenError: new Error('no token') });

        await assert.rejects(gmail.init(), /no token/);

        assert.ok(calls.warn.some(entry => entry.msg === 'Failed to get token or reload account data during init'));
        assert.equal(log.at(-1), 'getToken');
    });

    await t.test('a refused profile request is an authentication error', async () => {
        const err = refusedError();
        const { gmail, log, calls } = makeInitClient({ profile: err });

        await assert.rejects(gmail.init(), thrown => thrown === err);

        assert.equal(err.authenticationFailed, true);
        assert.equal(err.errorNotified, true);
        assert.deepEqual(log.slice(-3), ['request:profile', 'state:authenticationError', 'notify:authenticationError']);
        assert.deepEqual(calls.notify, [{ event: 'authenticationError', data: { response: 'Bad token', serverResponseCode: 'ApiRequestError' } }]);
    });

    await t.test('a refusal already announced is not announced again', async () => {
        const err = Object.assign(refusedError(), { errorNotified: true });
        const { gmail, calls } = makeInitClient({ profile: err });

        await assert.rejects(gmail.init());

        assert.deepEqual(calls.notify, []);
        assert.equal(gmail.state, 'authenticationError');
    });

    await t.test('a transient failure is rethrown unflagged for the worker to retry', async () => {
        const err = Object.assign(new Error('Backend Error'), { statusCode: 503, oauthRequest: { status: 503 } });
        const { gmail, log, calls } = makeInitClient({ profile: err });

        await assert.rejects(gmail.init(), thrown => thrown === err);

        assert.equal(err.authenticationFailed, undefined);
        assert.deepEqual(calls.notify, []);
        assert.equal(log.at(-1), 'request:profile');
        assert.equal(gmail.state, 'connecting');
    });
});
