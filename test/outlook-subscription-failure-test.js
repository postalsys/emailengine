'use strict';

// Reported from the field: Outlook accounts across several tenants stopped receiving mail and went
// undetected for about nine months. The tenants had disabled the Exchange Online service principal
// (AADSTS500014, typically a lapsed subscription or an admin action). Token refresh still succeeds,
// so no authentication error fires; the Graph mail calls all fail, the change subscription can
// never be created, and the retries exhaust. Exhausting them wrote a log line and nothing else, so
// the account reported `connected` for the whole nine months.
//
// Three things had to hold for that to be possible, and each is covered here: giving up has to
// report something, a working subscription has to take the report back, and a fresh access token
// must not be read as a recovery from a failure it says nothing about.

const test = require('node:test');
const { after } = require('node:test');
const assert = require('node:assert').strict;

require('./helpers/mock-db').installDbMock();

after(() => {
    // outlook-client pulls in lib/settings -> lib/tools, whose Redis handles keep the event loop
    // alive after the assertions are done. Same force-exit the other pure suites use.
    setTimeout(() => process.exit(), 1000).unref();
});

const { OutlookClient } = require('../lib/email-client/outlook-client');
const { LAST_ERROR_EVENT_FIELD, OUTLOOK_MAX_RETRY_ATTEMPTS } = require('../lib/consts');

// AADSTS500014 as Graph reports it, which is the text an operator has to be shown.
const SP_DISABLED = 'The service principal for resource https://outlook.office365.com is disabled.';

// lib/lua/h-del-if-equals.lua against a Map: the delete applies only while the guard field still
// holds the value the caller judged. Shared by both hand-rolled clients below, so they cannot
// prove different things about the same script.
const hDelIfEqualsOn =
    hash =>
    async (key, guardKey, expected, ...fields) => {
        if ((hash.get(guardKey) ?? '') !== expected) {
            return 0;
        }
        fields.forEach(field => hash.delete(field));
        return 1;
    };

function makeClient({ state = 'connected', storedError } = {}) {
    const notifications = [];
    const hash = new Map();
    if (storedError !== undefined) {
        hash.set('lastErrorState', JSON.stringify(storedError));
    }

    const outlook = new OutlookClient('test-account', {
        // Enough of an account hash for the two paths under test: the direct reads, and the one
        // MULTI notifyAuthenticationSuccess() uses to read and clear the stored error run
        redis: {
            hget: async (key, field) => hash.get(field) ?? null,
            hdel: async (key, ...fields) => {
                fields.forEach(field => hash.delete(field));
                return 1;
            },
            hDelIfEquals: hDelIfEqualsOn(hash),
            multi() {
                const queued = [];
                const chain = {
                    hmget: (key, ...fields) => {
                        queued.push(() => fields.map(field => hash.get(field) ?? null));
                        return chain;
                    },
                    hdel: (key, ...fields) => {
                        queued.push(() => {
                            fields.forEach(field => hash.delete(field));
                            return 1;
                        });
                        return chain;
                    },
                    exec: async () => queued.map(run => [null, run()])
                };
                return chain;
            }
        }
    });

    outlook.logger = { trace() {}, debug() {}, info() {}, warn() {}, error() {} };
    outlook.state = state;
    outlook.setStateVal = async () => {};
    outlook.getAccountKey = () => 'iad:test-account';
    outlook.notify = async (mailbox, event, data) => {
        notifications.push({ event, data });
    };

    return { outlook, notifications, hash };
}

test('OutlookClient.reportSubscriptionFailure()', async t => {
    await t.test('announces a subscription that could not be created', async () => {
        const { outlook, notifications } = makeClient();

        await outlook.reportSubscriptionFailure('creation', { state: 'error', error: `Subscription failed: ${SP_DISABLED}` });

        assert.equal(notifications.length, 1, 'giving up has to be heard, not only logged');
        assert.equal(notifications[0].event, 'connectError');
        assert.match(notifications[0].data.response, /service principal/, 'the operator needs the reason Graph gave');
        assert.equal(notifications[0].data.serverResponseCode, 'SubscriptionSetupError');
    });

    await t.test('is a connection error, not an authentication one', async () => {
        // The credential is fine - re-authorizing cannot lift a disabled service principal, and
        // reporting it as an authentication failure would hand it to the safety net that switches
        // the account off after three days and offers only a re-authorization that cannot help.
        const { outlook, notifications } = makeClient();

        await outlook.reportSubscriptionFailure('renewal', { error: SP_DISABLED });

        assert.equal(notifications[0].event, 'connectError');
        assert.notEqual(notifications[0].event, 'authenticationError');
    });

    await t.test('still says something when the stored state carries no message', async () => {
        const { outlook, notifications } = makeClient();

        await outlook.reportSubscriptionFailure('renewal', null);

        assert.match(notifications[0].data.response, /subscription renewal failed/i);
    });
});

test('a reported subscription failure and its recovery, through the real notify path', async t => {
    // The suites above stub notify(), which is where setErrorState() lives - so on their own they
    // verify the report and the clear as two halves that never meet. If reportSubscriptionFailure()
    // were switched to the notification handler directly, it would stop setting the account state,
    // clearSubscriptionFailure()'s gate would never be true again, and every assertion above would
    // still pass while the nine-month outage came back. This case runs the pair for real.
    const hash = new Map([['account', 'test-account']]);
    const delivered = [];

    const outlook = new OutlookClient('test-account', {
        redis: {
            hget: async (key, field) => hash.get(field) ?? null,
            hSetExists: async (key, field, value) => {
                hash.set(field, value);
                return 1;
            },
            hIncrbyExists: async (key, field, by) => {
                const next = Number(hash.get(field) || 0) + by;
                hash.set(field, String(next));
                return next;
            },
            hdel: async (key, ...fields) => {
                fields.forEach(field => hash.delete(field));
                return 1;
            },
            hDelIfEquals: hDelIfEqualsOn(hash),
            multi() {
                const queued = [];
                const chain = new Proxy(
                    {},
                    {
                        get: (target, prop) => {
                            if (prop === 'exec') {
                                return async () => queued.map(run => [null, run()]);
                            }
                            return (key, ...args) => {
                                queued.push(() => applyCommand(String(prop), args));
                                return chain;
                            };
                        }
                    }
                );
                return chain;
            }
        }
    });

    // The handful of commands the two paths queue, applied against the same hash the direct reads use
    function applyCommand(command, args) {
        switch (command) {
            case 'hmget':
                return args.map(field => hash.get(field) ?? null);
            case 'hdel':
                args.forEach(field => hash.delete(field));
                return 1;
            case 'hSetExists':
                hash.set(args[0], args[1]);
                return 1;
            case 'hSetBigger':
                hash.set(args[0], args[1]);
                return 1;
            case 'hget':
                return hash.get(args[0]) ?? null;
            case 'hIncrbyExists': {
                const next = Number(hash.get(args[0]) || 0) + args[1];
                hash.set(args[0], String(next));
                return next;
            }
            default:
                return 1;
        }
    }

    outlook.logger = { trace() {}, debug() {}, info() {}, warn() {}, error() {} };
    outlook.state = 'connected';
    outlook.runIndex = 0;
    outlook.getAccountKey = () => 'iad:test-account';
    outlook.notificationHandler = {
        notify: async (mailbox, event, data) => {
            delivered.push({ event, data });
        }
    };

    await t.test('the report sets the account state and stores the error', async () => {
        await outlook.reportSubscriptionFailure('creation', { error: `Subscription failed: ${SP_DISABLED}` }, 3);

        assert.deepEqual(
            delivered.map(entry => entry.event),
            ['connectError'],
            'the operator has to be told, and only once'
        );
        assert.equal(outlook.state, 'connectError', 'an account that cannot subscribe is not connected');

        const stored = JSON.parse(hash.get('lastErrorState'));
        assert.equal(stored.serverResponseCode, 'SubscriptionSetupError', 'the marker clearSubscriptionFailure() gates on');
        assert.match(stored.response, /service principal/);
    });

    await t.test('a working subscription takes it back', async () => {
        await outlook.clearSubscriptionFailure();

        assert.equal(outlook.state, 'connected');
        assert.equal(hash.has('lastErrorState'), false, 'the error must not outlive the condition');
        assert.equal(delivered.length, 1, 'recovering from a connection error is not an authentication success');
    });
});

test('OutlookClient.clearSubscriptionFailure()', async t => {
    await t.test('lifts the failure once a subscription works again', async () => {
        const { outlook, hash } = makeClient({
            state: 'connectError',
            storedError: { response: SP_DISABLED, serverResponseCode: 'SubscriptionSetupError' }
        });
        hash.set(LAST_ERROR_EVENT_FIELD, 'connectError');
        hash.set('lastError:errorCount', '3');

        await outlook.clearSubscriptionFailure();

        assert.equal(outlook.state, 'connected');
        assert.equal(hash.has('lastErrorState'), false, 'the error must not outlive the condition');
        assert.equal(hash.has(LAST_ERROR_EVENT_FIELD), false);
        assert.equal(hash.has('lastError:errorCount'), false);
    });

    await t.test('leaves an error state it did not report alone', async () => {
        // A connection error from somewhere else is that owner's to clear.
        const { outlook, hash } = makeClient({
            state: 'connectError',
            storedError: { response: 'Something else went wrong', serverResponseCode: 'ETIMEDOUT' }
        });

        await outlook.clearSubscriptionFailure();

        assert.equal(outlook.state, 'connectError');
        assert.equal(hash.has('lastErrorState'), true);
    });

    await t.test('does nothing for an account that is not in an error state', async () => {
        const { outlook } = makeClient({ state: 'connected' });

        await outlook.clearSubscriptionFailure();

        assert.equal(outlook.state, 'connected');
    });

    await t.test('leaves a failure written while it was deciding', async () => {
        // The race lib/lua/h-del-if-equals.lua exists for: anything else in the worker - a refused
        // token refresh, say - can replace the error between the read and the delete.
        const { outlook, hash } = makeClient({
            state: 'connectError',
            storedError: { response: SP_DISABLED, serverResponseCode: 'SubscriptionSetupError' }
        });

        const newFailure = JSON.stringify({ response: 'invalid_grant', serverResponseCode: 'TokenGenerationError' });
        const readErrorState = outlook.redis.hget;
        outlook.redis.hget = async (key, field) => {
            const value = await readErrorState(key, field);
            // The report lands while this call is still holding the value it read
            hash.set('lastErrorState', newFailure);
            return value;
        };

        await outlook.clearSubscriptionFailure();

        assert.equal(hash.get('lastErrorState'), newFailure, 'the newer failure is left for whoever wrote it');
        assert.equal(outlook.state, 'connectError', 'and the account is not reported as recovered');
    });
});

test('OutlookClient.getTokenData() recovery', async t => {
    function makeTokenClient(state) {
        const { outlook, notifications } = makeClient({ state });
        outlook.accountObject = {
            getActiveAccessTokenData: async () => ({ accessToken: 'tok', user: 'user@example.com', cached: true })
        };
        return { outlook, notifications };
    }

    await t.test('a fresh token clears an authentication error', async () => {
        const { outlook } = makeTokenClient('authenticationError');

        assert.equal(await outlook.getToken(), 'tok');
        assert.equal(outlook.state, 'connected');
    });

    await t.test('a fresh token does not clear a subscription failure', async () => {
        // This is what hid the reported outage: the tenant's tokens kept refreshing perfectly, so
        // every Graph call reset the account to `connected` while nothing was syncing.
        const { outlook } = makeTokenClient('connectError');

        assert.equal(await outlook.getToken(), 'tok');
        assert.equal(outlook.state, 'connectError', 'a token says nothing about the subscription');
    });

    await t.test('a connected account is left alone', async () => {
        const { outlook, notifications } = makeTokenClient('connected');

        await outlook.getToken();

        assert.equal(outlook.state, 'connected');
        assert.deepEqual(notifications, [], 'nothing to announce for an account that never failed');
    });
});

test('OutlookClient.renewOrCreateSubscription()', async t => {
    // The hourly pass behind setupRenewWatchTimer(), extracted so it can be run without waiting an
    // hour. It is the account's only slow retry: the fast ones ensureSubscription() schedules are
    // capped, and there is no poller behind a Graph account, so an account that stops recreating
    // its subscription stops syncing entirely until something reconnects it.
    function makeTicker({ renewalResult = { success: true }, storedSubscription = {}, ensureError } = {}) {
        const calls = [];
        const errors = [];
        const { outlook } = makeClient();

        let stored = JSON.parse(JSON.stringify(storedSubscription));

        outlook.logger.error = entry => errors.push(entry);
        outlook.getStoredSubscription = async () => stored;
        outlook.saveStoredSubscription = async value => {
            calls.push('save');
            stored = value;
        };
        outlook.renewSubscription = async opts => {
            calls.push(`renew:${opts.force}`);
            return renewalResult;
        };
        outlook.ensureSubscription = async () => {
            calls.push('ensure');
            if (ensureError) {
                throw ensureError;
            }
        };

        return { outlook, calls, errors, stored: () => stored };
    }

    await t.test('renews a subscription that is still there, and creates nothing', async () => {
        const { outlook, calls } = makeTicker({ renewalResult: { success: true } });

        await outlook.renewOrCreateSubscription();

        assert.deepEqual(calls, ['renew:false']);
    });

    await t.test('recreates a subscription there is nothing left to renew', async () => {
        for (const reason of ['expired', 'no_subscription']) {
            const { outlook, calls } = makeTicker({ renewalResult: { success: false, reason } });

            await outlook.renewOrCreateSubscription();

            assert.deepEqual(calls, ['renew:false', 'ensure'], `a ${reason} subscription is recreated`);
        }
    });

    await t.test('leaves a renewal that failed for some other reason alone', async () => {
        const { outlook, calls } = makeTicker({ renewalResult: { success: false, reason: 'request_failed' } });

        await outlook.renewOrCreateSubscription();

        assert.deepEqual(calls, ['renew:false'], 'a subscription that still exists is not replaced');
    });

    await t.test('keeps trying once the fast retries are exhausted, with the ladder reset', async () => {
        // The end state this pass used to accept: it read the creation retry count, found it at the
        // cap and logged "waiting for reconnect", which only a worker restart, an account update or
        // a re-authorization brings. A tenant that re-enabled the service principal an hour later
        // was never noticed, and the account had no subscription to sync from in the meantime.
        //
        // Clearing the counters is what makes it a retry rather than one attempt an hour forever:
        // left at the cap, ensureSubscription() never schedules a fast one again, so an hour that
        // could have recovered in thirty seconds costs the full hour.
        const { outlook, calls, stored } = makeTicker({
            renewalResult: { success: false, reason: 'no_subscription' },
            storedSubscription: { state: { state: 'error', error: 'Subscription failed', createRetryCount: OUTLOOK_MAX_RETRY_ATTEMPTS, retryCount: 2 } }
        });

        await outlook.renewOrCreateSubscription();

        assert.deepEqual(calls, ['renew:false', 'save', 'ensure'], 'the hourly pass is the slow retry, so it does not give up');
        assert.deepEqual(stored().state, { state: 'error', error: null, createRetryCount: 0, retryCount: 0 });
    });

    await t.test('does not rewrite a stored record that has nothing to reset', async () => {
        const { outlook, calls } = makeTicker({
            renewalResult: { success: false, reason: 'expired' },
            storedSubscription: { state: { state: 'error', createRetryCount: 0, retryCount: 0 } }
        });

        await outlook.renewOrCreateSubscription();

        assert.deepEqual(calls, ['renew:false', 'ensure'], 'a subscription whose counters are already clear is left alone');
    });

    await t.test('reports a failed pass rather than rejecting', async () => {
        // setupRenewWatchTimer() reschedules off this promise settling, so a rejection would be an
        // unhandled one and would take the worker with it
        const { outlook, calls, errors } = makeTicker({
            renewalResult: { success: false, reason: 'expired' },
            ensureError: new Error('Graph is unavailable')
        });

        await outlook.renewOrCreateSubscription();

        assert.deepEqual(calls, ['renew:false', 'ensure']);
        assert.equal(errors.length, 1);
        assert.match(errors[0].msg, /Failed to renew/);
    });
});
