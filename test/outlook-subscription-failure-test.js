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
        // Enough of an account hash for the two paths under test: the direct reads, and the
        // conditional delete both recovery routes clear the stored error run through
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

// A client whose notify() runs the real BaseClient path, setErrorState and the state write
// included, against one account hash. The makeClient() above stubs notify(), so on its own it
// verifies the report and the clear as two halves that never meet: if reportSubscriptionFailure()
// were switched to the notification handler directly it would stop setting the account state,
// clearSubscriptionFailure()'s gate would never be true again, and every assertion there would
// still pass while the nine-month outage came back.
function makeLiveClient() {
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

    return { outlook, delivered, hash };
}

test('a reported subscription failure and its recovery, through the real notify path', async t => {
    const { outlook, delivered, hash } = makeLiveClient();

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

test('a reported subscription failure across a worker restart', async t => {
    // The report is written while the credential is perfectly healthy, so everything a restart does
    // on the way back up - a token refresh, a login, a state flip to `connected` - happens while the
    // account still cannot subscribe. Clearing the error run on the way past made the account report
    // healthy with no lastError, and then announced the same failure again as if it were new.
    const { outlook, delivered, hash } = makeLiveClient();

    await t.test('survives the login init() performs on the way back up', async () => {
        await outlook.reportSubscriptionFailure('creation', { error: `Subscription failed: ${SP_DISABLED}` }, 3);
        assert.equal(delivered.length, 1);

        assert.equal(await outlook.notifyAuthenticationSuccess('user@example.com'), false, 'a login is not a recovery from this');

        assert.match(hash.get('lastErrorState'), /service principal/, 'the failure is still live, so it is still on record');
        assert.equal(hash.get(LAST_ERROR_EVENT_FIELD), 'connectError');
        assert.equal(delivered.length, 1);
    });

    await t.test('and is not announced a second time', async () => {
        // init() flips the state before it reaches ensureSubscription(), which then fails again
        outlook.state = 'connected';

        await outlook.reportSubscriptionFailure('creation', { error: `Subscription failed: ${SP_DISABLED}` }, 3);

        assert.equal(delivered.length, 1, 'the same failure is heard once, not once per restart');
        assert.equal(outlook.state, 'connectError');
    });

    await t.test('is still lifted by a subscription that works', async () => {
        // A restart whose ensureSubscription() succeeds reaches this with the state already back at
        // `connected`, which used to be read as "nothing of ours to clear"
        outlook.state = 'connected';

        await outlook.clearSubscriptionFailure();

        assert.equal(hash.has('lastErrorState'), false, 'the error must not outlive the condition');
        assert.equal(hash.has(LAST_ERROR_EVENT_FIELD), false);
        assert.equal(outlook.state, 'connected');
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

    await t.test('reads the stored state once per healthy account, not once an hour', async () => {
        // Every path that concludes a subscription is working calls this, so a healthy account
        // reaches it on every hourly pass. The only reason to look at Redis while the state is not
        // `connectError` is a report written before this process started, which cannot become true
        // again while the process runs.
        const { outlook } = makeClient({ state: 'connected' });

        let reads = 0;
        const readErrorState = outlook.redis.hget;
        outlook.redis.hget = async (key, field) => {
            reads++;
            return readErrorState(key, field);
        };

        await outlook.clearSubscriptionFailure();
        assert.equal(reads, 1, 'a worker that restarted since a report has to find it');

        await outlook.clearSubscriptionFailure();
        await outlook.clearSubscriptionFailure();
        assert.equal(reads, 1, 'and every pass after that is free');

        // A failure reported since is this client's own, and it is in the state to prove it
        outlook.state = 'connectError';
        await outlook.clearSubscriptionFailure();
        assert.equal(reads, 2, 'a reported account is always read');
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

test('OutlookClient.renewSubscription() and the report it takes back', async t => {
    // Driving the real renewal, because that is where the clear is called from: it sits inside the
    // try whose catch reads any throw as a Graph failure, and the healthy paths through it are the
    // ones an account reported while it still had a subscription has to come back through.
    function makeRenewClient({ expiresInMs, patchResult } = {}) {
        const { outlook, notifications, hash } = makeClient({
            state: 'connectError',
            storedError: { response: SP_DISABLED, serverResponseCode: 'SubscriptionSetupError' }
        });
        hash.set(LAST_ERROR_EVENT_FIELD, 'connectError');

        let stored = {
            id: 'sub-1',
            expirationDateTime: new Date(Date.now() + expiresInMs).toISOString(),
            state: { state: 'created', time: Date.now(), retryCount: 0, createRetryCount: 0 }
        };
        const requests = [];

        outlook.accountObject = {
            getLock: () => ({ acquireLock: async () => ({ success: true }), releaseLock: async () => {} })
        };
        outlook.getStoredSubscription = async () => JSON.parse(JSON.stringify(stored));
        outlook.saveStoredSubscription = async value => {
            stored = value;
        };
        outlook.request = async (...args) => {
            requests.push(args);
            return patchResult;
        };

        return { outlook, notifications, hash, requests, stored: () => stored };
    }

    await t.test('a subscription that is still good takes the report back too', async () => {
        // Reported while the subscription had two days left on it: every hourly pass answers
        // `not_needed` without making a request, so nothing used to lift the report until the
        // renewal window opened - up to 46 hours of 503s while notifications kept arriving.
        const { outlook, hash, requests } = makeRenewClient({ expiresInMs: 60 * 3600 * 1000 });

        const result = await outlook.renewSubscription({ force: false });

        assert.deepEqual(result, { success: true, reason: 'not_needed' });
        assert.deepEqual(requests, [], 'and it did so without asking Graph anything');
        assert.equal(outlook.state, 'connected');
        assert.equal(hash.has('lastErrorState'), false, 'the error must not outlive the condition');
    });

    await t.test('a renewal is not failed by a clear that could not be stored', async () => {
        // The clear is Redis work inside the renewal's own try: a hiccup used to be caught by the
        // catch below it, counted as a failed renewal, and at the cap announced to the operator as
        // a Graph failure whose text was a Redis error.
        const expirationDateTime = new Date(Date.now() + 70 * 3600 * 1000).toISOString();
        const { outlook, notifications, stored } = makeRenewClient({
            expiresInMs: 12 * 3600 * 1000,
            patchResult: { expirationDateTime }
        });

        outlook.redis.hDelIfEquals = async () => {
            throw new Error('READONLY You can not write against a read only replica');
        };

        const result = await outlook.renewSubscription({ force: false });

        assert.deepEqual(result, { success: true, expirationDateTime }, 'the renewal succeeded, and says so');
        assert.equal(stored().state.state, 'created', 'the renewed subscription is recorded as renewed');
        assert.equal(stored().state.retryCount, 0, 'and nothing is counted against the retry budget');
        assert.deepEqual(notifications, [], 'nothing is announced for it');
        assert.equal(outlook.state, 'connectError', 'the report stands until a later pass manages to clear it');
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

        assert.deepEqual(calls, ['save', 'renew:false', 'ensure'], 'the hourly pass is the slow retry, so it does not give up');
        assert.deepEqual(stored().state, { state: 'error', error: null, createRetryCount: 0, retryCount: 0 });
    });

    await t.test('gives a spent renewal ladder a fresh one as well', async () => {
        // A subscription inside the renew window is never recreated by this pass, so the reset is
        // the only thing it gets: left at the cap, its renewal is one PATCH an hour forever, with
        // no backoff ladder between the attempts and no report that it is still failing.
        const { outlook, calls, stored } = makeTicker({
            renewalResult: { success: false, reason: 'renewal_failed' },
            storedSubscription: { state: { state: 'error', error: 'Subscription renewal failed', retryCount: OUTLOOK_MAX_RETRY_ATTEMPTS, createRetryCount: 0 } }
        });

        await outlook.renewOrCreateSubscription();

        assert.deepEqual(calls, ['save', 'renew:false'], 'the counters are cleared before the attempt, and nothing is recreated');
        assert.equal(stored().state.retryCount, 0);
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
