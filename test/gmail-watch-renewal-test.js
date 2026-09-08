'use strict';

// Unit coverage for GmailClient.renewWatch()'s watch-arming gate (gmail-client.js).
//
// Focus: when the linked Pub/Sub app is missing the pubSubTopic / pubSubIamPolicy markers,
// renewWatch must SKIP arming the Gmail watch and log the warning only ONCE per connection
// (the renewal timer re-fires ~hourly and the skip path never sets lastWatch, so an unguarded
// warning would repeat every cycle). When the markers are present it must arm the watch.

const test = require('node:test');
const assert = require('node:assert').strict;

const { GmailClient } = require('../lib/email-client/gmail-client');
const { oauth2Apps } = require('../lib/oauth2-apps');
const { redis } = require('../lib/db');
const registerRedisTeardown = require('./helpers/redis-teardown');

// Requiring the clients pulls in lib/db (persistent Redis + BullMQ handles); force a clean exit.
registerRedisTeardown(redis);

// Build a GmailClient with the renewWatch collaborators stubbed and log output captured.
function makeClient() {
    const gmail = new GmailClient('test-account', {});
    const logs = { warn: [], info: [], error: [] };
    gmail.logger = {
        warn: entry => logs.warn.push(entry),
        info: entry => logs.info.push(entry),
        error: entry => logs.error.push(entry),
        debug: () => {},
        trace: () => {}
    };
    gmail.prepare = async () => {};
    const watchCalls = [];
    gmail.request = async (url, method, payload) => {
        watchCalls.push({ url, method, payload });
        return { historyId: '1', expiration: '0' };
    };
    const updates = [];
    gmail.accountObject = {
        update: async payload => {
            updates.push(payload);
        }
    };
    return { gmail, logs, watchCalls, updates };
}

// lastWatch null -> renewal is due; _app.pubSubApp linked -> the gate is reached.
const dueAccountData = () => ({ _app: { pubSubApp: 'test-pubsub-app' }, lastWatch: null });

test('Gmail renewWatch watch-arming gate', async t => {
    const savedGet = oauth2Apps.get;
    t.after(() => {
        oauth2Apps.get = savedGet;
    });

    await t.test('skips arming and warns only once when topic/IAM markers are missing', async () => {
        // Linked app exists but has neither pubSubTopic nor pubSubIamPolicy recorded.
        oauth2Apps.get = async () => ({ id: 'test-pubsub-app' });
        const { gmail, logs, watchCalls } = makeClient();

        // Three renewal cycles back to back (mimics the ~hourly timer re-firing).
        await gmail.renewWatch(dueAccountData(), {});
        await gmail.renewWatch(dueAccountData(), {});
        await gmail.renewWatch(dueAccountData(), {});

        assert.equal(watchCalls.length, 0, 'the watch must not be armed without markers');
        assert.equal(logs.warn.length, 1, 'the missing-markers warning must be logged at most once per connection');
        assert.match(logs.warn[0].msg, /topic\/IAM markers are not recorded/);
        assert.equal(logs.warn[0].hasTopic, false);
        assert.equal(logs.warn[0].hasIamPolicy, false);
    });

    await t.test('arms the watch when topic and IAM markers are present', async () => {
        oauth2Apps.get = async () => ({
            id: 'test-pubsub-app',
            pubSubTopic: 'projects/p/topics/ee-pub-test',
            pubSubIamPolicy: { members: ['serviceAccount:gmail-api-push@system.gserviceaccount.com'], role: 'roles/pubsub.publisher' }
        });
        const { gmail, logs, watchCalls, updates } = makeClient();

        await gmail.renewWatch(dueAccountData(), {});

        assert.equal(updates[0].watchFailure, null, 'a successful arm has to clear a recorded failure, which is what the API field reads');
        assert.equal(watchCalls.length, 1, 'the watch must be armed when markers are present');
        assert.ok(watchCalls[0].url.endsWith('/watch'));
        assert.equal(watchCalls[0].payload.topicName, 'projects/p/topics/ee-pub-test');
        assert.equal(logs.warn.length, 0, 'no missing-markers warning when markers are present');
    });

    await t.test('a later missing-markers state warns again after a successful arm reset the flag', async () => {
        const { gmail, logs, watchCalls } = makeClient();

        // First: markers present -> arm -> resets the once-per-connection flag.
        oauth2Apps.get = async () => ({
            id: 'test-pubsub-app',
            pubSubTopic: 'projects/p/topics/ee-pub-test',
            pubSubIamPolicy: { members: ['x'], role: 'roles/pubsub.publisher' }
        });
        await gmail.renewWatch(dueAccountData(), {});
        assert.equal(watchCalls.length, 1);

        // Then: markers disappear -> the warning is allowed to fire once more.
        oauth2Apps.get = async () => ({ id: 'test-pubsub-app' });
        await gmail.renewWatch(dueAccountData(), {});
        await gmail.renewWatch(dueAccountData(), {});

        assert.equal(watchCalls.length, 1, 'no further arming once markers are gone');
        assert.equal(logs.warn.length, 1, 'warning fires again exactly once after the flag was reset');
    });
});

test('Gmail renewWatch failure bookkeeping', async t => {
    function makeFailingClient(err) {
        const { gmail, logs, watchCalls, updates } = makeClient();
        gmail.request = async () => {
            throw err;
        };
        return { gmail, logs, watchCalls, updates };
    }

    await t.test('does not move lastWatch, so the hourly timer can retry', async () => {
        // The renewal gate is `lastWatch < now - MIN_WATCH_TTL` (24h). Writing lastWatch on a
        // failure bought a broken watch a full day of silence even though the timer fires hourly,
        // and a Gmail watch lapses seven days after the last successful call - so a week of daily
        // failures ended push for good.
        const { gmail, updates } = makeFailingClient(Object.assign(new Error('OAuth2 request failed'), { oauthRequest: { status: 403 } }));
        oauth2Apps.get = async () => ({ pubSubTopic: 'projects/p/topics/t', pubSubIamPolicy: {} });

        await gmail.renewWatch(dueAccountData(), {});

        assert.equal(updates.length, 1);
        assert.equal('lastWatch' in updates[0], false, 'a failed attempt must not defer the next one by a day');
        assert.ok(updates[0].watchFailure, 'the failure is recorded');
    });

    await t.test('records when the attempt happened', async () => {
        // lastWatch stops moving once renewals fail, so it cannot say how stale the answer is.
        const { gmail, updates } = makeFailingClient(new Error('OAuth2 request failed'));
        oauth2Apps.get = async () => ({ pubSubTopic: 'projects/p/topics/t', pubSubIamPolicy: {} });

        await gmail.renewWatch(dueAccountData(), {});

        assert.ok(updates[0].watchFailure.time, 'the record has to carry its own timestamp');
        assert.doesNotThrow(() => new Date(updates[0].watchFailure.time).toISOString());
        assert.equal(updates[0].watchFailure.err, 'OAuth2 request failed');
    });

    await t.test('records the missing-markers skip, which used to write nothing at all', async () => {
        // The branch the code itself calls the silent failure: Pub/Sub resources pre-provisioned in
        // GCP so the markers were never persisted. It armed no watch, wrote no record, and an
        // operator polling the account saw exactly what a healthy one shows.
        const { gmail, logs, watchCalls, updates } = makeClient();
        oauth2Apps.get = async () => ({});

        await gmail.renewWatch(dueAccountData(), {});

        assert.equal(watchCalls.length, 0, 'nothing is armed without the markers');
        assert.equal(updates.length, 1, 'but the account now says so');
        assert.match(updates[0].watchFailure.err, /markers are not recorded/);
        assert.equal(logs.warn.length, 1);
    });

    await t.test('re-records the skip every cycle while warning only once', async () => {
        // The record says when the state was last observed, so it has to keep up with the hourly
        // check; the warning is what would spam the log. Latching both would freeze the reported
        // time at the first sighting - the very staleness the lastWatch change went out to fix.
        const { gmail, updates, logs } = makeClient();
        oauth2Apps.get = async () => ({});

        await gmail.renewWatch(dueAccountData(), {});
        await gmail.renewWatch(dueAccountData(), {});
        await gmail.renewWatch(dueAccountData(), {});

        assert.equal(updates.length, 3, 'the reported time must not go stale while the check runs');
        assert.equal(logs.warn.length, 1, 'but the warning stays once per connection');
    });

    await t.test('the skip record carries no provider request, so the page shows no detail block', async () => {
        const { gmail, updates } = makeClient();
        oauth2Apps.get = async () => ({});

        await gmail.renewWatch(dueAccountData(), {});

        assert.equal('req' in updates[0].watchFailure, false);
    });

    await t.test('a Redis failure while recording the skip does not fail the renewal', async () => {
        // renewWatch() is awaited by init(); an escaping error here would abort account setup over
        // a bookkeeping write.
        const { gmail, logs } = makeClient();
        oauth2Apps.get = async () => ({});
        gmail.accountObject.update = async () => {
            throw new Error('Redis is unavailable');
        };

        await gmail.renewWatch(dueAccountData(), {});

        assert.ok(logs.error.some(entry => /Failed to record the missing watch markers/.test(entry.msg)));
    });
});
