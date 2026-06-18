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
    gmail.accountObject = { update: async () => {} };
    return { gmail, logs, watchCalls };
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
        const { gmail, logs, watchCalls } = makeClient();

        await gmail.renewWatch(dueAccountData(), {});

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
