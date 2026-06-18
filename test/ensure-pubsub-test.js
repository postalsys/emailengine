'use strict';

// Unit coverage for OAuth2AppsHandler.ensurePubsub() and the ownership-aware deletion path.
//
// Focus: when the Gmail Pub/Sub topic / subscription / IAM publisher binding are PRE-PROVISIONED
// in GCP (the "adopt" paths), ensurePubsub must persist the pubSubTopic / pubSubSubscription /
// pubSubIamPolicy markers (otherwise the Gmail watch never arms) while recording per-resource
// ownership flags so app deletion never removes a resource EmailEngine did not create.
//
// These run in the unit tier: Redis, BullMQ, get-secret, and the ioredfour distributed lock are
// mocked, so no live server or real Redis is needed.

const test = require('node:test');
const assert = require('node:assert').strict;

// ---- Mocks (must be wired before importing production modules) ----

const mockQueue = {
    add: async () => ({}),
    close: async () => {},
    on: () => {},
    off: () => {},
    getJob: async () => null
};

let mockRedisData = {};
let mockSets = {};

function createMockRedis() {
    let redis = {
        status: 'ready',
        hget: async (key, field) => (mockRedisData[key] && mockRedisData[key][field]) || null,
        hset: async (key, field, value) => {
            if (!mockRedisData[key]) mockRedisData[key] = {};
            mockRedisData[key][field] = value;
        },
        hgetall: async key => mockRedisData[key] || null,
        hdel: async () => {},
        hgetallBuffer: async key => {
            if (!mockRedisData[key]) return {};
            let result = {};
            for (let [k, v] of Object.entries(mockRedisData[key])) {
                result[k] = Buffer.isBuffer(v) ? v : Buffer.from(String(v));
            }
            return result;
        },
        hgetBuffer: async (key, field) => {
            if (!mockRedisData[key] || !mockRedisData[key][field]) return null;
            let v = mockRedisData[key][field];
            return Buffer.isBuffer(v) ? v : Buffer.from(String(v));
        },
        hmgetBuffer: async (key, fields) => {
            if (!mockRedisData[key]) return fields.map(() => null);
            return fields.map(f => {
                let v = mockRedisData[key][f];
                if (v == null) return null;
                return Buffer.isBuffer(v) ? v : Buffer.from(String(v));
            });
        },
        hmset: async (key, data) => {
            if (!mockRedisData[key]) mockRedisData[key] = {};
            Object.assign(mockRedisData[key], data);
        },
        multi: () => {
            let ops = [];
            let chain = {
                exec: async () => {
                    let results = [];
                    for (let op of ops) {
                        try {
                            results.push([null, await op()]);
                        } catch (err) {
                            results.push([err, null]);
                        }
                    }
                    return results;
                },
                sadd: function (key, ...members) {
                    ops.push(() => redis.sadd(key, ...members));
                    return this;
                },
                hmset: function (key, data) {
                    ops.push(() => redis.hmset(key, data));
                    return this;
                },
                hdel: function (key, fields) {
                    ops.push(() => redis.hdel(key, fields));
                    return this;
                },
                del: function (key) {
                    ops.push(() => redis.del(key));
                    return this;
                },
                srem: function (key, ...members) {
                    ops.push(() => redis.srem(key, ...members));
                    return this;
                },
                scard: function (key) {
                    ops.push(() => redis.scard(key));
                    return this;
                }
            };
            return chain;
        },
        smembers: async key => Array.from(mockSets[key] || []),
        sismember: async (key, member) => (mockSets[key] && mockSets[key].has(member) ? 1 : 0),
        sadd: async (key, ...members) => {
            if (!mockSets[key]) mockSets[key] = new Set();
            let added = 0;
            for (let m of members) {
                if (!mockSets[key].has(m)) {
                    mockSets[key].add(m);
                    added++;
                }
            }
            return added;
        },
        scard: async key => (mockSets[key] ? mockSets[key].size : 0),
        srem: async (key, ...members) => {
            if (!mockSets[key]) return 0;
            let removed = 0;
            for (let m of members) {
                if (mockSets[key].delete(m)) removed++;
            }
            return removed;
        },
        del: async key => {
            let existed = 0;
            if (mockSets[key]) {
                delete mockSets[key];
                existed = 1;
            }
            if (mockRedisData[key]) {
                delete mockRedisData[key];
                existed = 1;
            }
            return existed;
        },
        exists: async () => 0,
        get: async () => null,
        set: async () => 'OK',
        ttl: async () => 3600,
        eval: async () => 1,
        scan: async () => ['0', []],
        quit: async () => {},
        disconnect: () => {},
        on: () => {},
        off: () => {},
        defineCommand: name => {
            redis[name] = async () => [1, null, 0];
        },
        duplicate: function () {
            return createMockRedis();
        }
    };
    return redis;
}

const mockRedis = createMockRedis();

const dbPath = require.resolve('../lib/db');
require.cache[dbPath] = {
    id: dbPath,
    filename: dbPath,
    loaded: true,
    parent: null,
    children: [],
    exports: {
        redis: mockRedis,
        queueConf: { connection: {} },
        notifyQueue: mockQueue,
        submitQueue: mockQueue,
        documentsQueue: mockQueue,
        exportQueue: mockQueue,
        getFlowProducer: () => ({}),
        REDIS_CONF: {},
        getRedisURL: () => 'redis://mock'
    }
};

const getSecretPath = require.resolve('../lib/get-secret');
require.cache[getSecretPath] = {
    id: getSecretPath,
    filename: getSecretPath,
    loaded: true,
    parent: null,
    children: [],
    exports: async () => null
};

// Replace the ioredfour distributed lock with an always-succeeding no-op so ensurePubsub/del run
// without a real Redis-backed lock.
const ioredfourPath = require.resolve('ioredfour');
require.cache[ioredfourPath] = {
    id: ioredfourPath,
    filename: ioredfourPath,
    loaded: true,
    parent: null,
    children: [],
    exports: class MockLock {
        async waitAcquireLock(key) {
            return { success: true, id: `mock-lock-${key}`, key };
        }
        async acquireLock(key) {
            return { success: true, id: `mock-lock-${key}`, key };
        }
        async releaseLock() {}
    }
};

// Now safe to import production modules
const msgpack = require('msgpack5')();
const { oauth2Apps } = require('../lib/oauth2-apps');
const settings = require('../lib/settings');
const { GMAIL_PUBSUB_DEFAULT_EXPIRATION_TTL } = require('../lib/consts');

// Deterministic: no Gmail subscription TTL override -> ensurePubsub leaves Google's default policy,
// so the "already exists" subscription path does not attempt a PATCH.
settings.get = async () => undefined;

const PROJECT = 'test-project';
const GMAIL_PUBLISHER = 'serviceAccount:gmail-api-push@system.gserviceaccount.com';
const PUBLISHER_ROLE = 'roles/pubsub.publisher';

const topicNameFor = id => `projects/${PROJECT}/topics/ee-pub-${id}`;
const subNameFor = id => `projects/${PROJECT}/subscriptions/ee-sub-${id}`;

// Seed an app record directly into the mocked store using the production key helpers.
function seedApp(id, extra) {
    let appData = Object.assign({ id, provider: 'gmailService', baseScopes: 'pubsub', googleProjectId: PROJECT }, extra || {});
    let dataKey = oauth2Apps.getDataKey();
    if (!mockRedisData[dataKey]) mockRedisData[dataKey] = {};
    mockRedisData[dataKey][`${id}:data`] = msgpack.encode(appData);
    let indexKey = oauth2Apps.getIndexKey();
    if (!mockSets[indexKey]) mockSets[indexKey] = new Set();
    mockSets[indexKey].add(id);
}

function notFoundError() {
    let err = new Error('Resource not found');
    err.oauthRequest = { response: { error: { code: 404, message: 'Resource not found' } } };
    return err;
}

function conflictError() {
    let err = new Error('Resource already exists');
    err.oauthRequest = { response: { error: { code: 409, message: 'Resource already exists' } } };
    return err;
}

// Build a fake Google API client. `cfg` may override topicGet / subGet / getIamPolicy handlers;
// PUT (create), setIamPolicy and DELETE are handled with sensible defaults. All calls are recorded.
function makeClient(cfg) {
    cfg = cfg || {};
    let calls = [];

    let defaults = {
        // "already exists" responses (adopt scenario)
        topicGet: () => ({ name: 'topic' }),
        subGet: () => ({ name: 'sub', expirationPolicy: { ttl: GMAIL_PUBSUB_DEFAULT_EXPIRATION_TTL } }),
        getIamPolicy: () => ({ bindings: [{ role: PUBLISHER_ROLE, members: [GMAIL_PUBLISHER] }], etag: 'etag-1' })
    };
    let handlers = Object.assign({}, defaults, cfg);

    return {
        calls,
        request: async (accessToken, url, method) => {
            calls.push({ url, method });

            if (url.endsWith(':getIamPolicy')) {
                return handlers.getIamPolicy();
            }
            if (url.endsWith(':setIamPolicy')) {
                return {};
            }

            let isSub = url.includes('/subscriptions/');

            switch (method) {
                case 'GET':
                    return isSub ? handlers.subGet() : handlers.topicGet();
                case 'PUT': {
                    // resource creation
                    let resourceName = url.split('/v1/')[1];
                    if (isSub) {
                        if (handlers.subPut) return handlers.subPut();
                        return { name: resourceName, expirationPolicy: { ttl: GMAIL_PUBSUB_DEFAULT_EXPIRATION_TTL } };
                    }
                    if (handlers.topicPut) return handlers.topicPut();
                    return { name: resourceName };
                }
                case 'DELETE':
                    return '';
                default:
                    return {};
            }
        }
    };
}

let currentClient = null;
oauth2Apps.getClient = async () => currentClient;
oauth2Apps.getServiceAccessToken = async () => 'mock-token';

const deleteCalls = client => client.calls.filter(c => c.method === 'DELETE');

// Run `fn` with the gmailSubscriptionTtl setting forced to `days`, restoring settings.get after.
async function withGmailTtl(days, fn) {
    let savedSettingsGet = settings.get;
    settings.get = async key => (key === 'gmailSubscriptionTtl' ? days : undefined);
    try {
        await fn();
    } finally {
        settings.get = savedSettingsGet;
    }
}

test('ensurePubsub marker persistence and ownership-aware deletion', async t => {
    t.beforeEach(() => {
        mockRedisData = {};
        mockSets = {};
        currentClient = null;
    });

    await t.test('adopts pre-existing topic/subscription/IAM and marks them unmanaged', async () => {
        let id = 'app-adopt';
        seedApp(id);
        currentClient = makeClient(); // all-exists defaults

        let results = await oauth2Apps.ensurePubsub(await oauth2Apps.get(id));

        let saved = await oauth2Apps.get(id);
        assert.equal(saved.pubSubTopic, topicNameFor(id));
        assert.equal(saved.pubSubTopicManaged, false);
        assert.equal(saved.pubSubSubscription, subNameFor(id));
        assert.equal(saved.pubSubSubscriptionManaged, false);
        assert.deepEqual(saved.pubSubIamPolicy, { members: [GMAIL_PUBLISHER], role: PUBLISHER_ROLE });

        // results signal the create/update route to (re)start the pull worker on first adoption
        assert.equal(results.pubSubTopic, topicNameFor(id));
        assert.equal(results.pubSubSubscription, subNameFor(id));
        assert.deepEqual(results.iamPolicy, { members: [GMAIL_PUBLISHER], role: PUBLISHER_ROLE });
    });

    await t.test('marks EmailEngine-created topic/subscription as managed', async () => {
        let id = 'app-create';
        seedApp(id);
        currentClient = makeClient({
            topicGet: () => {
                throw notFoundError();
            },
            subGet: () => {
                throw notFoundError();
            },
            getIamPolicy: () => ({ bindings: [], etag: 'etag-empty' })
        });

        await oauth2Apps.ensurePubsub(await oauth2Apps.get(id));

        let saved = await oauth2Apps.get(id);
        assert.equal(saved.pubSubTopic, topicNameFor(id));
        assert.equal(saved.pubSubTopicManaged, true);
        assert.equal(saved.pubSubSubscription, subNameFor(id));
        assert.equal(saved.pubSubSubscriptionManaged, true);
        assert.deepEqual(saved.pubSubIamPolicy, { members: [GMAIL_PUBLISHER], role: PUBLISHER_ROLE });
    });

    await t.test('adopts topic/subscription when creation races (PUT returns 409)', async () => {
        let id = 'app-race';
        seedApp(id);
        currentClient = makeClient({
            topicGet: () => {
                throw notFoundError();
            },
            subGet: () => {
                throw notFoundError();
            },
            topicPut: () => {
                throw conflictError();
            },
            subPut: () => {
                throw conflictError();
            }
        });

        await oauth2Apps.ensurePubsub(await oauth2Apps.get(id));

        let saved = await oauth2Apps.get(id);
        assert.equal(saved.pubSubTopic, topicNameFor(id));
        assert.equal(saved.pubSubTopicManaged, false, 'a raced (409) topic must be treated as unmanaged');
        assert.equal(saved.pubSubSubscription, subNameFor(id));
        assert.equal(saved.pubSubSubscriptionManaged, false, 'a raced (409) subscription must be treated as unmanaged');
    });

    await t.test('re-run with markers already present is a no-op (no spurious restart)', async () => {
        let id = 'app-idempotent';
        seedApp(id, {
            pubSubTopic: topicNameFor(id),
            pubSubTopicManaged: false,
            pubSubSubscription: subNameFor(id),
            pubSubSubscriptionManaged: false,
            pubSubIamPolicy: { members: [GMAIL_PUBLISHER], role: PUBLISHER_ROLE }
        });
        currentClient = makeClient(); // everything already exists

        let results = await oauth2Apps.ensurePubsub(await oauth2Apps.get(id));

        // No new keys -> applyPubSubUpdates would not trigger a pull-worker restart
        assert.equal(Object.keys(results).length, 0);

        // Ownership flags are preserved, not downgraded/overwritten
        let saved = await oauth2Apps.get(id);
        assert.equal(saved.pubSubTopicManaged, false);
        assert.equal(saved.pubSubSubscriptionManaged, false);
    });

    await t.test('does not rewrite the expiration policy of an adopted (unmanaged) subscription', async () => {
        let id = 'app-adopt-ttl';
        seedApp(id);
        // EmailEngine wants a 31-day expiration; the customer's pre-existing subscription is shorter.
        await withGmailTtl(31, async () => {
            currentClient = makeClient({
                subGet: () => ({ name: 'sub', expirationPolicy: { ttl: '604800s' } }) // 7 days
            });
            await oauth2Apps.ensurePubsub(await oauth2Apps.get(id));
        });

        assert.equal(currentClient.calls.filter(c => c.method === 'PATCH').length, 0, 'an adopted subscription must not be PATCHed');
        let saved = await oauth2Apps.get(id);
        assert.equal(saved.pubSubSubscriptionManaged, false);
    });

    await t.test('still rewrites the expiration policy of an EmailEngine-managed subscription', async () => {
        let id = 'app-managed-ttl';
        seedApp(id, {
            pubSubTopic: topicNameFor(id),
            pubSubTopicManaged: true,
            pubSubSubscription: subNameFor(id),
            pubSubSubscriptionManaged: true,
            pubSubIamPolicy: { members: [GMAIL_PUBLISHER], role: PUBLISHER_ROLE }
        });
        await withGmailTtl(31, async () => {
            currentClient = makeClient({
                subGet: () => ({ name: 'sub', expirationPolicy: { ttl: '604800s' } }) // 7 days, differs from desired
            });
            await oauth2Apps.ensurePubsub(await oauth2Apps.get(id));
        });

        assert.equal(currentClient.calls.filter(c => c.method === 'PATCH').length, 1, 'a managed subscription with a differing TTL must be PATCHed');
    });

    await t.test('deletion skips adopted (unmanaged) resources', async () => {
        let id = 'app-del-adopted';
        seedApp(id, {
            pubSubTopic: topicNameFor(id),
            pubSubTopicManaged: false,
            pubSubSubscription: subNameFor(id),
            pubSubSubscriptionManaged: false
        });
        currentClient = makeClient();

        await oauth2Apps.del(id);

        assert.equal(deleteCalls(currentClient).length, 0, 'must not delete user-provisioned GCP resources');
    });

    await t.test('deletion removes EmailEngine-managed resources', async () => {
        let id = 'app-del-managed';
        seedApp(id, {
            pubSubTopic: topicNameFor(id),
            pubSubTopicManaged: true,
            pubSubSubscription: subNameFor(id),
            pubSubSubscriptionManaged: true
        });
        currentClient = makeClient();

        await oauth2Apps.del(id);

        let dels = deleteCalls(currentClient);
        assert.equal(dels.length, 2);
        assert.ok(
            dels.some(c => c.url.includes('/subscriptions/')),
            'subscription should be deleted'
        );
        assert.ok(
            dels.some(c => c.url.includes('/topics/')),
            'topic should be deleted'
        );
    });

    await t.test('deletion of a legacy app (no ownership flags) still removes resources', async () => {
        let id = 'app-del-legacy';
        seedApp(id, {
            pubSubTopic: topicNameFor(id),
            pubSubSubscription: subNameFor(id)
            // no managed flags -> undefined -> treated as managed (preserves prior behavior)
        });
        currentClient = makeClient();

        await oauth2Apps.del(id);

        assert.equal(deleteCalls(currentClient).length, 2);
    });

    await t.test('mixed ownership: deletes the managed subscription but spares the adopted topic', async () => {
        let id = 'app-del-mixed';
        seedApp(id, {
            pubSubTopic: topicNameFor(id),
            pubSubTopicManaged: false, // adopted topic - must be spared
            pubSubSubscription: subNameFor(id),
            pubSubSubscriptionManaged: true // EmailEngine-created subscription - delete it
        });
        currentClient = makeClient();

        await oauth2Apps.del(id);

        let dels = deleteCalls(currentClient);
        assert.equal(dels.length, 1);
        assert.ok(dels[0].url.includes('/subscriptions/'));
        assert.ok(!dels.some(c => c.url.includes('/topics/')), 'adopted topic must not be deleted');
    });
});
