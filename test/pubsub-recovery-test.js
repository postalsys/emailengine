'use strict';

const test = require('node:test');
const assert = require('node:assert').strict;
// Mock Redis and BullMQ before any production imports
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
        hSetExists: async () => {},
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
        hincrby: async (key, field, increment) => {
            if (!mockRedisData[key]) mockRedisData[key] = {};
            let current = Number(mockRedisData[key][field]) || 0;
            current += increment;
            mockRedisData[key][field] = String(current);
            return current;
        },
        multi: () => {
            let ops = [];
            let chain = {
                exec: async () => {
                    let results = [];
                    for (let op of ops) {
                        try {
                            let result = await op();
                            results.push([null, result]);
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
                hset: function () {
                    ops.push(() => 0);
                    return this;
                },
                hdel: function () {
                    ops.push(() => 0);
                    return this;
                },
                del: function (key) {
                    ops.push(() => redis.del(key));
                    return this;
                },
                expire: function () {
                    ops.push(() => 0);
                    return this;
                },
                srem: function (key, ...members) {
                    ops.push(() => redis.srem(key, ...members));
                    return this;
                },
                scard: function (key) {
                    ops.push(() => redis.scard(key));
                    return this;
                },
                zadd: function () {
                    ops.push(() => 0);
                    return this;
                },
                hincrby: function () {
                    ops.push(() => 0);
                    return this;
                }
            };
            return chain;
        },
        ttl: async () => 3600,
        eval: async () => 1,
        smembers: async key => Array.from(mockSets[key] || []),
        sismember: async (key, member) => {
            if (!mockSets[key]) return 0;
            return mockSets[key].has(member) ? 1 : 0;
        },
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
        scard: async key => {
            if (!mockSets[key]) return 0;
            return mockSets[key].size;
        },
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
        scan: async () => ['0', []],
        quit: async () => {},
        disconnect: () => {},
        subscribe: () => {},
        on: () => {},
        off: () => {},
        defineCommand: () => {},
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

// Mock get-secret to return null (no encryption)
const getSecretPath = require.resolve('../lib/get-secret');
require.cache[getSecretPath] = {
    id: getSecretPath,
    filename: getSecretPath,
    loaded: true,
    parent: null,
    children: [],
    exports: async () => null
};

// Now safe to import production modules
const { PubSubInstance, GooglePubSub } = require('../lib/oauth/pubsub/google');
const { oauth2Apps } = require('../lib/oauth2-apps');
const msgpack = require('msgpack5')();
const { REDIS_PREFIX } = require('../lib/consts');

// Helper to create a mock 404 error matching the shape from lib/oauth/gmail.js
function create404Error() {
    let err = new Error('Subscription not found');
    err.statusCode = 404;
    err.oauthRequest = {
        response: {
            error: {
                code: 404,
                message: 'Resource not found'
            }
        }
    };
    return err;
}

function create403Error() {
    let err = new Error('Permission denied');
    err.statusCode = 403;
    err.oauthRequest = {
        response: {
            error: {
                code: 403,
                message: 'Permission denied'
            }
        }
    };
    return err;
}

function createTestInstance(overrides) {
    let instance = Object.create(PubSubInstance.prototype);
    Object.assign(
        instance,
        {
            app: 'test-app',
            stopped: false,
            recoveryAttempts: 0,
            lastRecoveryAttempt: 0,
            _hadPubSubFlag: true,
            _lastLoopError: null,
            parent: { getSubscribersKey: () => 'ee:oapp:sub', remove: () => {} },
            appData: { id: 'test-app', pubSubSubscription: 'projects/test/subscriptions/test-sub' },
            client: {
                request: async () => {
                    throw create404Error();
                }
            }
        },
        overrides
    );
    return instance;
}

const MOCKED_METHODS = ['ensurePubsub', 'setMeta', 'get', 'getClient', 'getServiceAccessToken'];

function withMockedOauth2Apps(mocks, fn) {
    let originals = {};
    for (let method of MOCKED_METHODS) {
        originals[method] = oauth2Apps[method];
    }
    // Default mocks
    oauth2Apps.setMeta = mocks.setMeta || (async () => {});
    oauth2Apps.ensurePubsub = mocks.ensurePubsub || (async () => {});
    oauth2Apps.get = mocks.get || (async () => ({ id: 'test-app', pubSubSubscription: 'projects/test/subscriptions/test-sub' }));
    oauth2Apps.getClient =
        mocks.getClient ||
        (async () => ({
            request: async () => {
                throw create404Error();
            }
        }));
    oauth2Apps.getServiceAccessToken = mocks.getServiceAccessToken || (async () => 'mock-token');
    // Apply explicit overrides
    for (let [key, val] of Object.entries(mocks)) {
        if (MOCKED_METHODS.includes(key)) {
            oauth2Apps[key] = val;
        }
    }
    return async () => {
        try {
            await fn();
        } finally {
            for (let method of MOCKED_METHODS) {
                oauth2Apps[method] = originals[method];
            }
        }
    };
}

test('Pub/Sub subscription recovery tests', async t => {
    t.after(() => {
        setTimeout(() => process.exit(), 1000).unref();
    });

    t.beforeEach(() => {
        mockRedisData = {};
        mockSets = {};
        // Existing tests use 'ee:oapp:sub' as the subscriber key (from createTestInstance parent mock).
        // run() checks sismember for the app before proceeding, so populate the set.
        mockSets['ee:oapp:sub'] = new Set(['test-app']);
    });

    await t.test('pull loop detects 404 and calls ensurePubsub to recover', async () => {
        let ensurePubsubCalls = [];
        let setMetaCalls = [];

        await withMockedOauth2Apps(
            {
                ensurePubsub: async appData => {
                    ensurePubsubCalls.push(appData);
                },
                setMeta: async (id, meta) => {
                    setMetaCalls.push({ id, meta });
                }
            },
            async () => {
                let instance = createTestInstance();

                // run() should catch 404, call ensurePubsub, and return (not throw)
                await instance.run();

                assert.strictEqual(ensurePubsubCalls.length, 1, 'ensurePubsub should be called once');
                assert.strictEqual(ensurePubsubCalls[0].id, 'test-app');

                // setMeta should be called to clear pubSubFlag
                let clearCall = setMetaCalls.find(c => c.meta && c.meta.pubSubFlag === null);
                assert.ok(clearCall, 'setMeta should be called with pubSubFlag: null');

                assert.strictEqual(instance.recoveryAttempts, 0, 'recoveryAttempts should be reset to 0 after success');
            }
        )();
    });

    await t.test('recovery uses exponential backoff on repeated failures', async () => {
        let ensurePubsubCalls = [];

        await withMockedOauth2Apps(
            {
                ensurePubsub: async () => {
                    ensurePubsubCalls.push(Date.now());
                    throw new Error('GCP permission error');
                }
            },
            async () => {
                let instance = createTestInstance();

                // First call: ensurePubsub fails, should throw the recovery error
                await assert.rejects(() => instance.run(), /GCP permission error/);
                assert.strictEqual(instance.recoveryAttempts, 1);
                assert.strictEqual(ensurePubsubCalls.length, 1);

                // Second call immediately: should skip recovery due to backoff and throw with retryDelay
                let backoffErr;
                try {
                    await instance.run();
                } catch (err) {
                    backoffErr = err;
                }
                assert.ok(backoffErr, 'should throw during backoff');
                assert.match(backoffErr.message, /Subscription not found/);
                assert.ok(typeof backoffErr.retryDelay === 'number' && backoffErr.retryDelay > 0, 'backoff error should include retryDelay');
                // ensurePubsub should NOT be called again (backoff not elapsed)
                assert.strictEqual(ensurePubsubCalls.length, 1, 'ensurePubsub should not be called during backoff');
            }
        )();
    });

    await t.test('pull loop falls through on non-404 errors', async () => {
        let ensurePubsubCalls = [];

        await withMockedOauth2Apps(
            {
                ensurePubsub: async () => {
                    ensurePubsubCalls.push(Date.now());
                },
                getClient: async () => ({
                    request: async () => {
                        throw create403Error();
                    }
                })
            },
            async () => {
                let instance = createTestInstance({
                    client: {
                        request: async () => {
                            throw create403Error();
                        }
                    }
                });

                // 403 should throw without calling ensurePubsub
                await assert.rejects(() => instance.run(), /Permission denied/);
                assert.strictEqual(ensurePubsubCalls.length, 0, 'ensurePubsub should not be called for non-404 errors');
            }
        )();
    });

    await t.test('successful pull after recovery clears error state', async () => {
        let setMetaCalls = [];
        let pullCount = 0;

        // Client that fails first call with 404, then succeeds
        let mockClient = {
            request: async () => {
                pullCount++;
                if (pullCount === 1) {
                    throw create404Error();
                }
                return { receivedMessages: [] };
            }
        };

        await withMockedOauth2Apps(
            {
                setMeta: async (id, meta) => {
                    setMetaCalls.push({ id, meta });
                },
                getClient: async () => mockClient
            },
            async () => {
                let instance = createTestInstance({ client: mockClient });

                // First run: 404 -> recovery clears pubSubFlag
                await instance.run();

                // Recovery should have cleared pubSubFlag
                let clearCall = setMetaCalls.find(c => c.meta && c.meta.pubSubFlag === null);
                assert.ok(clearCall, 'recovery should clear pubSubFlag');

                // Second run: successful pull should NOT call setMeta (no-op optimization)
                setMetaCalls = [];
                await instance.run();

                let redundantClear = setMetaCalls.find(c => c.meta && c.meta.pubSubFlag === null);
                assert.ok(!redundantClear, 'setMeta should not be called redundantly on successful pull when flag is already clear');
            }
        )();
    });

    // --- backfillPubSubApps tests ---

    await t.test('backfillPubSubApps tests', async t2 => {
        let subscribersKey = `${REDIS_PREFIX}oapp:sub`;
        let indexKey = `${REDIS_PREFIX}oapp:i`;
        let dataKey = `${REDIS_PREFIX}oapp:c`;

        t2.beforeEach(() => {
            mockRedisData = {};
            mockSets = {};
            oauth2Apps._pubSubBackfillDone = false;
            oauth2Apps._pubSubBackfillPromise = null;
        });

        await t2.test('no missing apps returns existing subscribers', async () => {
            mockSets[subscribersKey] = new Set(['app1', 'app2']);
            mockSets[indexKey] = new Set(['app1', 'app2']);

            let result = await oauth2Apps.backfillPubSubApps();
            assert.deepStrictEqual(result.sort(), ['app1', 'app2']);
            assert.ok(oauth2Apps._pubSubBackfillDone, '_pubSubBackfillDone should be true');
        });

        await t2.test('missing pubsub app gets backfilled into subscriber set', async () => {
            mockSets[subscribersKey] = new Set(['app1']);
            mockSets[indexKey] = new Set(['app1', 'app2']);
            mockRedisData[dataKey] = {
                'app2:data': msgpack.encode({ id: 'app2', baseScopes: 'pubsub', provider: 'gmailService' })
            };

            let result = await oauth2Apps.backfillPubSubApps();
            assert.ok(result.includes('app1'), 'existing subscriber should be in result');
            assert.ok(result.includes('app2'), 'backfilled app should be in result');
            assert.ok(mockSets[subscribersKey].has('app2'), 'app2 should be added to subscriber set');
        });

        await t2.test('non-pubsub app is not backfilled', async () => {
            mockSets[subscribersKey] = new Set();
            mockSets[indexKey] = new Set(['app1']);
            mockRedisData[dataKey] = {
                'app1:data': msgpack.encode({ id: 'app1', baseScopes: 'api', provider: 'gmail' })
            };

            let result = await oauth2Apps.backfillPubSubApps();
            assert.strictEqual(result.length, 0, 'non-pubsub app should not be in result');
            assert.ok(!mockSets[subscribersKey] || !mockSets[subscribersKey].has('app1'), 'app1 should not be in subscriber set');
        });

        await t2.test('corrupt data buffer is skipped gracefully', async () => {
            mockSets[subscribersKey] = new Set();
            mockSets[indexKey] = new Set(['corrupt-app', 'valid-app']);
            mockRedisData[dataKey] = {
                'corrupt-app:data': Buffer.from('not-valid-msgpack'),
                'valid-app:data': msgpack.encode({ id: 'valid-app', baseScopes: 'pubsub' })
            };

            let result = await oauth2Apps.backfillPubSubApps();
            assert.ok(result.includes('valid-app'), 'valid pubsub app should be backfilled');
            assert.ok(!result.includes('corrupt-app'), 'corrupt app should not be in result');
        });

        await t2.test('null buffer entry is skipped', async () => {
            mockSets[subscribersKey] = new Set();
            mockSets[indexKey] = new Set(['ghost-app']);
            // No data entry for ghost-app in mockRedisData

            let result = await oauth2Apps.backfillPubSubApps();
            assert.strictEqual(result.length, 0, 'app with no data should not be backfilled');
        });

        await t2.test('second call uses cached path', async () => {
            mockSets[subscribersKey] = new Set(['app1']);
            mockSets[indexKey] = new Set(['app1']);

            await oauth2Apps.backfillPubSubApps();
            assert.ok(oauth2Apps._pubSubBackfillDone, 'backfill should be marked done');

            // Add a new app to the subscriber set directly (simulating external change)
            mockSets[subscribersKey].add('app-new');

            let result2 = await oauth2Apps.backfillPubSubApps();
            // Second call uses smembers fast path, should see the new app
            assert.ok(result2.includes('app-new'), 'cached path should return fresh smembers');
        });

        await t2.test('concurrent calls share the same promise', async () => {
            let indexSmembersCalls = 0;
            let origSmembers = mockRedis.smembers;
            mockRedis.smembers = async key => {
                if (key === indexKey) {
                    indexSmembersCalls++;
                }
                return Array.from(mockSets[key] || []);
            };

            try {
                mockSets[subscribersKey] = new Set();
                mockSets[indexKey] = new Set(['app1']);
                mockRedisData[dataKey] = {
                    'app1:data': msgpack.encode({ id: 'app1', baseScopes: 'pubsub' })
                };

                let [result1, result2] = await Promise.all([oauth2Apps.backfillPubSubApps(), oauth2Apps.backfillPubSubApps()]);

                assert.strictEqual(indexSmembersCalls, 1, 'index smembers should be called only once (shared promise)');
                assert.deepStrictEqual(result1, result2, 'both calls should return the same result');
            } finally {
                mockRedis.smembers = origSmembers;
            }
        });

        await t2.test('promise is cleared after completion', async () => {
            mockSets[subscribersKey] = new Set();
            mockSets[indexKey] = new Set();

            await oauth2Apps.backfillPubSubApps();
            assert.strictEqual(oauth2Apps._pubSubBackfillPromise, null, 'promise should be null after completion');
            assert.ok(oauth2Apps._pubSubBackfillDone, 'backfill should be marked done');
        });
    });

    // --- Pre-pull subscription check tests ---

    await t.test('pre-pull subscription check tests', async t2 => {
        t2.beforeEach(() => {
            mockRedisData = {};
            mockSets = {};
            mockSets['ee:oapp:sub'] = new Set(['test-app']);
        });

        await t2.test('missing pubSubSubscription triggers recovery', async () => {
            let ensurePubsubCalls = [];
            let setMetaCalls = [];
            let clientRequestCalls = 0;

            await withMockedOauth2Apps(
                {
                    ensurePubsub: async appData => {
                        ensurePubsubCalls.push(appData);
                    },
                    setMeta: async (id, meta) => {
                        setMetaCalls.push({ id, meta });
                    },
                    // get() always returns app without pubSubSubscription
                    get: async () => ({ id: 'test-app' })
                },
                async () => {
                    let instance = createTestInstance({
                        appData: { id: 'test-app' },
                        client: {
                            request: async () => {
                                clientRequestCalls++;
                                return { receivedMessages: [] };
                            }
                        }
                    });

                    await instance.run();

                    assert.strictEqual(ensurePubsubCalls.length, 1, 'ensurePubsub should be called for missing subscription');
                    assert.strictEqual(clientRequestCalls, 0, 'pull should not be attempted when subscription is missing');
                    assert.strictEqual(instance.recoveryAttempts, 0, 'recoveryAttempts should be reset after successful recovery');
                }
            )();
        });

        await t2.test('missing on cache but present after forced refresh skips recovery', async () => {
            let ensurePubsubCalls = [];
            let clientRequestCalls = 0;

            await withMockedOauth2Apps(
                {
                    ensurePubsub: async appData => {
                        ensurePubsubCalls.push(appData);
                    },
                    setMeta: async () => {},
                    // getApp(false) uses cached this.appData (does not call get()),
                    // getApp(true) calls get() -- return subscription present
                    get: async () => ({ id: 'test-app', pubSubSubscription: 'projects/test/subscriptions/test-sub' })
                },
                async () => {
                    // Instance starts with no pubSubSubscription in cached appData
                    let instance = createTestInstance({
                        appData: { id: 'test-app' },
                        client: {
                            request: async () => {
                                clientRequestCalls++;
                                return { receivedMessages: [] };
                            }
                        }
                    });

                    await instance.run();

                    assert.strictEqual(ensurePubsubCalls.length, 0, 'ensurePubsub should NOT be called when refresh finds subscription');
                    assert.ok(clientRequestCalls > 0, 'pull should proceed when subscription is found after refresh');
                }
            )();
        });

        await t2.test('missing subscription respects backoff on repeated recovery failures', async () => {
            let ensurePubsubCalls = [];

            await withMockedOauth2Apps(
                {
                    ensurePubsub: async () => {
                        ensurePubsubCalls.push(Date.now());
                        throw new Error('Setup failed');
                    },
                    get: async () => ({ id: 'test-app' })
                },
                async () => {
                    let instance = createTestInstance({
                        appData: { id: 'test-app' }
                    });

                    // First call: recovery attempted, fails
                    await assert.rejects(() => instance.run(), /Setup failed/);
                    assert.strictEqual(ensurePubsubCalls.length, 1);
                    assert.strictEqual(instance.recoveryAttempts, 1);

                    // Second immediate call: backoff should skip recovery
                    await assert.rejects(() => instance.run(), /Subscription not configured/);
                    assert.strictEqual(ensurePubsubCalls.length, 1, 'ensurePubsub should not be called during backoff');
                }
            )();
        });
    });

    // --- create/update subscriber set tests ---

    await t.test('create/update subscriber set tests', async t2 => {
        let subscribersKey = `${REDIS_PREFIX}oapp:sub`;

        t2.beforeEach(() => {
            mockRedisData = {};
            mockSets = {};
        });

        await t2.test('create() with baseScopes pubsub adds to subscriber set', async () => {
            await withMockedOauth2Apps(
                {
                    ensurePubsub: async () => ({}),
                    get: async id => ({ id, baseScopes: 'pubsub', provider: 'gmailService' })
                },
                async () => {
                    let result = await oauth2Apps.create({ provider: 'gmailService', baseScopes: 'pubsub' });
                    assert.ok(result.id, 'should return generated id');
                    assert.ok(mockSets[subscribersKey] && mockSets[subscribersKey].has(result.id), 'id should be in subscriber set');
                }
            )();
        });

        await t2.test('create() without pubsub scope does not add to subscriber set', async () => {
            await withMockedOauth2Apps(
                {
                    ensurePubsub: async () => ({}),
                    get: async id => ({ id, baseScopes: 'api', provider: 'gmail' })
                },
                async () => {
                    let result = await oauth2Apps.create({ provider: 'gmail', baseScopes: 'api' });
                    assert.ok(result.id, 'should return generated id');
                    assert.ok(!mockSets[subscribersKey] || !mockSets[subscribersKey].has(result.id), 'id should NOT be in subscriber set');
                }
            )();
        });

        await t2.test('update() with existing baseScopes pubsub adds to subscriber set', async () => {
            let appId = 'existing-app';
            let dataKey = `${REDIS_PREFIX}oapp:c`;
            // Pre-populate app data in Redis
            mockRedisData[dataKey] = {
                [`${appId}:data`]: msgpack.encode({ id: appId, baseScopes: 'pubsub', provider: 'gmailService', created: new Date().toISOString() })
            };
            mockSets[`${REDIS_PREFIX}oapp:i`] = new Set([appId]);

            await withMockedOauth2Apps(
                {
                    ensurePubsub: async () => ({}),
                    get: async () => ({ id: appId, baseScopes: 'pubsub', provider: 'gmailService' })
                },
                async () => {
                    let result = await oauth2Apps.update(appId, { googleProjectId: 'new-proj' });
                    assert.ok(result.updated, 'should return updated: true');
                    assert.ok(mockSets[subscribersKey] && mockSets[subscribersKey].has(appId), 'id should be in subscriber set');
                }
            )();
        });
    });

    // --- stopAll() and instance lifecycle tests ---

    await t.test('stopAll() and instance lifecycle tests', async t2 => {
        await t2.test('stopAll() clears all instances safely', async () => {
            let pubsub = new GooglePubSub({ call: async () => {} });
            // Manually add instances without triggering constructor side effects
            for (let id of ['app-a', 'app-b', 'app-c']) {
                let instance = Object.create(PubSubInstance.prototype);
                Object.assign(instance, {
                    app: id,
                    stopped: false,
                    _loopTimer: null,
                    _immediateHandle: null,
                    _abortController: null
                });
                pubsub.pubSubInstances.set(id, instance);
            }

            assert.strictEqual(pubsub.pubSubInstances.size, 3, 'should have 3 instances');
            pubsub.stopAll();
            assert.strictEqual(pubsub.pubSubInstances.size, 0, 'all instances should be removed');
        });

        await t2.test('stopAll() sets stopped flag on all instances', async () => {
            let pubsub = new GooglePubSub({ call: async () => {} });
            let instances = [];
            for (let id of ['app-x', 'app-y']) {
                let instance = Object.create(PubSubInstance.prototype);
                Object.assign(instance, {
                    app: id,
                    stopped: false,
                    _loopTimer: null,
                    _immediateHandle: null,
                    _abortController: null
                });
                pubsub.pubSubInstances.set(id, instance);
                instances.push(instance);
            }

            pubsub.stopAll();
            for (let inst of instances) {
                assert.strictEqual(inst.stopped, true, 'instance should be stopped');
            }
        });

        await t2.test('remove() clears immediate handle', async () => {
            let pubsub = new GooglePubSub({ call: async () => {} });
            let instance = Object.create(PubSubInstance.prototype);
            Object.assign(instance, {
                app: 'imm-test',
                stopped: false,
                _loopTimer: null,
                _immediateHandle: setImmediate(() => {}),
                _abortController: null
            });
            pubsub.pubSubInstances.set('imm-test', instance);

            pubsub.remove('imm-test');
            assert.strictEqual(instance.stopped, true, 'instance should be stopped');
            assert.strictEqual(pubsub.pubSubInstances.size, 0, 'instance should be removed from map');
        });

        await t2.test('update() replaces existing instance with a fresh one', async () => {
            let pubsub = new GooglePubSub({ call: async () => {} });
            await pubsub.update('refresh-test');
            let firstInstance = pubsub.pubSubInstances.get('refresh-test');
            assert.ok(firstInstance, 'instance should exist after first update');

            await pubsub.update('refresh-test');
            let secondInstance = pubsub.pubSubInstances.get('refresh-test');
            assert.ok(secondInstance, 'instance should exist after second update');
            assert.notStrictEqual(firstInstance, secondInstance, 'instance should be a new object');
            assert.strictEqual(firstInstance.stopped, true, 'old instance should be stopped');
            assert.strictEqual(secondInstance.stopped, false, 'new instance should not be stopped');
            assert.strictEqual(pubsub.pubSubInstances.size, 1, 'map should still have exactly one entry');

            pubsub.stopAll();
        });
    });

    // --- _recoveryBackoffMs() tests ---

    await t.test('_recoveryBackoffMs() returns expected values', async t2 => {
        await t2.test('backoff at 0 attempts is 3000ms', () => {
            let instance = createTestInstance({ recoveryAttempts: 0 });
            assert.strictEqual(instance._recoveryBackoffMs(), 3000);
        });

        await t2.test('backoff at 1 attempt is 6000ms', () => {
            let instance = createTestInstance({ recoveryAttempts: 1 });
            assert.strictEqual(instance._recoveryBackoffMs(), 6000);
        });

        await t2.test('backoff at 5 attempts is 96000ms', () => {
            let instance = createTestInstance({ recoveryAttempts: 5 });
            assert.strictEqual(instance._recoveryBackoffMs(), 96000);
        });

        await t2.test('backoff caps at 300000ms (5 minutes)', () => {
            let instance = createTestInstance({ recoveryAttempts: 20 });
            assert.strictEqual(instance._recoveryBackoffMs(), 300000);
        });

        await t2.test('backoff stays capped beyond 20 attempts', () => {
            let instance = createTestInstance({ recoveryAttempts: 25 });
            assert.strictEqual(instance._recoveryBackoffMs(), 300000);
        });
    });

    // --- del() subscriber cleanup tests ---

    await t.test('del() subscriber cleanup tests', async t2 => {
        let subscribersKey = `${REDIS_PREFIX}oapp:sub`;
        let indexKey = `${REDIS_PREFIX}oapp:i`;
        let dataKey = `${REDIS_PREFIX}oapp:c`;

        t2.beforeEach(() => {
            mockRedisData = {};
            mockSets = {};
        });

        await t2.test('del() removes app from subscriber set and pubsub app set', async () => {
            let appId = 'del-test-app';
            let pubSubAppId = 'parent-pubsub-app';
            let pubsubAppKey = `${REDIS_PREFIX}oapp:pub:${pubSubAppId}`;
            let appFields = { id: appId, baseScopes: 'pubsub', provider: 'gmailService', pubSubApp: pubSubAppId };

            mockSets[indexKey] = new Set([appId]);
            mockSets[subscribersKey] = new Set([appId]);
            mockSets[pubsubAppKey] = new Set([appId]);
            mockRedisData[dataKey] = { [`${appId}:data`]: msgpack.encode(appFields) };

            await withMockedOauth2Apps({ get: async () => ({ ...appFields }) }, async () => {
                let result = await oauth2Apps.del(appId);
                assert.strictEqual(result.id, appId, 'should return correct id');
                assert.ok(!mockSets[subscribersKey] || !mockSets[subscribersKey].has(appId), 'app should be removed from subscriber set');
                assert.ok(!mockSets[pubsubAppKey] || !mockSets[pubsubAppKey].has(appId), 'app should be removed from pubsub app set');
            })();
        });

        await t2.test('del() deletes oapp:pub:{id} set when app has baseScopes pubsub', async () => {
            let appId = 'del-pubsub-provider';
            let pubsubAppKey = `${REDIS_PREFIX}oapp:pub:${appId}`;
            let appFields = { id: appId, baseScopes: 'pubsub', provider: 'gmailService' };

            mockSets[indexKey] = new Set([appId]);
            mockSets[subscribersKey] = new Set([appId]);
            mockSets[pubsubAppKey] = new Set(['subscriber-1', 'subscriber-2']);
            mockRedisData[dataKey] = { [`${appId}:data`]: msgpack.encode(appFields) };

            await withMockedOauth2Apps({ get: async () => ({ ...appFields }) }, async () => {
                let result = await oauth2Apps.del(appId);
                assert.strictEqual(result.id, appId, 'should return correct id');
                assert.ok(!mockSets[subscribersKey] || !mockSets[subscribersKey].has(appId), 'app should be removed from subscriber set');
                assert.ok(!mockSets[pubsubAppKey], 'oapp:pub:{id} set should be deleted');
            })();
        });

        await t2.test('del() without pubSubApp skips pubsub app set removal', async () => {
            let appId = 'del-no-pubsub-app';
            let appFields = { id: appId, baseScopes: 'api', provider: 'gmail' };

            mockSets[indexKey] = new Set([appId]);
            mockSets[subscribersKey] = new Set([appId]);
            mockRedisData[dataKey] = { [`${appId}:data`]: msgpack.encode(appFields) };

            await withMockedOauth2Apps({ get: async () => ({ ...appFields }) }, async () => {
                let result = await oauth2Apps.del(appId);
                assert.strictEqual(result.id, appId, 'should return correct id');
                assert.ok(!mockSets[subscribersKey] || !mockSets[subscribersKey].has(appId), 'app should be removed from subscriber set');
            })();
        });
    });

    // --- remove() synchronous behavior tests ---

    await t.test('remove() synchronous behavior tests', async t2 => {
        await t2.test('remove() returns undefined, not a Promise', () => {
            let pubsub = new GooglePubSub({ call: async () => {} });
            let instance = Object.create(PubSubInstance.prototype);
            Object.assign(instance, {
                app: 'sync-test',
                stopped: false,
                _loopTimer: null,
                _immediateHandle: null,
                _abortController: null
            });
            pubsub.pubSubInstances.set('sync-test', instance);

            let result = pubsub.remove('sync-test');
            assert.strictEqual(result, undefined, 'remove() should return undefined, not a Promise');
        });

        await t2.test('remove() is a no-op for unknown app', () => {
            let pubsub = new GooglePubSub({ call: async () => {} });
            pubsub.remove('nonexistent');
            assert.strictEqual(pubsub.pubSubInstances.size, 0, 'map should remain empty');
        });

        await t2.test('remove() aborts active AbortController', () => {
            let pubsub = new GooglePubSub({ call: async () => {} });
            let abortController = new AbortController();
            let instance = Object.create(PubSubInstance.prototype);
            Object.assign(instance, {
                app: 'abort-test',
                stopped: false,
                _loopTimer: null,
                _immediateHandle: null,
                _abortController: abortController
            });
            pubsub.pubSubInstances.set('abort-test', instance);

            pubsub.remove('abort-test');
            assert.strictEqual(abortController.signal.aborted, true, 'AbortController should be aborted');
        });
    });

    // --- setMeta isolation in run() ---

    await t.test('setMeta failure after successful pull does not throw', async t2 => {
        await t2.test('setMeta error is caught and _hadPubSubFlag stays true for retry', async () => {
            let setMetaCallCount = 0;

            await withMockedOauth2Apps(
                {
                    setMeta: async () => {
                        setMetaCallCount++;
                        throw new Error('Redis connection lost');
                    },
                    getServiceAccessToken: async () => 'mock-token'
                },
                async () => {
                    let instance = createTestInstance({
                        _hadPubSubFlag: true,
                        client: {
                            request: async () => ({ receivedMessages: [] })
                        }
                    });

                    // Simulate app exists in subscriber set
                    mockSets[`${REDIS_PREFIX}oapp:sub`] = new Set(['test-app']);

                    // Should not throw despite setMeta failure
                    await instance.run();
                    assert.strictEqual(setMetaCallCount, 1, 'setMeta should have been called once');
                    assert.strictEqual(instance._hadPubSubFlag, true, '_hadPubSubFlag should remain true for retry');
                }
            )();
        });
    });

    // --- attemptRecovery stopped checks ---

    await t.test('attemptRecovery respects stopped flag', async t2 => {
        await t2.test('attemptRecovery returns early when stopped is set before start', async () => {
            let ensurePubsubCalls = 0;

            await withMockedOauth2Apps(
                {
                    ensurePubsub: async () => {
                        ensurePubsubCalls++;
                    },
                    get: async () => ({ id: 'test-app', pubSubSubscription: 'projects/test/subscriptions/test-sub' })
                },
                async () => {
                    let instance = createTestInstance({ recoveryAttempts: 0, lastRecoveryAttempt: 0 });
                    instance.stopped = true;

                    await instance.attemptRecovery('test reason');
                    assert.strictEqual(ensurePubsubCalls, 0, 'ensurePubsub should not be called when stopped');
                }
            )();
        });

        await t2.test('attemptRecovery returns early when stopped during recovery', async () => {
            let setMetaCalls = 0;

            await withMockedOauth2Apps(
                {
                    ensurePubsub: async function () {
                        // Simulate being stopped during recovery
                        this._instance.stopped = true;
                    },
                    get: async () => ({ id: 'test-app', pubSubSubscription: 'projects/test/subscriptions/test-sub' }),
                    getClient: async () => ({ request: async () => {} }),
                    setMeta: async () => {
                        setMetaCalls++;
                    }
                },
                async () => {
                    let instance = createTestInstance({ recoveryAttempts: 0, lastRecoveryAttempt: 0 });

                    // Patch ensurePubsub to set stopped on the correct instance
                    let origEnsurePubsub = oauth2Apps.ensurePubsub;
                    oauth2Apps.ensurePubsub = async () => {
                        instance.stopped = true;
                    };

                    await instance.attemptRecovery('test reason');
                    assert.strictEqual(setMetaCalls, 0, 'setMeta should not be called after stopped during recovery');

                    oauth2Apps.ensurePubsub = origEnsurePubsub;
                }
            )();
        });
    });

    // --- per-batch access token test ---

    await t.test('ACK reuses batch-level access token', async t2 => {
        await t2.test('getServiceAccessToken is called once for pull, not per-message ACK', async () => {
            let tokenCallCount = 0;

            await withMockedOauth2Apps(
                {
                    getServiceAccessToken: async () => {
                        tokenCallCount++;
                        return 'mock-token';
                    }
                },
                async () => {
                    let ackCount = 0;
                    let instance = createTestInstance({
                        client: {
                            request: async (token, url) => {
                                if (url.includes(':pull')) {
                                    return {
                                        receivedMessages: [
                                            { message: { messageId: 'msg-1', data: '' }, ackId: 'ack-1' },
                                            { message: { messageId: 'msg-2', data: '' }, ackId: 'ack-2' },
                                            { message: { messageId: 'msg-3', data: '' }, ackId: 'ack-3' }
                                        ]
                                    };
                                }
                                if (url.includes(':acknowledge')) {
                                    ackCount++;
                                    return '';
                                }
                            }
                        }
                    });

                    mockSets[`${REDIS_PREFIX}oapp:sub`] = new Set(['test-app']);

                    await instance.run();
                    assert.strictEqual(ackCount, 3, 'should have ACKed all 3 messages');
                    // getServiceAccessToken called once for getAccessToken() before pull,
                    // plus once inside getClient(). Should NOT be called per-message.
                    assert.ok(tokenCallCount <= 2, `getServiceAccessToken should be called at most twice, got ${tokenCallCount}`);
                }
            )();
        });
    });
});
