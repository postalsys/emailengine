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
        defineCommand: name => {
            redis[name] = async () => [1, null, 0];
        },
        pipeline: () => {
            let pipeOps = [];
            let pipeChain = new Proxy(
                {
                    exec: async () => {
                        let results = [];
                        for (let op of pipeOps) {
                            try {
                                let result = await op();
                                results.push([null, result]);
                            } catch (err) {
                                results.push([err, null]);
                            }
                        }
                        return results;
                    }
                },
                {
                    get(target, prop) {
                        if (prop in target) return target[prop];
                        return function (...args) {
                            if (typeof redis[prop] === 'function') {
                                pipeOps.push(() => redis[prop](...args));
                            } else {
                                pipeOps.push(() => 0);
                            }
                            return pipeChain;
                        };
                    }
                }
            );
            return pipeChain;
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

function create401Error() {
    let err = new Error('Unauthorized');
    err.statusCode = 401;
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

function create429Error(retryAfterSec) {
    let err = new Error('Rate limited');
    err.statusCode = 429;
    err.oauthRequest = {
        response: {
            error: {
                code: 429,
                message: 'Rate limited'
            }
        }
    };
    if (retryAfterSec != null) {
        err.retryAfter = retryAfterSec;
        err.oauthRequest.retryAfter = retryAfterSec;
    }
    return err;
}

function createTestInstance(overrides) {
    let defaults = {
        app: 'test-app',
        stopped: false,
        _hadPubSubFlag: true,
        _lastLoopError: null,
        _consecutiveErrors: 0,
        _loopTimer: null,
        _immediateHandle: null,
        _abortController: null,
        parent: { getSubscribersKey: () => 'ee:oapp:sub', remove: () => {} },
        appData: { id: 'test-app', pubSubSubscription: 'projects/test/subscriptions/test-sub' },
        client: {
            request: async () => {
                throw create404Error();
            }
        }
    };
    let instance = Object.create(PubSubInstance.prototype);
    Object.assign(instance, defaults, overrides);
    return instance;
}

const MOCKED_METHODS = ['ensurePubsub', 'setMeta', 'get', 'getClient', 'getServiceAccessToken'];

function withMockedOauth2Apps(mocks, fn) {
    let originals = {};
    for (let method of MOCKED_METHODS) {
        originals[method] = oauth2Apps[method];
    }

    // Apply defaults, then override with any provided mocks
    let defaults = {
        setMeta: async () => {},
        ensurePubsub: async () => {},
        get: async () => ({ id: 'test-app', pubSubSubscription: 'projects/test/subscriptions/test-sub' }),
        getClient: async () => ({
            request: async () => {
                throw create404Error();
            }
        }),
        getServiceAccessToken: async () => 'mock-token'
    };
    for (let method of MOCKED_METHODS) {
        oauth2Apps[method] = mocks[method] || defaults[method];
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
            }
        )();
    });

    await t.test('recovery failure propagates error to caller', async () => {
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

                // ensurePubsub fails, error should propagate to caller (startLoop handles backoff)
                await assert.rejects(() => instance.run(), /GCP permission error/);
                assert.strictEqual(ensurePubsubCalls.length, 1);
            }
        )();
    });

    await t.test('403 error sets pubSubFlag and throws without calling ensurePubsub', async () => {
        let ensurePubsubCalls = [];
        let setMetaCalls = [];

        await withMockedOauth2Apps(
            {
                ensurePubsub: async () => {
                    ensurePubsubCalls.push(Date.now());
                },
                setMeta: async (id, meta) => {
                    setMetaCalls.push({ id, meta });
                }
            },
            async () => {
                let instance = createTestInstance({
                    _hadPubSubFlag: false,
                    client: {
                        request: async () => {
                            throw create403Error();
                        }
                    }
                });

                // 403 should throw without calling attemptRecovery/ensurePubsub
                await assert.rejects(() => instance.run(), { statusCode: 403 });
                assert.strictEqual(ensurePubsubCalls.length, 0, 'ensurePubsub should NOT be called for 403 errors');
                assert.ok(
                    setMetaCalls.some(c => c.meta.pubSubFlag !== undefined && c.meta.pubSubFlag !== null),
                    'pubSubFlag should be set for 403 errors'
                );
            }
        )();
    });

    await t.test('401 error sets pubSubFlag and throws without calling ensurePubsub', async () => {
        let ensurePubsubCalls = [];
        let setMetaCalls = [];

        await withMockedOauth2Apps(
            {
                ensurePubsub: async () => {
                    ensurePubsubCalls.push(Date.now());
                },
                setMeta: async (id, meta) => {
                    setMetaCalls.push({ id, meta });
                }
            },
            async () => {
                let instance = createTestInstance({
                    _hadPubSubFlag: false,
                    client: {
                        request: async () => {
                            throw create401Error();
                        }
                    }
                });

                // 401 should throw without calling attemptRecovery/ensurePubsub
                await assert.rejects(() => instance.run(), { statusCode: 401 });
                assert.strictEqual(ensurePubsubCalls.length, 0, 'ensurePubsub should NOT be called for 401 errors');
                assert.ok(
                    setMetaCalls.some(c => c.meta.pubSubFlag !== undefined && c.meta.pubSubFlag !== null),
                    'pubSubFlag should be set for 401 errors'
                );
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

            let subscriptionCreated = false;
            await withMockedOauth2Apps(
                {
                    ensurePubsub: async appData => {
                        ensurePubsubCalls.push(appData);
                        subscriptionCreated = true;
                    },
                    setMeta: async (id, meta) => {
                        setMetaCalls.push({ id, meta });
                    },
                    // After ensurePubsub succeeds, get() returns app with pubSubSubscription
                    get: async () =>
                        subscriptionCreated ? { id: 'test-app', pubSubSubscription: 'projects/test/subscriptions/ee-sub-test-app' } : { id: 'test-app' }
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

        await t2.test('missing subscription recovery failure propagates error to caller', async () => {
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

                    // Recovery fails, error should propagate to caller (startLoop handles backoff)
                    await assert.rejects(() => instance.run(), /Setup failed/);
                    assert.strictEqual(ensurePubsubCalls.length, 1);
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
            for (let id of ['app-a', 'app-b', 'app-c']) {
                pubsub.pubSubInstances.set(id, createTestInstance({ app: id }));
            }

            assert.strictEqual(pubsub.pubSubInstances.size, 3, 'should have 3 instances');
            pubsub.stopAll();
            assert.strictEqual(pubsub.pubSubInstances.size, 0, 'all instances should be removed');
        });

        await t2.test('stopAll() sets stopped flag on all instances', async () => {
            let pubsub = new GooglePubSub({ call: async () => {} });
            let instances = [];
            for (let id of ['app-x', 'app-y']) {
                let instance = createTestInstance({ app: id });
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
            let instance = createTestInstance({ app: 'imm-test', _immediateHandle: setImmediate(() => {}) });
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

    // --- _backoffMs() tests ---

    await t.test('_backoffMs() returns expected values with jitter', async t2 => {
        await t2.test('backoff at 0 attempts is in range [1500, 3000)', () => {
            let instance = createTestInstance();
            let result = instance._backoffMs(0);
            assert.ok(result >= 1500 && result < 3000, `expected [1500, 3000) but got ${result}`);
        });

        await t2.test('backoff at 1 attempt is in range [3000, 6000)', () => {
            let instance = createTestInstance();
            let result = instance._backoffMs(1);
            assert.ok(result >= 3000 && result < 6000, `expected [3000, 6000) but got ${result}`);
        });

        await t2.test('backoff at 5 attempts is in range [48000, 96000)', () => {
            let instance = createTestInstance();
            let result = instance._backoffMs(5);
            assert.ok(result >= 48000 && result < 96000, `expected [48000, 96000) but got ${result}`);
        });

        await t2.test('backoff caps at 300000ms (5 minutes) with jitter in range [150000, 300000)', () => {
            let instance = createTestInstance();
            let result = instance._backoffMs(20);
            assert.ok(result >= 150000 && result < 300000, `expected [150000, 300000) but got ${result}`);
        });

        await t2.test('backoff stays capped beyond 20 attempts with jitter in range [150000, 300000)', () => {
            let instance = createTestInstance();
            let result = instance._backoffMs(25);
            assert.ok(result >= 150000 && result < 300000, `expected [150000, 300000) but got ${result}`);
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

        await t2.test('del() returns safely when app does not exist', async () => {
            let appId = 'nonexistent-app';

            await withMockedOauth2Apps({ get: async () => false }, async () => {
                let result = await oauth2Apps.del(appId);
                assert.strictEqual(result.id, appId, 'should return correct id');
                assert.strictEqual(result.deleted, false, 'should indicate nothing was deleted');
                assert.strictEqual(result.accounts, 0, 'should report zero accounts');
            })();
        });
    });

    // --- remove() synchronous behavior tests ---

    await t.test('remove() synchronous behavior tests', async t2 => {
        await t2.test('remove() returns undefined, not a Promise', () => {
            let pubsub = new GooglePubSub({ call: async () => {} });
            pubsub.pubSubInstances.set('sync-test', createTestInstance({ app: 'sync-test' }));

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
            let instance = createTestInstance({ app: 'abort-test', _abortController: abortController });
            pubsub.pubSubInstances.set('abort-test', instance);

            pubsub.remove('abort-test');
            assert.strictEqual(abortController.signal.aborted, true, 'AbortController should be aborted');
        });
    });

    // --- getApp() self-termination on deleted app ---

    await t.test('getApp() self-terminates when app data is not found', async t2 => {
        await t2.test('getApp() sets stopped, calls parent.remove, and throws', async () => {
            let removeCalled = false;
            let removedApp = null;

            await withMockedOauth2Apps({ get: async () => false }, async () => {
                let instance = createTestInstance();
                instance.appData = null; // force refresh
                let originalRemove = instance.parent.remove;
                instance.parent.remove = function (app) {
                    removeCalled = true;
                    removedApp = app;
                    originalRemove.call(this, app);
                };

                await assert.rejects(() => instance.getApp(true), { message: 'App no longer exists' });
                assert.strictEqual(instance.stopped, true, 'instance should be stopped');
                assert.strictEqual(removeCalled, true, 'parent.remove should have been called');
                assert.strictEqual(removedApp, 'test-app', 'should remove the correct app');
            })();
        });

        await t2.test('getApp() returns cached data without hitting oauth2Apps.get', async () => {
            let getCalled = false;

            await withMockedOauth2Apps(
                {
                    get: async () => {
                        getCalled = true;
                        return { id: 'test-app', pubSubSubscription: 'projects/test/subscriptions/test-sub' };
                    }
                },
                async () => {
                    let instance = createTestInstance();
                    // appData is already set by createTestInstance
                    let result = await instance.getApp(false);
                    assert.strictEqual(getCalled, false, 'should use cached data');
                    assert.strictEqual(result.id, 'test-app', 'should return cached appData');
                }
            )();
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
                    let instance = createTestInstance();
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
                    get: async () => ({ id: 'test-app', pubSubSubscription: 'projects/test/subscriptions/test-sub' }),
                    getClient: async () => ({ request: async () => {} }),
                    setMeta: async () => {
                        setMetaCalls++;
                    }
                },
                async () => {
                    let instance = createTestInstance();

                    // Override ensurePubsub to simulate shutdown during recovery
                    oauth2Apps.ensurePubsub = async () => {
                        instance.stopped = true;
                    };

                    await instance.attemptRecovery('test reason');
                    assert.strictEqual(setMetaCalls, 0, 'setMeta should not be called after stopped during recovery');
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
                    let batchedAckIds = [];
                    let instance = createTestInstance({
                        client: {
                            request: async (token, url, method, payload) => {
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
                                    batchedAckIds = payload.ackIds || [];
                                    return '';
                                }
                            }
                        }
                    });

                    mockSets[`${REDIS_PREFIX}oapp:sub`] = new Set(['test-app']);

                    await instance.run();
                    assert.strictEqual(ackCount, 1, 'should have sent a single batch ACK request');
                    assert.strictEqual(batchedAckIds.length, 3, 'batch ACK should contain all 3 ackIds');
                    assert.deepStrictEqual(batchedAckIds, ['ack-1', 'ack-2', 'ack-3']);
                    // getServiceAccessToken called once for getAccessToken() before pull,
                    // plus once inside getClient(). Should NOT be called per-message.
                    assert.ok(tokenCallCount <= 2, `getServiceAccessToken should be called at most twice, got ${tokenCallCount}`);
                }
            )();
        });
    });

    // --- _deletePubSubResource transient error retry tests ---

    await t.test('_deletePubSubResource transient error retry tests', async t2 => {
        let deleteAppData = {
            id: 'test-app',
            pubSubTopic: 'projects/test/topics/test-topic',
            pubSubSubscription: 'projects/test/subscriptions/test-sub'
        };

        t2.beforeEach(() => {
            mockRedisData = {};
            mockSets = {};
        });

        await t2.test('retries once on transient error and succeeds', async () => {
            let callCount = 0;
            await withMockedOauth2Apps(
                {
                    getClient: async () => ({
                        request: async () => {
                            callCount++;
                            if (callCount === 1) {
                                let err = new Error('Connection timed out');
                                err.code = 'ETIMEDOUT';
                                throw err;
                            }
                            return '';
                        }
                    }),
                    getServiceAccessToken: async () => 'mock-token'
                },
                async () => {
                    await oauth2Apps.deleteTopic(deleteAppData);
                    // First call fails with ETIMEDOUT, retry succeeds, then subscription delete succeeds
                    assert.ok(callCount >= 3, `expected at least 3 requests (topic attempt, topic retry, subscription), got ${callCount}`);
                }
            )();
        });

        await t2.test('throws after retry also fails with transient error', async () => {
            let callCount = 0;
            await withMockedOauth2Apps(
                {
                    getClient: async () => ({
                        request: async () => {
                            callCount++;
                            let err = new Error('Connection reset');
                            err.code = 'ECONNRESET';
                            throw err;
                        }
                    }),
                    getServiceAccessToken: async () => 'mock-token'
                },
                async () => {
                    await assert.rejects(
                        async () => oauth2Apps.deleteTopic(deleteAppData),
                        err => err.code === 'ECONNRESET'
                    );
                    // First attempt + retry = 2 calls for topic (fails before reaching subscription)
                    assert.strictEqual(callCount, 2, 'should have made exactly 2 requests (topic attempt + retry)');
                }
            )();
        });

        await t2.test('treats 404 on retry as success', async () => {
            let callCount = 0;
            await withMockedOauth2Apps(
                {
                    getClient: async () => ({
                        request: async () => {
                            callCount++;
                            if (callCount === 1) {
                                let err = new Error('Connection timed out');
                                err.code = 'ETIMEDOUT';
                                throw err;
                            }
                            if (callCount === 2) {
                                // Retry returns 404 (resource already gone)
                                throw create404Error();
                            }
                            return '';
                        }
                    }),
                    getServiceAccessToken: async () => 'mock-token'
                },
                async () => {
                    await oauth2Apps.deleteTopic(deleteAppData);
                    // Topic attempt (ETIMEDOUT) + retry (404, treated as success) + subscription attempt
                    assert.ok(callCount >= 3, `expected at least 3 requests, got ${callCount}`);
                }
            )();
        });
    });

    // --- processPulledMessage missing fields warning tests ---

    await t.test('processPulledMessage logs warning for missing fields', async t2 => {
        await t2.test('returns without throwing when emailAddress is missing', async () => {
            let instance = createTestInstance();
            // payload has historyId but no emailAddress
            let data = JSON.stringify({ historyId: '12345' });
            // Should return gracefully without throwing
            await instance.processPulledMessage('msg-missing-email', data);
        });

        await t2.test('returns without throwing when historyId is missing', async () => {
            let instance = createTestInstance();
            // payload has emailAddress but no historyId
            let data = JSON.stringify({ emailAddress: 'user@example.com' });
            await instance.processPulledMessage('msg-missing-history', data);
        });

        await t2.test('returns without throwing when payload is empty object', async () => {
            let instance = createTestInstance();
            let data = JSON.stringify({});
            await instance.processPulledMessage('msg-empty-payload', data);
        });
    });

    // --- 429 rate limiting in pull loop ---

    await t.test('429 rate limiting in pull loop', async t2 => {
        await t2.test('sets retryDelay from retryAfter header', async () => {
            await withMockedOauth2Apps(
                {
                    getServiceAccessToken: async () => 'mock-token'
                },
                async () => {
                    let instance = createTestInstance({
                        client: {
                            request: async () => {
                                throw create429Error(10);
                            }
                        }
                    });

                    let thrownErr;
                    try {
                        await instance.run();
                    } catch (err) {
                        thrownErr = err;
                    }
                    assert.ok(thrownErr, 'should throw on 429');
                    assert.strictEqual(thrownErr.statusCode, 429);
                    assert.strictEqual(thrownErr.retryDelay, 10000, 'retryDelay should be retryAfter * 1000');
                }
            )();
        });

        await t2.test('defaults to 30s retryDelay when retryAfter is missing', async () => {
            await withMockedOauth2Apps(
                {
                    getServiceAccessToken: async () => 'mock-token'
                },
                async () => {
                    let instance = createTestInstance({
                        client: {
                            request: async () => {
                                throw create429Error(null);
                            }
                        }
                    });

                    let thrownErr;
                    try {
                        await instance.run();
                    } catch (err) {
                        thrownErr = err;
                    }
                    assert.ok(thrownErr, 'should throw on 429');
                    assert.strictEqual(thrownErr.retryDelay, 30000, 'retryDelay should default to 30000ms');
                }
            )();
        });
    });

    // --- batch ACK failure ---

    await t.test('batch ACK failure does not crash the loop', async t2 => {
        await t2.test('logs error and continues when ACK request fails', async () => {
            await withMockedOauth2Apps(
                {
                    getServiceAccessToken: async () => 'mock-token'
                },
                async () => {
                    let ackCalled = false;
                    let instance = createTestInstance({
                        client: {
                            request: async (token, url) => {
                                if (url.includes(':pull')) {
                                    return {
                                        receivedMessages: [
                                            { message: { messageId: 'msg-1', data: '' }, ackId: 'ack-1' },
                                            { message: { messageId: 'msg-2', data: '' }, ackId: 'ack-2' }
                                        ]
                                    };
                                }
                                if (url.includes(':acknowledge')) {
                                    ackCalled = true;
                                    throw new Error('Network error during ACK');
                                }
                            }
                        }
                    });

                    // run() should complete without throwing despite ACK failure
                    await instance.run();
                    assert.ok(ackCalled, 'ACK request should have been attempted');
                }
            )();
        });
    });

    // --- processPulledMessage throw skips ACK for that message ---

    await t.test('processPulledMessage failure excludes message from batch ACK', async t2 => {
        await t2.test('only successfully processed messages are ACKed', async () => {
            let callCount = 0;
            await withMockedOauth2Apps(
                {
                    getServiceAccessToken: async () => 'mock-token'
                },
                async () => {
                    let batchedAckIds = [];
                    let instance = createTestInstance({
                        client: {
                            request: async (token, url, method, payload) => {
                                if (url.includes(':pull')) {
                                    return {
                                        receivedMessages: [
                                            {
                                                message: {
                                                    messageId: 'msg-ok',
                                                    data: Buffer.from(JSON.stringify({ emailAddress: 'user@example.com', historyId: '100' })).toString('base64')
                                                },
                                                ackId: 'ack-ok'
                                            },
                                            {
                                                message: {
                                                    messageId: 'msg-fail',
                                                    data: Buffer.from(JSON.stringify({ emailAddress: 'user2@example.com', historyId: '200' })).toString(
                                                        'base64'
                                                    )
                                                },
                                                ackId: 'ack-fail'
                                            }
                                        ]
                                    };
                                }
                                if (url.includes(':acknowledge')) {
                                    batchedAckIds = payload.ackIds || [];
                                    return '';
                                }
                            }
                        },
                        parent: {
                            getSubscribersKey: () => 'ee:oapp:sub',
                            remove: () => {},
                            call: async msg => {
                                callCount++;
                                // Fail on the second call (msg-fail)
                                if (callCount === 2) {
                                    throw new Error('Worker RPC timeout');
                                }
                            }
                        }
                    });

                    // Set up subscriber app with account mapping
                    mockSets[`${REDIS_PREFIX}oapp:pub:test-app`] = new Set(['sub-app']);
                    mockRedisData[`${REDIS_PREFIX}oapp:h:sub-app`] = {
                        'user@example.com': 'account-1',
                        'user2@example.com': 'account-2'
                    };

                    await instance.run();
                    assert.strictEqual(batchedAckIds.length, 1, 'only the successful message should be ACKed');
                    assert.deepStrictEqual(batchedAckIds, ['ack-ok'], 'failed message ackId should be excluded');
                }
            )();
        });
    });

    // --- _deletePubSubResource 429 rate limit retry ---

    await t.test('_deletePubSubResource 429 rate limit retry tests', async t2 => {
        let deleteAppData = {
            id: 'test-app',
            pubSubTopic: 'projects/test/topics/test-topic',
            pubSubSubscription: 'projects/test/subscriptions/test-sub'
        };

        t2.beforeEach(() => {
            mockRedisData = {};
            mockSets = {};
        });

        await t2.test('retries once on 429 and succeeds', async () => {
            let callCount = 0;
            await withMockedOauth2Apps(
                {
                    getClient: async () => ({
                        request: async () => {
                            callCount++;
                            if (callCount === 1) {
                                throw create429Error(1);
                            }
                            return '';
                        }
                    }),
                    getServiceAccessToken: async () => 'mock-token'
                },
                async () => {
                    await oauth2Apps.deleteTopic(deleteAppData);
                    // First call fails with 429, retry succeeds, then subscription delete succeeds
                    assert.ok(callCount >= 3, `expected at least 3 requests (topic attempt, topic retry, subscription), got ${callCount}`);
                }
            )();
        });

        await t2.test('throws after retry also fails with 429', async () => {
            let callCount = 0;
            await withMockedOauth2Apps(
                {
                    getClient: async () => ({
                        request: async () => {
                            callCount++;
                            throw create429Error(1);
                        }
                    }),
                    getServiceAccessToken: async () => 'mock-token'
                },
                async () => {
                    await assert.rejects(
                        async () => oauth2Apps.deleteTopic(deleteAppData),
                        err => err.statusCode === 429
                    );
                    // First attempt + retry = 2 calls for topic (fails before reaching subscription)
                    assert.strictEqual(callCount, 2, 'should have made exactly 2 requests (topic attempt + retry)');
                }
            )();
        });
    });
});

test('startLoop orchestration tests', async t => {
    t.after(() => {
        setTimeout(() => process.exit(), 1000).unref();
    });

    t.beforeEach(() => {
        mockRedisData = {};
        mockSets = {};
        mockSets['ee:oapp:sub'] = new Set(['test-app']);
    });

    // Helper: create an instance with run() replaced by a controllable mock.
    // Returns { instance, resolve, reject, settled } where settled is a promise
    // that resolves once startLoop's .then/.catch handler has finished.
    function createLoopTestInstance(overrides) {
        let runResolve, runReject;
        let settled;

        let instance = createTestInstance(overrides);

        // Replace run() with a controllable promise
        function armRun() {
            settled = new Promise(settledResolve => {
                let runPromise = new Promise((res, rej) => {
                    runResolve = res;
                    runReject = rej;
                });
                instance.run = () => {
                    // Wrap so startLoop's .then/.catch signals completion
                    let original = runPromise;
                    runPromise = new Promise(() => {}); // disarm for next call
                    return original.then(
                        val => {
                            // let startLoop's .then run, then signal
                            setImmediate(settledResolve);
                            return val;
                        },
                        err => {
                            // let startLoop's .catch run, then signal
                            setImmediate(settledResolve);
                            throw err;
                        }
                    );
                };
            });
        }

        armRun();

        return {
            instance,
            resolve: val => runResolve(val),
            reject: err => runReject(err),
            get settled() {
                return settled;
            },
            armRun
        };
    }

    // Helper: wrap startLoop so only the first invocation runs the real code.
    // Subsequent calls (from setImmediate/setTimeout) are suppressed.
    function guardStartLoop(instance) {
        let realStartLoop = instance.startLoop.bind(instance);
        let callCount = 0;
        instance.startLoop = function () {
            callCount++;
            if (callCount === 1) {
                return realStartLoop();
            }
        };
        return {
            get callCount() {
                return callCount;
            },
            reset() {
                callCount = 0;
            }
        };
    }

    await t.test('success resets _consecutiveErrors and _lastLoopError', async () => {
        await withMockedOauth2Apps({ setMeta: async () => {} }, async () => {
            let ctl = createLoopTestInstance({ _consecutiveErrors: 5, _lastLoopError: 'some|error' });
            let guard = guardStartLoop(ctl.instance);

            ctl.instance.startLoop();
            // Resolve with a positive messageCount so startLoop uses setImmediate
            ctl.resolve(1);

            // Wait for .then handler and setImmediate
            await new Promise(r => setImmediate(r));
            await new Promise(r => setImmediate(r));

            assert.strictEqual(ctl.instance._consecutiveErrors, 0, 'should reset to 0 on success');
            assert.strictEqual(ctl.instance._lastLoopError, null, 'should clear on success');
            assert.strictEqual(guard.callCount, 2, 'startLoop re-invoked via setImmediate');
        })();
    });

    await t.test('error deduplication: same error logged once, different error logged again', async () => {
        let setMetaCalls = [];
        await withMockedOauth2Apps(
            {
                setMeta: async (id, meta) => {
                    setMetaCalls.push({ id, meta });
                }
            },
            async () => {
                let ctl = createLoopTestInstance();
                let guard = guardStartLoop(ctl.instance);

                // First error
                ctl.instance.startLoop();
                let err1 = new Error('Connection timeout');
                err1.code = 'ETIMEDOUT';
                err1.retryDelay = 60000;
                ctl.reject(err1);
                await ctl.settled;

                assert.strictEqual(ctl.instance._consecutiveErrors, 1);
                assert.strictEqual(setMetaCalls.length, 1, 'setMeta called on first occurrence');
                assert.ok(setMetaCalls[0].meta.pubSubFlag, 'pubSubFlag set');

                // Second identical error -- should NOT trigger setMeta again
                let prevSetMetaCount = setMetaCalls.length;
                clearTimeout(ctl.instance._loopTimer);
                guard.reset();
                ctl.armRun();
                ctl.instance.startLoop();
                let err2 = new Error('Connection timeout');
                err2.code = 'ETIMEDOUT';
                err2.retryDelay = 60000;
                ctl.reject(err2);
                await ctl.settled;

                assert.strictEqual(ctl.instance._consecutiveErrors, 2);
                assert.strictEqual(setMetaCalls.length, prevSetMetaCount, 'setMeta NOT called for duplicate error');

                // Third error with different message -- should trigger setMeta again
                clearTimeout(ctl.instance._loopTimer);
                guard.reset();
                ctl.armRun();
                ctl.instance.startLoop();
                let err3 = new Error('DNS lookup failed');
                err3.code = 'ENOTFOUND';
                err3.retryDelay = 60000;
                ctl.reject(err3);
                await ctl.settled;

                assert.strictEqual(ctl.instance._consecutiveErrors, 3);
                assert.strictEqual(setMetaCalls.length, prevSetMetaCount + 1, 'setMeta called for new error');

                clearTimeout(ctl.instance._loopTimer);
            }
        )();
    });

    await t.test('stopped flag prevents scheduling', async () => {
        let instance = createTestInstance({ _consecutiveErrors: 0, _loopTimer: null });
        instance.stopped = true;

        instance.startLoop();

        // startLoop should return immediately without calling run()
        assert.strictEqual(instance._loopTimer, null, 'no setTimeout scheduled');
    });

    await t.test('AbortError is silenced: no error state change, no scheduling', async () => {
        let setMetaCalls = [];
        await withMockedOauth2Apps(
            {
                setMeta: async (id, meta) => {
                    setMetaCalls.push({ id, meta });
                }
            },
            async () => {
                let { instance, reject, settled } = createLoopTestInstance();
                guardStartLoop(instance);

                instance.startLoop();

                let abortErr = new Error('The operation was aborted');
                abortErr.name = 'AbortError';
                reject(abortErr);
                await settled;

                assert.strictEqual(instance._consecutiveErrors, 0, 'no error increment');
                assert.strictEqual(instance._lastLoopError, null, 'no error key set');
                assert.strictEqual(instance._loopTimer, null, 'no retry scheduled');
                assert.strictEqual(setMetaCalls.length, 0, 'no setMeta call');
            }
        )();
    });

    await t.test('stopped during run: error handler does not schedule', async () => {
        let setMetaCalls = [];
        await withMockedOauth2Apps(
            {
                setMeta: async (id, meta) => {
                    setMetaCalls.push({ id, meta });
                }
            },
            async () => {
                let { instance, reject, settled } = createLoopTestInstance();
                guardStartLoop(instance);

                instance.startLoop();

                // Stop the instance while run() is pending
                instance.stopped = true;
                reject(new Error('some error'));
                await settled;

                assert.strictEqual(instance._consecutiveErrors, 0, 'no error increment when stopped');
                assert.strictEqual(instance._loopTimer, null, 'no retry scheduled when stopped');
                assert.strictEqual(setMetaCalls.length, 0, 'no setMeta call when stopped');
            }
        )();
    });

    await t.test('err.retryDelay overrides backoff calculation', async () => {
        await withMockedOauth2Apps({ setMeta: async () => {} }, async () => {
            let { instance, reject, settled } = createLoopTestInstance();
            guardStartLoop(instance);

            instance.startLoop();

            let err = new Error('Rate limited');
            err.retryDelay = 42000;
            reject(err);
            await settled;

            // startLoop stores the timer in _loopTimer; verify it was scheduled
            assert.ok(instance._loopTimer, 'setTimeout was scheduled');
            clearTimeout(instance._loopTimer);
        })();
    });

    await t.test('setMeta called with pubSubFlag on first error occurrence', async () => {
        let setMetaCalls = [];
        await withMockedOauth2Apps(
            {
                setMeta: async (id, meta) => {
                    setMetaCalls.push({ id, meta });
                }
            },
            async () => {
                let { instance, reject, settled } = createLoopTestInstance({
                    _hadPubSubFlag: false
                });
                guardStartLoop(instance);

                instance.startLoop();

                let err = new Error('Connection failed');
                err.code = 'SERVICE_UNAVAILABLE';
                err.statusCode = 503;
                err.retryDelay = 1;
                reject(err);
                await settled;

                assert.strictEqual(setMetaCalls.length, 1, 'setMeta called once');
                assert.strictEqual(setMetaCalls[0].id, 'test-app');
                assert.ok(setMetaCalls[0].meta.pubSubFlag, 'pubSubFlag is set');
                assert.strictEqual(setMetaCalls[0].meta.pubSubFlag.message, 'Failed to process subscription loop');
                assert.ok(setMetaCalls[0].meta.pubSubFlag.description.includes('Connection failed'));
                assert.ok(setMetaCalls[0].meta.pubSubFlag.description.includes('SERVICE_UNAVAILABLE'));
                assert.strictEqual(instance._hadPubSubFlag, true, '_hadPubSubFlag set to true');

                clearTimeout(instance._loopTimer);
            }
        )();
    });
});
