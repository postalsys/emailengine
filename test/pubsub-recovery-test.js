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

function createMockRedis() {
    return {
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
        hmset: async (key, data) => {
            if (!mockRedisData[key]) mockRedisData[key] = {};
            Object.assign(mockRedisData[key], data);
        },
        multi: () => ({
            exec: async () => [],
            hmset: function () {
                return this;
            },
            hset: function () {
                return this;
            },
            hdel: function () {
                return this;
            },
            del: function () {
                return this;
            },
            expire: function () {
                return this;
            },
            srem: function () {
                return this;
            },
            zadd: function () {
                return this;
            },
            hincrby: function () {
                return this;
            }
        }),
        ttl: async () => 3600,
        eval: async () => 1,
        smembers: async () => [],
        sismember: async () => 1,
        srem: async () => {},
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
const { PubSubInstance } = require('../lib/oauth/pubsub/google');
const { oauth2Apps } = require('../lib/oauth2-apps');

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

                // Second call immediately: should skip recovery due to backoff and throw
                await assert.rejects(() => instance.run(), /Subscription not found/);
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

                // First run: 404 -> recovery -> returns
                await instance.run();

                // Second run: successful pull
                setMetaCalls = [];
                await instance.run();

                // setMeta should be called with pubSubFlag: null on successful pull
                let clearCall = setMetaCalls.find(c => c.meta && c.meta.pubSubFlag === null);
                assert.ok(clearCall, 'setMeta should clear pubSubFlag after successful pull');
            }
        )();
    });
});
