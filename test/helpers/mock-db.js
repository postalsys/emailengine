'use strict';

// Installs stubs for lib/db and lib/get-secret in the require cache.
//
// Requiring anything under lib/email-client pulls in lib/db, which opens real
// Redis connections and BullMQ queues at module load time. Pure unit tests that
// exercise a class method against a mock context never touch either, so the
// stubs stay empty - a test that needs Redis should use the real client and
// test/helpers/redis-teardown instead.
//
// Must be called before the module under test is required.

const mockQueue = {
    add: async () => ({}),
    close: async () => {},
    on: () => {},
    off: () => {}
};

function installDbMock({ redis } = {}) {
    const dbPath = require.resolve('../../lib/db');
    require.cache[dbPath] = {
        id: dbPath,
        filename: dbPath,
        loaded: true,
        parent: null,
        children: [],
        exports: {
            redis: redis || {},
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

    const getSecretPath = require.resolve('../../lib/get-secret');
    require.cache[getSecretPath] = {
        id: getSecretPath,
        filename: getSecretPath,
        loaded: true,
        parent: null,
        children: [],
        exports: async () => null
    };
}

module.exports = { installDbMock, mockQueue };
