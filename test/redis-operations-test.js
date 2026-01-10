'use strict';

const test = require('node:test');
const assert = require('node:assert').strict;

const {
    RedisTransaction,
    createTransaction,
    atomicUpdate,
    batchGet,
    batchSet,
    conditionalSet,
    atomicIncrement,
    boundedPush,
    getAndDelete,
    isTransientError,
    extractMultiError,
    extractMultiValues
} = require('../lib/redis-operations');

test('Redis Operations tests', async t => {
    t.after(() => {
        setTimeout(() => process.exit(), 1000).unref();
    });

    // isTransientError tests
    await t.test('isTransientError() returns false for null/undefined', async () => {
        assert.strictEqual(isTransientError(null), false);
        assert.strictEqual(isTransientError(undefined), false);
    });

    await t.test('isTransientError() detects ECONNRESET', async () => {
        const err = new Error('Connection reset');
        err.code = 'ECONNRESET';
        assert.strictEqual(isTransientError(err), true);
    });

    await t.test('isTransientError() detects ETIMEDOUT', async () => {
        const err = new Error('Timed out');
        err.code = 'ETIMEDOUT';
        assert.strictEqual(isTransientError(err), true);
    });

    await t.test('isTransientError() detects ECONNREFUSED', async () => {
        const err = new Error('Connection refused');
        err.code = 'ECONNREFUSED';
        assert.strictEqual(isTransientError(err), true);
    });

    await t.test('isTransientError() detects EPIPE', async () => {
        const err = new Error('Broken pipe');
        err.code = 'EPIPE';
        assert.strictEqual(isTransientError(err), true);
    });

    await t.test('isTransientError() detects Redis LOADING error', async () => {
        const err = new Error('LOADING Redis is loading the dataset');
        err.name = 'ReplyError';
        assert.strictEqual(isTransientError(err), true);
    });

    await t.test('isTransientError() detects Redis BUSY error', async () => {
        const err = new Error('BUSY Redis is busy');
        err.name = 'ReplyError';
        assert.strictEqual(isTransientError(err), true);
    });

    await t.test('isTransientError() detects Redis READONLY error', async () => {
        const err = new Error('READONLY You cannot write');
        err.name = 'ReplyError';
        assert.strictEqual(isTransientError(err), true);
    });

    await t.test('isTransientError() detects connection lost message', async () => {
        const err = new Error('Connection lost to server');
        assert.strictEqual(isTransientError(err), true);
    });

    await t.test('isTransientError() detects socket closed message', async () => {
        const err = new Error('Socket has been closed');
        assert.strictEqual(isTransientError(err), true);
    });

    await t.test('isTransientError() returns false for normal errors', async () => {
        const err = new Error('Some other error');
        assert.strictEqual(isTransientError(err), false);
    });

    await t.test('isTransientError() returns false for ENOENT', async () => {
        const err = new Error('File not found');
        err.code = 'ENOENT';
        assert.strictEqual(isTransientError(err), false);
    });

    // extractMultiError tests
    await t.test('extractMultiError() returns null for non-array', async () => {
        assert.strictEqual(extractMultiError(null), null);
        assert.strictEqual(extractMultiError(undefined), null);
        assert.strictEqual(extractMultiError('string'), null);
    });

    await t.test('extractMultiError() returns null for empty array', async () => {
        assert.strictEqual(extractMultiError([]), null);
    });

    await t.test('extractMultiError() returns null when no errors', async () => {
        const results = [
            [null, 'OK'],
            [null, 1],
            [null, 'value']
        ];
        assert.strictEqual(extractMultiError(results), null);
    });

    await t.test('extractMultiError() returns first error found', async () => {
        const err1 = new Error('First error');
        const err2 = new Error('Second error');
        const results = [
            [null, 'OK'],
            [err1, null],
            [err2, null]
        ];
        assert.strictEqual(extractMultiError(results), err1);
    });

    await t.test('extractMultiError() handles mixed result formats', async () => {
        const results = ['OK', [null, 1], [new Error('Error'), null]];
        assert.strictEqual(extractMultiError(results).message, 'Error');
    });

    // extractMultiValues tests
    await t.test('extractMultiValues() returns empty array for non-array', async () => {
        assert.deepStrictEqual(extractMultiValues(null), []);
        assert.deepStrictEqual(extractMultiValues(undefined), []);
        assert.deepStrictEqual(extractMultiValues('string'), []);
    });

    await t.test('extractMultiValues() extracts values from results', async () => {
        const results = [
            [null, 'OK'],
            [null, 1],
            [null, 'value']
        ];
        assert.deepStrictEqual(extractMultiValues(results), ['OK', 1, 'value']);
    });

    await t.test('extractMultiValues() handles non-array elements', async () => {
        const results = ['OK', 1, 'value'];
        assert.deepStrictEqual(extractMultiValues(results), ['OK', 1, 'value']);
    });

    await t.test('extractMultiValues() handles mixed formats', async () => {
        const results = [[null, 'first'], 'second', [new Error('err'), null]];
        assert.deepStrictEqual(extractMultiValues(results), ['first', 'second', null]);
    });

    // RedisTransaction class tests with mock Redis
    await t.test('RedisTransaction.add() chains commands', async () => {
        const mockRedis = {};
        const txn = new RedisTransaction(mockRedis);

        const result = txn.add('set', 'key1', 'value1').add('get', 'key1').add('del', 'key1');

        assert.strictEqual(result, txn); // Returns this for chaining
        assert.strictEqual(txn.commands.length, 3);
        assert.deepStrictEqual(txn.commandNames, ['set', 'get', 'del']);
    });

    await t.test('RedisTransaction stores commands correctly', async () => {
        const mockRedis = {};
        const txn = new RedisTransaction(mockRedis);

        txn.add('hset', 'hash', 'field', 'value');
        txn.add('expire', 'hash', 3600);

        assert.deepStrictEqual(txn.commands[0], { command: 'hset', args: ['hash', 'field', 'value'] });
        assert.deepStrictEqual(txn.commands[1], { command: 'expire', args: ['hash', 3600] });
    });

    await t.test('RedisTransaction.exec() executes multi transaction', async () => {
        const results = [
            [null, 'OK'],
            [null, 1]
        ];

        const mockMulti = {
            set: function () {
                return this;
            },
            expire: function () {
                return this;
            },
            exec: async function () {
                return results;
            }
        };

        const mockRedis = {
            multi: () => mockMulti
        };

        const txn = new RedisTransaction(mockRedis);
        txn.add('set', 'key', 'value');
        txn.add('expire', 'key', 100);

        const result = await txn.exec();

        assert.strictEqual(result.error, null);
        assert.deepStrictEqual(result.values, ['OK', 1]);
        assert.strictEqual(result.results, results);
    });

    await t.test('RedisTransaction.execOrThrow() returns values on success', async () => {
        const results = [
            [null, 'value1'],
            [null, 'value2']
        ];

        const mockMulti = {
            get: function () {
                return this;
            },
            exec: async function () {
                return results;
            }
        };

        const mockRedis = {
            multi: () => mockMulti
        };

        const txn = new RedisTransaction(mockRedis);
        txn.add('get', 'key1');
        txn.add('get', 'key2');

        const values = await txn.execOrThrow();

        assert.deepStrictEqual(values, ['value1', 'value2']);
    });

    await t.test('RedisTransaction.execOrThrow() throws on error', async () => {
        const err = new Error('Redis error');
        const results = [
            [err, null],
            [null, 'value2']
        ];

        const mockMulti = {
            get: function () {
                return this;
            },
            exec: async function () {
                return results;
            }
        };

        const mockRedis = {
            multi: () => mockMulti
        };

        const txn = new RedisTransaction(mockRedis);
        txn.add('get', 'key1');
        txn.add('get', 'key2');

        await assert.rejects(async () => {
            await txn.execOrThrow();
        }, err);
    });

    // createTransaction tests
    await t.test('createTransaction() returns RedisTransaction instance', async () => {
        const mockRedis = {};
        const txn = createTransaction(mockRedis);

        assert.ok(txn instanceof RedisTransaction);
    });

    await t.test('createTransaction() passes options', async () => {
        const mockRedis = {};
        const options = { maxAttempts: 5, baseDelay: 200 };
        const txn = createTransaction(mockRedis, options);

        assert.strictEqual(txn.retryOptions.maxAttempts, 5);
        assert.strictEqual(txn.retryOptions.baseDelay, 200);
    });

    // atomicUpdate tests
    await t.test('atomicUpdate() sets hash fields', async () => {
        const calledCommands = [];
        const mockMulti = {
            hmset: function (...args) {
                calledCommands.push(['hmset', ...args]);
                return this;
            },
            exec: async function () {
                return [[null, 'OK']];
            }
        };

        const mockRedis = {
            multi: () => mockMulti
        };

        const result = await atomicUpdate(mockRedis, 'mykey', { field1: 'value1', field2: 'value2' });

        assert.strictEqual(result.success, true);
        assert.strictEqual(result.error, null);
        assert.deepStrictEqual(calledCommands[0], ['hmset', 'mykey', { field1: 'value1', field2: 'value2' }]);
    });

    await t.test('atomicUpdate() handles empty fields', async () => {
        const mockMulti = {
            exec: async function () {
                return [];
            }
        };

        const mockRedis = {
            multi: () => mockMulti
        };

        const result = await atomicUpdate(mockRedis, 'mykey', {});

        assert.strictEqual(result.success, true);
    });

    await t.test('atomicUpdate() sets expiration when specified', async () => {
        const calledCommands = [];
        const mockMulti = {
            hmset: function (...args) {
                calledCommands.push(['hmset', ...args]);
                return this;
            },
            expire: function (...args) {
                calledCommands.push(['expire', ...args]);
                return this;
            },
            exec: async function () {
                return [
                    [null, 'OK'],
                    [null, 1]
                ];
            }
        };

        const mockRedis = {
            multi: () => mockMulti
        };

        await atomicUpdate(mockRedis, 'mykey', { field: 'value' }, { expireSeconds: 3600 });

        assert.strictEqual(calledCommands.length, 2);
        assert.deepStrictEqual(calledCommands[1], ['expire', 'mykey', 3600]);
    });

    // batchGet tests
    await t.test('batchGet() returns empty array for empty keys', async () => {
        const mockRedis = {};
        const result = await batchGet(mockRedis, []);
        assert.deepStrictEqual(result, []);
    });

    await t.test('batchGet() fetches multiple keys', async () => {
        const mockMulti = {
            get: function () {
                return this;
            },
            exec: async function () {
                return [
                    [null, 'value1'],
                    [null, 'value2'],
                    [null, 'value3']
                ];
            }
        };

        const mockRedis = {
            multi: () => mockMulti
        };

        const result = await batchGet(mockRedis, ['key1', 'key2', 'key3']);

        assert.deepStrictEqual(result, ['value1', 'value2', 'value3']);
    });

    // batchSet tests
    await t.test('batchSet() returns success for empty items', async () => {
        const mockRedis = {};
        const result = await batchSet(mockRedis, []);

        assert.strictEqual(result.success, true);
        assert.deepStrictEqual(result.values, []);
    });

    await t.test('batchSet() sets multiple key-value pairs', async () => {
        const calledCommands = [];
        const mockMulti = {
            set: function (...args) {
                calledCommands.push(['set', ...args]);
                return this;
            },
            exec: async function () {
                return [
                    [null, 'OK'],
                    [null, 'OK']
                ];
            }
        };

        const mockRedis = {
            multi: () => mockMulti
        };

        const items = [
            { key: 'key1', value: 'value1' },
            { key: 'key2', value: 'value2' }
        ];

        const result = await batchSet(mockRedis, items);

        assert.strictEqual(result.success, true);
        assert.strictEqual(calledCommands.length, 2);
    });

    // conditionalSet tests
    await t.test('conditionalSet() uses hSetExists when available', async () => {
        const mockMulti = {
            hSetExists: function () {
                return this;
            },
            exec: async function () {
                return [[null, 1]];
            }
        };

        const mockRedis = {
            multi: () => mockMulti,
            hSetExists: async () => 1
        };

        const result = await conditionalSet(mockRedis, 'key', 'field', 'value');

        assert.strictEqual(result.success, true);
        assert.strictEqual(result.wasSet, true);
    });

    await t.test('conditionalSet() falls back when hSetExists unavailable', async () => {
        let hsetCalled = false;
        const mockRedis = {
            exists: async () => 1,
            hset: async () => {
                hsetCalled = true;
                return 1;
            }
        };

        const result = await conditionalSet(mockRedis, 'key', 'field', 'value');

        assert.strictEqual(result.success, true);
        assert.strictEqual(result.wasSet, true);
        assert.strictEqual(hsetCalled, true);
    });

    await t.test('conditionalSet() returns wasSet false when key does not exist', async () => {
        const mockRedis = {
            exists: async () => 0
        };

        const result = await conditionalSet(mockRedis, 'key', 'field', 'value');

        assert.strictEqual(result.success, true);
        assert.strictEqual(result.wasSet, false);
    });

    // atomicIncrement tests
    await t.test('atomicIncrement() increments and sets expiration', async () => {
        const calledCommands = [];
        const mockMulti = {
            incrby: function (...args) {
                calledCommands.push(['incrby', ...args]);
                return this;
            },
            expire: function (...args) {
                calledCommands.push(['expire', ...args]);
                return this;
            },
            exec: async function () {
                return [
                    [null, 5],
                    [null, 1]
                ];
            }
        };

        const mockRedis = {
            multi: () => mockMulti
        };

        const result = await atomicIncrement(mockRedis, 'counter', 5, 3600);

        assert.strictEqual(result.success, true);
        assert.strictEqual(result.value, 5);
        assert.deepStrictEqual(calledCommands[0], ['incrby', 'counter', 5]);
        assert.deepStrictEqual(calledCommands[1], ['expire', 'counter', 3600]);
    });

    // boundedPush tests
    await t.test('boundedPush() pushes right and trims by default', async () => {
        const calledCommands = [];
        const mockMulti = {
            rpush: function (...args) {
                calledCommands.push(['rpush', ...args]);
                return this;
            },
            ltrim: function (...args) {
                calledCommands.push(['ltrim', ...args]);
                return this;
            },
            exec: async function () {
                return [
                    [null, 5],
                    [null, 'OK']
                ];
            }
        };

        const mockRedis = {
            multi: () => mockMulti
        };

        const result = await boundedPush(mockRedis, 'list', 'value', 100);

        assert.strictEqual(result.success, true);
        assert.strictEqual(result.listLength, 5);
        assert.deepStrictEqual(calledCommands[0], ['rpush', 'list', 'value']);
        assert.deepStrictEqual(calledCommands[1], ['ltrim', 'list', -100, -1]);
    });

    await t.test('boundedPush() pushes left when direction specified', async () => {
        const calledCommands = [];
        const mockMulti = {
            lpush: function (...args) {
                calledCommands.push(['lpush', ...args]);
                return this;
            },
            ltrim: function (...args) {
                calledCommands.push(['ltrim', ...args]);
                return this;
            },
            exec: async function () {
                return [
                    [null, 5],
                    [null, 'OK']
                ];
            }
        };

        const mockRedis = {
            multi: () => mockMulti
        };

        const result = await boundedPush(mockRedis, 'list', 'value', 100, { direction: 'left' });

        assert.strictEqual(result.success, true);
        assert.deepStrictEqual(calledCommands[0], ['lpush', 'list', 'value']);
        assert.deepStrictEqual(calledCommands[1], ['ltrim', 'list', 0, 99]);
    });

    // getAndDelete tests
    await t.test('getAndDelete() gets and deletes key', async () => {
        const calledCommands = [];
        const mockMulti = {
            get: function (...args) {
                calledCommands.push(['get', ...args]);
                return this;
            },
            del: function (...args) {
                calledCommands.push(['del', ...args]);
                return this;
            },
            exec: async function () {
                return [
                    [null, 'myvalue'],
                    [null, 1]
                ];
            }
        };

        const mockRedis = {
            multi: () => mockMulti
        };

        const result = await getAndDelete(mockRedis, 'mykey');

        assert.strictEqual(result.success, true);
        assert.strictEqual(result.value, 'myvalue');
        assert.deepStrictEqual(calledCommands, [
            ['get', 'mykey'],
            ['del', 'mykey']
        ]);
    });

    await t.test('getAndDelete() supports lrange type', async () => {
        const calledCommands = [];
        const mockMulti = {
            lrange: function (...args) {
                calledCommands.push(['lrange', ...args]);
                return this;
            },
            del: function (...args) {
                calledCommands.push(['del', ...args]);
                return this;
            },
            exec: async function () {
                return [
                    [null, ['item1', 'item2']],
                    [null, 1]
                ];
            }
        };

        const mockRedis = {
            multi: () => mockMulti
        };

        const result = await getAndDelete(mockRedis, 'mylist', { type: 'lrange', rangeArgs: [0, -1] });

        assert.strictEqual(result.success, true);
        assert.deepStrictEqual(result.value, ['item1', 'item2']);
        assert.deepStrictEqual(calledCommands[0], ['lrange', 'mylist', 0, -1]);
    });
});
