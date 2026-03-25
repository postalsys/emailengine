'use strict';

const test = require('node:test');
const assert = require('node:assert').strict;

// In-memory mock Redis data store
let mockRedisData = {};
let mockRedisSets = {};
let mockRedisStrings = {};

function createMockRedis() {
    return {
        status: 'ready',
        hget: async (key, field) => (mockRedisData[key] && mockRedisData[key][field]) || null,
        hset: async (key, ...args) => {
            if (!mockRedisData[key]) mockRedisData[key] = {};
            if (args.length === 1 && typeof args[0] === 'object') {
                Object.assign(mockRedisData[key], args[0]);
            } else if (args.length === 2) {
                mockRedisData[key][args[0]] = args[1];
            }
        },
        hgetall: async key => {
            let data = mockRedisData[key];
            if (!data || Object.keys(data).length === 0) return null;
            return data;
        },
        hdel: async () => {},
        hmset: async (key, data) => {
            if (!mockRedisData[key]) mockRedisData[key] = {};
            Object.assign(mockRedisData[key], data);
        },
        hmget: async (key, fields) => {
            let result = [];
            for (let field of fields) {
                result.push((mockRedisData[key] && mockRedisData[key][field]) || null);
            }
            return result;
        },
        sadd: async (key, member) => {
            if (!mockRedisSets[key]) mockRedisSets[key] = new Set();
            mockRedisSets[key].add(member);
            return 1;
        },
        smembers: async key => {
            if (!mockRedisSets[key]) return [];
            return Array.from(mockRedisSets[key]);
        },
        srem: async (key, member) => {
            if (!mockRedisSets[key]) return 0;
            mockRedisSets[key].delete(member);
            return 1;
        },
        scard: async key => {
            if (!mockRedisSets[key]) return 0;
            return mockRedisSets[key].size;
        },
        get: async key => mockRedisStrings[key] || null,
        getdel: async key => {
            let val = mockRedisStrings[key] || null;
            delete mockRedisStrings[key];
            return val;
        },
        set: async (key, value) => {
            mockRedisStrings[key] = value;
            return 'OK';
        },
        del: async key => {
            delete mockRedisData[key];
            delete mockRedisStrings[key];
            return 1;
        },
        scan: async (cursor, ...args) => {
            // simple scan implementation: return all matching hash keys
            let matchPattern = '';
            for (let i = 0; i < args.length; i += 2) {
                if (args[i] === 'MATCH') matchPattern = args[i + 1];
            }
            let keys = Object.keys(mockRedisData).filter(k => {
                if (!matchPattern) return true;
                let regex = new RegExp('^' + matchPattern.replace(/\*/g, '.*') + '$');
                return regex.test(k);
            });
            return ['0', keys];
        },
        pipeline: () => {
            let ops = [];
            let pipeObj = {
                hset(key, ...args) {
                    ops.push({
                        cmd: 'hset',
                        key,
                        args
                    });
                    return pipeObj;
                },
                sadd(key, member) {
                    ops.push({ cmd: 'sadd', key, member });
                    return pipeObj;
                },
                srem(key, member) {
                    ops.push({ cmd: 'srem', key, member });
                    return pipeObj;
                },
                del(key) {
                    ops.push({ cmd: 'del', key });
                    return pipeObj;
                },
                hgetall(key) {
                    ops.push({ cmd: 'hgetall', key });
                    return pipeObj;
                },
                async exec() {
                    let results = [];
                    for (let op of ops) {
                        try {
                            if (op.cmd === 'hset') {
                                if (!mockRedisData[op.key]) mockRedisData[op.key] = {};
                                if (op.args.length === 1 && typeof op.args[0] === 'object') {
                                    Object.assign(mockRedisData[op.key], op.args[0]);
                                } else if (op.args.length === 2) {
                                    mockRedisData[op.key][op.args[0]] = op.args[1];
                                }
                                results.push([null, 'OK']);
                            } else if (op.cmd === 'sadd') {
                                if (!mockRedisSets[op.key]) mockRedisSets[op.key] = new Set();
                                mockRedisSets[op.key].add(op.member);
                                results.push([null, 1]);
                            } else if (op.cmd === 'srem') {
                                if (mockRedisSets[op.key]) mockRedisSets[op.key].delete(op.member);
                                results.push([null, 1]);
                            } else if (op.cmd === 'del') {
                                delete mockRedisData[op.key];
                                results.push([null, 1]);
                            } else if (op.cmd === 'hgetall') {
                                let data = mockRedisData[op.key];
                                if (!data || Object.keys(data).length === 0) {
                                    results.push([null, null]);
                                } else {
                                    results.push([null, { ...data }]);
                                }
                            }
                        } catch (err) {
                            results.push([err, null]);
                        }
                    }
                    return results;
                }
            };
            return pipeObj;
        },
        multi: () => {
            return {
                hset() {
                    return this;
                },
                hdel() {
                    return this;
                },
                del() {
                    return this;
                },
                expire() {
                    return this;
                },
                srem() {
                    return this;
                },
                hincrby() {
                    return this;
                },
                async exec() {
                    return [];
                }
            };
        },
        ttl: async () => 3600,
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

// Mock db module
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
        notifyQueue: { add: async () => ({}) },
        submitQueue: { add: async () => ({}) },
        documentsQueue: { add: async () => ({}) },
        exportQueue: { add: async () => ({}) },
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

// Now safe to import the module under test
const passkeys = require('../lib/passkeys');
const { REDIS_PREFIX } = require('../lib/consts');

test('Passkeys module tests', async t => {
    t.after(() => {
        setTimeout(() => process.exit(), 1000).unref();
    });

    t.beforeEach(() => {
        // Reset all mock data
        for (let key of Object.keys(mockRedisData)) delete mockRedisData[key];
        for (let key of Object.keys(mockRedisSets)) delete mockRedisSets[key];
        for (let key of Object.keys(mockRedisStrings)) delete mockRedisStrings[key];
    });

    // -- getRpConfig --

    await t.test('getRpConfig() returns nulls when serviceUrl is not set', async () => {
        let { rpId, origin } = await passkeys.getRpConfig();
        assert.strictEqual(rpId, null);
        assert.strictEqual(origin, null);
    });

    await t.test('getRpConfig() returns hostname and origin from serviceUrl', async () => {
        mockRedisData[`${REDIS_PREFIX}settings`] = {
            serviceUrl: JSON.stringify('https://mail.example.com:8080/path')
        };
        let { rpId, origin } = await passkeys.getRpConfig();
        assert.strictEqual(rpId, 'mail.example.com');
        assert.strictEqual(origin, 'https://mail.example.com:8080');
    });

    // -- storeChallenge / consumeChallenge --

    await t.test('storeChallenge() stores challenge and returns challengeId', async () => {
        let challengeId = await passkeys.storeChallenge('test-challenge-data');
        assert.strictEqual(typeof challengeId, 'string');
        assert.strictEqual(challengeId.length, 64); // 32 bytes hex
    });

    await t.test('consumeChallenge() retrieves and deletes challenge', async () => {
        let challengeId = await passkeys.storeChallenge('my-challenge');
        let challenge = await passkeys.consumeChallenge(challengeId);
        assert.strictEqual(challenge, 'my-challenge');

        // Second retrieval should return null (consumed)
        let again = await passkeys.consumeChallenge(challengeId);
        assert.strictEqual(again, null);
    });

    await t.test('consumeChallenge() returns null for invalid challengeId', async () => {
        let result = await passkeys.consumeChallenge('nonexistent');
        assert.strictEqual(result, null);
    });

    await t.test('consumeChallenge() returns null for null/undefined input', async () => {
        assert.strictEqual(await passkeys.consumeChallenge(null), null);
        assert.strictEqual(await passkeys.consumeChallenge(undefined), null);
        assert.strictEqual(await passkeys.consumeChallenge(''), null);
    });

    // -- saveCredential / getCredential --

    await t.test('saveCredential() stores credential and adds to user and global sets', async () => {
        await passkeys.saveCredential({
            id: 'cred-abc123',
            publicKey: 'pubkey-base64url',
            counter: 0,
            transports: ['internal'],
            name: 'My Passkey',
            user: 'admin'
        });

        let cred = await passkeys.getCredential('cred-abc123');
        assert.ok(cred);
        assert.strictEqual(cred.id, 'cred-abc123');
        assert.strictEqual(cred.publicKey, 'pubkey-base64url');
        assert.strictEqual(cred.counter, 0);
        assert.strictEqual(cred.name, 'My Passkey');
        assert.strictEqual(cred.user, 'admin');
        assert.deepStrictEqual(cred.transports, ['internal']);
        assert.ok(cred.createdAt);

        // Check the user set
        let setKey = `${REDIS_PREFIX}webauthn:creds:admin`;
        assert.ok(mockRedisSets[setKey]);
        assert.ok(mockRedisSets[setKey].has('cred-abc123'));

        // Check the global set
        let allSetKey = `${REDIS_PREFIX}webauthn:all`;
        assert.ok(mockRedisSets[allSetKey]);
        assert.ok(mockRedisSets[allSetKey].has('cred-abc123'));
    });

    await t.test('saveCredential() uses default name when not provided', async () => {
        await passkeys.saveCredential({
            id: 'cred-noname',
            publicKey: 'pk',
            counter: 0,
            transports: [],
            name: '',
            user: 'admin'
        });

        let cred = await passkeys.getCredential('cred-noname');
        assert.strictEqual(cred.name, 'Unnamed passkey');
    });

    await t.test('getCredential() returns null for nonexistent credential', async () => {
        let cred = await passkeys.getCredential('does-not-exist');
        assert.strictEqual(cred, null);
    });

    await t.test('getCredential() returns null for invalid input', async () => {
        assert.strictEqual(await passkeys.getCredential(null), null);
        assert.strictEqual(await passkeys.getCredential(''), null);
    });

    // -- updateCounter --

    await t.test('updateCounter() updates the counter value', async () => {
        await passkeys.saveCredential({
            id: 'cred-counter',
            publicKey: 'pk',
            counter: 5,
            transports: [],
            name: 'Test',
            user: 'admin'
        });

        await passkeys.updateCounter('cred-counter', 10);

        let cred = await passkeys.getCredential('cred-counter');
        assert.strictEqual(cred.counter, 10);
    });

    // -- listCredentials --

    await t.test('listCredentials() returns empty array when no passkeys exist', async () => {
        let creds = await passkeys.listCredentials('admin');
        assert.deepStrictEqual(creds, []);
    });

    await t.test('listCredentials() returns all credentials for a user', async () => {
        await passkeys.saveCredential({
            id: 'cred-1',
            publicKey: 'pk1',
            counter: 0,
            transports: ['internal'],
            name: 'Passkey 1',
            user: 'admin'
        });

        await passkeys.saveCredential({
            id: 'cred-2',
            publicKey: 'pk2',
            counter: 3,
            transports: ['usb'],
            name: 'Passkey 2',
            user: 'admin'
        });

        let creds = await passkeys.listCredentials('admin');
        assert.strictEqual(creds.length, 2);

        let ids = creds.map(c => c.id).sort();
        assert.deepStrictEqual(ids, ['cred-1', 'cred-2']);
    });

    await t.test('listCredentials() does not return credentials for other users', async () => {
        await passkeys.saveCredential({
            id: 'cred-admin',
            publicKey: 'pk',
            counter: 0,
            transports: [],
            name: 'Admin Key',
            user: 'admin'
        });

        await passkeys.saveCredential({
            id: 'cred-other',
            publicKey: 'pk',
            counter: 0,
            transports: [],
            name: 'Other Key',
            user: 'otheruser'
        });

        let adminCreds = await passkeys.listCredentials('admin');
        assert.strictEqual(adminCreds.length, 1);
        assert.strictEqual(adminCreds[0].id, 'cred-admin');

        let otherCreds = await passkeys.listCredentials('otheruser');
        assert.strictEqual(otherCreds.length, 1);
        assert.strictEqual(otherCreds[0].id, 'cred-other');
    });

    // -- deleteCredential --

    await t.test('deleteCredential() removes credential and set membership', async () => {
        await passkeys.saveCredential({
            id: 'cred-del',
            publicKey: 'pk',
            counter: 0,
            transports: [],
            name: 'To Delete',
            user: 'admin'
        });

        let before = await passkeys.getCredential('cred-del');
        assert.ok(before);

        await passkeys.deleteCredential('cred-del', 'admin');

        let after = await passkeys.getCredential('cred-del');
        assert.strictEqual(after, null);

        let setKey = `${REDIS_PREFIX}webauthn:creds:admin`;
        assert.ok(!mockRedisSets[setKey] || !mockRedisSets[setKey].has('cred-del'));

        let allSetKey = `${REDIS_PREFIX}webauthn:all`;
        assert.ok(!mockRedisSets[allSetKey] || !mockRedisSets[allSetKey].has('cred-del'));
    });

    // -- hasPasskeys --

    await t.test('hasPasskeys() returns false when no passkeys exist', async () => {
        let has = await passkeys.hasPasskeys();
        assert.strictEqual(has, false);
    });

    await t.test('hasPasskeys() returns true when passkeys exist', async () => {
        await passkeys.saveCredential({
            id: 'cred-exists',
            publicKey: 'pk',
            counter: 0,
            transports: [],
            name: 'Exists',
            user: 'admin'
        });

        let has = await passkeys.hasPasskeys();
        assert.strictEqual(has, true);
    });

    // -- getAllCredentials --

    await t.test('getAllCredentials() returns credentials across all users', async () => {
        await passkeys.saveCredential({
            id: 'cred-a',
            publicKey: 'pk-a',
            counter: 0,
            transports: ['internal'],
            name: 'Admin Key',
            user: 'admin'
        });

        await passkeys.saveCredential({
            id: 'cred-b',
            publicKey: 'pk-b',
            counter: 1,
            transports: ['usb'],
            name: 'Other Key',
            user: 'otheruser'
        });

        let all = await passkeys.getAllCredentials();
        assert.strictEqual(all.length, 2);

        let ids = all.map(c => c.id).sort();
        assert.deepStrictEqual(ids, ['cred-a', 'cred-b']);

        let users = all.map(c => c.user).sort();
        assert.deepStrictEqual(users, ['admin', 'otheruser']);
    });

    await t.test('getAllCredentials() returns empty array when no passkeys exist', async () => {
        let all = await passkeys.getAllCredentials();
        assert.deepStrictEqual(all, []);
    });

    // -- counter parsing --

    await t.test('getCredential() parses counter as integer', async () => {
        await passkeys.saveCredential({
            id: 'cred-cparse',
            publicKey: 'pk',
            counter: 42,
            transports: [],
            name: 'Test',
            user: 'admin'
        });

        let cred = await passkeys.getCredential('cred-cparse');
        assert.strictEqual(typeof cred.counter, 'number');
        assert.strictEqual(cred.counter, 42);
    });

    // -- multiple passkeys for same user --

    await t.test('supports multiple passkeys for the same user', async () => {
        for (let i = 0; i < 5; i++) {
            await passkeys.saveCredential({
                id: `multi-${i}`,
                publicKey: `pk-${i}`,
                counter: i,
                transports: ['internal'],
                name: `Key ${i}`,
                user: 'admin'
            });
        }

        let creds = await passkeys.listCredentials('admin');
        assert.strictEqual(creds.length, 5);

        // delete one and verify
        await passkeys.deleteCredential('multi-2', 'admin');
        creds = await passkeys.listCredentials('admin');
        assert.strictEqual(creds.length, 4);
        assert.ok(!creds.find(c => c.id === 'multi-2'));
    });
});
