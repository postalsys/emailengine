'use strict';

// Account data layer: what is decrypted when, what is encrypted at rest, and how writes behave
// around the update lock and the worker dispatch.
//
//   - listAccounts() and the delegated-row lookups never decrypt a credential. Each stored value
//     has its own salt, so a cold decrypt is a synchronous scrypt, and a 1000-account page used to
//     run a few thousand of them on the API worker's event loop for fields the listing never
//     outputs.
//   - The per-account `webhooks`, `webhooksCustomHeaders` and `proxy` fields carry credentials
//     like the global settings of the same name, and are encrypted at rest like them. Values
//     stored before that are cleartext and must keep reading.
//   - Token renewal writes only the token fields, and only while the stored grant is still the
//     one it used, so a re-authorization landing during the provider round trip is not undone.
//   - A failed dispatch to the worker after a successful write does not turn the saved change into
//     an error response.

const test = require('node:test');
const assert = require('node:assert').strict;

// A prefix carrying glob metacharacters, so the SCAN patterns built from it can be checked for
// escaping. Everything below runs against stubs, so no real key is ever named with it.
process.env.EENGINE_REDIS_PREFIX = 'ee[t]*';

// Count every value the account module decrypts, through decrypt() (the credential blobs) and
// through decryptField() (the credential-bearing fields, which reaches decrypt() inside its own
// module where no wrapper can see it). The wrappers are installed in the require cache before
// lib/account.js destructures its import, which is the only point where they can be seen.
const encryptPath = require.resolve('../lib/encrypt');
const realEncrypt = require('../lib/encrypt');
const decryptCalls = [];
require.cache[encryptPath].exports = Object.assign({}, realEncrypt, {
    decrypt(value, secret) {
        decryptCalls.push(value);
        return realEncrypt.decrypt(value, secret);
    },
    decryptField(value, secret, onError) {
        if (secret && value) {
            decryptCalls.push(value);
        }
        return realEncrypt.decryptField(value, secret, onError);
    }
});
const { encrypt, decrypt } = realEncrypt;

// Mock the db module before importing account.js so no real Redis/BullMQ connections open.
const mockQueue = { add: async () => ({}), close: async () => {}, on: () => {}, off: () => {} };
function createMockRedis() {
    return {
        status: 'ready',
        hget: async () => null,
        hmget: async (key, ...fields) => fields.map(() => null),
        hset: async () => {},
        hdel: async () => {},
        hgetall: async () => ({}),
        hgetallBuffer: async () => ({}),
        get: async () => null,
        set: async () => 'OK',
        exists: async () => 0,
        quit: async () => {},
        disconnect: () => {},
        subscribe: async () => {},
        on: () => {},
        off: () => {},
        defineCommand: () => {},
        duplicate() {
            return createMockRedis();
        }
    };
}

const dbPath = require.resolve('../lib/db');
require.cache[dbPath] = {
    id: dbPath,
    filename: dbPath,
    loaded: true,
    parent: null,
    children: [],
    exports: {
        redis: createMockRedis(),
        queueConf: { connection: {} },
        notifyQueue: mockQueue,
        submitQueue: mockQueue,
        exportQueue: mockQueue,
        REDIS_CONF: {},
        getRedisURL: () => 'redis://mock'
    }
};

const { Account, ENCRYPTED_ACCOUNT_FIELDS } = require('../lib/account');
const { oauth2Apps } = require('../lib/oauth2-apps');
const { createMockLogger } = require('./helpers/mock-logger');

const SECRET = 'account-data-layer-test-secret';

function createLock(events) {
    return {
        waitAcquireLock: async key => {
            events.push({ event: 'acquire', key });
            return { success: true, id: key };
        },
        releaseLock: async held => {
            events.push({ event: 'release', key: held.id });
        }
    };
}

function createAccount(extra) {
    return Object.assign(Object.create(Account.prototype), { secret: SECRET, logger: createMockLogger(), timeout: 1000, account: 'acc' }, extra || {});
}

test('ENCRYPTED_ACCOUNT_FIELDS names the credential-bearing account fields', () => {
    assert.deepStrictEqual(ENCRYPTED_ACCOUNT_FIELDS.slice().sort(), ['proxy', 'webhooks', 'webhooksCustomHeaders']);
});

test('credential-bearing account fields are encrypted at rest', async t => {
    const accountObject = createAccount();
    const headers = [{ key: 'Authorization', value: 'Bearer abc' }];

    const stored = accountObject.serializeAccountData({
        account: 'acc',
        webhooks: 'https://hook:s3cret@example.com/wh',
        webhooksCustomHeaders: headers,
        proxy: 'socks5://user:pass@127.0.0.1:1080'
    });

    await t.test('stored as ciphertext', () => {
        for (const key of ENCRYPTED_ACCOUNT_FIELDS) {
            assert.ok(stored[key].startsWith('$wd02$'), `${key} must be stored encrypted`);
            assert.ok(!/s3cret|Bearer|pass@/.test(stored[key]), `${key} must not be stored in the clear`);
        }
    });

    await t.test('read back intact', () => {
        const data = accountObject.unserializeAccountData(stored);
        assert.strictEqual(data.webhooks, 'https://hook:s3cret@example.com/wh');
        assert.deepStrictEqual(data.webhooksCustomHeaders, headers);
        assert.strictEqual(data.proxy, 'socks5://user:pass@127.0.0.1:1080');
    });

    await t.test('values stored in the clear before encryption still read', () => {
        const data = accountObject.unserializeAccountData({
            account: 'acc',
            webhooks: 'https://legacy@example.com/wh',
            webhooksCustomHeaders: JSON.stringify(headers),
            proxy: 'http://proxy.example.com:3128'
        });
        assert.strictEqual(data.webhooks, 'https://legacy@example.com/wh');
        assert.deepStrictEqual(data.webhooksCustomHeaders, headers);
        assert.strictEqual(data.proxy, 'http://proxy.example.com:3128');
    });

    await t.test('a cleared webhook URL stays the empty marker', () => {
        const cleared = accountObject.serializeAccountData({ webhooks: '' });
        assert.strictEqual(cleared.webhooks, '');
        assert.strictEqual(cleared.webhookErrorFlag, '{}');
    });

    await t.test('without a secret the fields are stored as before', () => {
        const plain = createAccount({ secret: undefined }).serializeAccountData({ webhooks: 'https://example.com/wh', webhooksCustomHeaders: headers });
        assert.strictEqual(plain.webhooks, 'https://example.com/wh');
        assert.strictEqual(plain.webhooksCustomHeaders, JSON.stringify(headers));
    });

    await t.test('a value that does not decrypt reads as unset instead of failing the account', () => {
        const other = encrypt('https://example.com/wh', 'some-other-secret');
        const data = accountObject.unserializeAccountData({
            account: 'acc',
            name: 'Name',
            webhooks: other,
            webhooksCustomHeaders: encrypt('[]', 'some-other-secret')
        });
        assert.strictEqual(data.name, 'Name');
        assert.ok(!('webhooks' in data));
        assert.ok(!('webhooksCustomHeaders' in data));
    });
});

test('skipDecrypt leaves every encrypted value alone', () => {
    const accountObject = createAccount();
    const row = {
        account: 'acc',
        imap: JSON.stringify({ host: 'imap.example.com', auth: { user: 'u', pass: encrypt('imap-pass', SECRET) } }),
        oauth2: JSON.stringify({ provider: 'app', auth: { user: 'u' }, accessToken: encrypt('at', SECRET), refreshToken: encrypt('rt', SECRET) }),
        webhooks: encrypt('https://example.com/wh', SECRET),
        webhooksCustomHeaders: encrypt('[]', SECRET)
    };

    decryptCalls.length = 0;
    const data = accountObject.unserializeAccountData(row, { skipDecrypt: true });
    assert.strictEqual(decryptCalls.length, 0);
    assert.strictEqual(data.imap.auth.pass, JSON.parse(row.imap).auth.pass);
    assert.strictEqual(data.oauth2.provider, 'app');
    assert.strictEqual(data.webhooks, row.webhooks);
    assert.ok(!('webhooksCustomHeaders' in data), 'an encrypted header list is left out rather than failing to parse');

    // and the default still decrypts
    const full = accountObject.unserializeAccountData(row);
    assert.strictEqual(full.imap.auth.pass, 'imap-pass');
    assert.strictEqual(full.oauth2.accessToken, 'at');
    assert.strictEqual(full.oauth2.refreshToken, 'rt');
});

test('listAccounts decrypts no credential', async () => {
    // Flat HGETALL replies, as s-list-accounts.lua returns them
    const flat = obj => Object.entries(obj).flat();
    const rows = [
        {
            account: 'imap-acc',
            state: 'connected',
            imap: JSON.stringify({ host: 'imap.example.com', auth: { user: 'u', pass: encrypt('p1', SECRET) } }),
            smtp: JSON.stringify({ host: 'smtp.example.com', auth: { user: 'u', pass: encrypt('p2', SECRET) } })
        },
        {
            account: 'oauth-acc',
            state: 'connected',
            oauth2: JSON.stringify({
                provider: 'missing-app',
                auth: { user: 'u@example.com' },
                accessToken: encrypt('at', SECRET),
                refreshToken: encrypt('rt', SECRET)
            })
        },
        {
            account: 'hook-acc',
            state: 'connected',
            imap: JSON.stringify({ host: 'imap.example.com', auth: { user: 'u', pass: encrypt('p3', SECRET) } }),
            webhooks: encrypt('https://hook:pw@example.com/wh', SECRET),
            proxy: 'http://legacy-cleartext-proxy:3128'
        },
        {
            account: 'delegating-acc',
            state: 'connected',
            oauth2: JSON.stringify({ auth: { user: 'shared@example.com', delegatedAccount: 'oauth-acc' } })
        }
    ];

    const storedById = Object.fromEntries(rows.map(row => [row.account, row]));
    const accountObject = createAccount({
        account: false,
        call: async () => 1,
        redis: Object.assign(createMockRedis(), {
            sListAccounts: async () => [rows.length, 0, rows.map(flat)],
            hgetall: async key => storedById[key.split(':').pop()] || {},
            hget: async (key, field) => ((storedById[key.split(':').pop()] || {})[field] ? storedById[key.split(':').pop()][field] : null)
        })
    });

    const origGet = oauth2Apps.get;
    oauth2Apps.get = async () => null;
    try {
        decryptCalls.length = 0;
        const list = await accountObject.listAccounts('*', '', 0, 20);

        assert.strictEqual(list.accounts.length, 4);
        // only the one credential-bearing URL the listing outputs, and only for the row that set it
        assert.deepStrictEqual(decryptCalls, [rows[2].webhooks, rows[2].proxy]);

        const hook = list.accounts.find(entry => entry.account === 'hook-acc');
        assert.strictEqual(hook.webhooks, 'https://hook:pw@example.com/wh');
        assert.strictEqual(hook.proxy, 'http://legacy-cleartext-proxy:3128');
    } finally {
        oauth2Apps.get = origGet;
    }
});

test('token renewal writes only the token fields, and only over the grant it used', async t => {
    const stored = {
        account: 'acc',
        proxy: 'socks5://account-proxy.example.com:1080',
        oauth2: {
            provider: 'app',
            auth: { user: 'u@example.com' },
            accessToken: 'OLD-AT',
            refreshToken: 'RT-1',
            scope: ['a', 'b'],
            expires: new Date(Date.now() - 1000)
        }
    };

    const origGetClient = oauth2Apps.getClient;
    t.after(() => {
        oauth2Apps.getClient = origGetClient;
    });
    oauth2Apps.getClient = async (id, opts) => ({
        refreshToken: async ({ refreshToken }) => {
            assert.strictEqual(refreshToken, 'RT-1');
            // the client is bound to the account's own proxy, as its IMAP connection would be
            assert.deepStrictEqual(opts.route, { proxy: stored.proxy, localAddress: null });
            return { access_token: 'NEW-AT', expires_in: 3600 };
        }
    });

    await t.test('the write is a partial token update guarded by the refresh token used', async () => {
        const updates = [];
        const accountObject = createAccount({
            getLock: () => createLock([]),
            loadAccountData: async () => structuredClone(stored),
            update: async (data, opts) => {
                updates.push({ data, opts });
                return { account: 'acc' };
            }
        });

        const result = await accountObject.renewAccessToken();

        assert.strictEqual(updates.length, 1);
        const { data, opts } = updates[0];
        assert.strictEqual(data.oauth2.partial, true);
        assert.strictEqual(data.oauth2.accessToken, 'NEW-AT');
        assert.strictEqual(data.oauth2.userFlag, null);
        for (const key of ['refreshToken', 'scope', 'auth', 'provider']) {
            assert.ok(!(key in data.oauth2), `${key} must not be written back from the snapshot`);
        }
        assert.deepStrictEqual(opts, { expectedRefreshToken: 'RT-1' });
        assert.strictEqual(result.oauth2.accessToken, 'NEW-AT');
    });

    await t.test('a skipped write returns the account as stored now', async () => {
        const reauthorized = Object.assign(structuredClone(stored), {
            oauth2: Object.assign(structuredClone(stored.oauth2), { accessToken: 'REAUTH-AT', refreshToken: 'RT-2' })
        });
        let loads = 0;
        const accountObject = createAccount({
            getLock: () => createLock([]),
            // the reads before the write are the renewal's own snapshot
            loadAccountData: async () => (++loads, structuredClone(stored)),
            // the skipped write hands back what it read under the lock
            update: async () => ({ account: 'acc', skipped: true, current: structuredClone(reauthorized) })
        });

        const result = await accountObject.renewAccessToken();
        assert.strictEqual(result.oauth2.accessToken, 'REAUTH-AT');
        assert.strictEqual(result.oauth2.refreshToken, 'RT-2');
        assert.strictEqual(loads, 2, 'the skipped write is not followed by a third read');
    });

    await t.test('update() skips the write when the stored refresh token changed', async () => {
        let persisted = 0;
        const events = [];
        const accountObject = createAccount({
            getLock: () => createLock(events),
            loadAccountData: async () => ({ account: 'acc', oauth2: { refreshToken: 'RT-2' } }),
            persistUpdate: async () => {
                persisted++;
                return {};
            },
            call: async () => true
        });

        const result = await accountObject.update({ account: 'acc', oauth2: { partial: true, accessToken: 'NEW-AT' } }, { expectedRefreshToken: 'RT-1' });
        // the record read for the check is handed back, so the renewal need not read it again
        assert.deepStrictEqual(result, { account: 'acc', skipped: true, current: { account: 'acc', oauth2: { refreshToken: 'RT-2' } } });
        assert.strictEqual(persisted, 0);
        assert.deepStrictEqual(
            events.map(e => e.event),
            ['acquire', 'release']
        );
    });

    await t.test('update() writes when the stored refresh token still matches, from one read', async () => {
        let persisted = 0;
        let loads = 0;
        const accountObject = createAccount({
            getLock: () => createLock([]),
            loadAccountData: async () => (++loads, { account: 'acc', oauth2: { refreshToken: 'RT-1' } }),
            persistUpdate: async (data, oldAccountData) => {
                persisted++;
                // the record read for the check is handed on, so the write does not read again
                assert.deepStrictEqual(oldAccountData, { account: 'acc', oauth2: { refreshToken: 'RT-1' } });
                return oldAccountData;
            },
            call: async () => true
        });

        const result = await accountObject.update({ account: 'acc', oauth2: { partial: true, accessToken: 'NEW-AT' } }, { expectedRefreshToken: 'RT-1' });
        assert.deepStrictEqual(result, { account: 'acc' });
        assert.strictEqual(persisted, 1);
        assert.strictEqual(loads, 1);
    });
});

test('create() runs the uniqueness check and the write under the update lock', async () => {
    const events = [];
    const multi = () => {
        const chain = {};
        for (const cmd of ['hgetall', 'hmset', 'hsetnx', 'sadd', 'hset']) {
            chain[cmd] = () => chain;
        }
        chain.exec = async () => {
            events.push({ event: 'exec' });
            return [
                [null, {}],
                [null, 'OK']
            ];
        };
        return chain;
    };

    const origGet = oauth2Apps.get;
    oauth2Apps.get = async () => ({ id: 'app', provider: 'gmail', baseScopes: 'api' });
    try {
        const accountObject = createAccount({
            getLock: () => createLock(events),
            call: async message => {
                events.push({ event: 'call', cmd: message.cmd });
                return 1;
            },
            redis: Object.assign(createMockRedis(), {
                multi,
                hget: async key => {
                    events.push({ event: 'uniqueness', key });
                    return null;
                }
            })
        });

        const result = await accountObject.create({ account: 'acc', oauth2: { provider: 'app', auth: { user: 'u@example.com' } } });
        assert.strictEqual(result.state, 'new');

        assert.deepStrictEqual(
            events.map(e => e.event + (e.cmd ? `:${e.cmd}` : '')),
            ['call:runIndex', 'acquire', 'uniqueness', 'exec', 'release', 'call:new']
        );
        assert.strictEqual(events.find(e => e.event === 'acquire').key, 'account:update:acc');
    } finally {
        oauth2Apps.get = origGet;
    }
});

test('a failed worker dispatch after a saved change is not an error', async t => {
    const failingCall = async message => {
        if (message.cmd === 'runIndex') {
            return 1;
        }
        const err = new Error('Timeout waiting for command response');
        err.statusCode = 504;
        throw err;
    };

    await t.test('create() of a new account', async () => {
        const multi = () => {
            const chain = {};
            for (const cmd of ['hgetall', 'hmset', 'hsetnx', 'sadd', 'hset']) {
                chain[cmd] = () => chain;
            }
            chain.exec = async () => [
                [null, {}],
                [null, 'OK']
            ];
            return chain;
        };
        const accountObject = createAccount({ getLock: () => createLock([]), call: failingCall, redis: Object.assign(createMockRedis(), { multi }) });
        const result = await accountObject.create({ account: 'acc', imap: { host: 'imap.example.com' }, imapIndexer: 'full' });
        assert.deepStrictEqual(result, { account: 'acc', state: 'new' });
        assert.ok(accountObject.logger.entries.some(entry => entry.level === 'error' && entry.cmd === 'new'));
    });

    await t.test('update() that changes the IMAP settings', async () => {
        const accountObject = createAccount({
            getLock: () => createLock([]),
            call: failingCall,
            persistUpdate: async () => ({ account: 'acc', state: 'connected', imap: { host: 'old.example.com' } })
        });
        const result = await accountObject.update({ account: 'acc', imap: { host: 'new.example.com' } });
        assert.deepStrictEqual(result, { account: 'acc' });
        assert.ok(accountObject.logger.entries.some(entry => entry.level === 'error' && entry.cmd === 'update'));
    });

    await t.test('delete()', async () => {
        const multi = () => {
            const chain = {};
            for (const cmd of ['hkeys', 'unlink', 'srem', 'hdel']) {
                chain[cmd] = () => chain;
            }
            chain.exec = async () => [
                [null, []],
                [null, 1]
            ];
            return chain;
        };
        const { Readable } = require('stream');
        const scanMatches = [];
        const accountObject = createAccount({
            call: failingCall,
            loadAccountData: async () => ({ account: 'acc' }),
            redis: Object.assign(createMockRedis(), {
                multi,
                scanStream: opts => {
                    scanMatches.push(opts.match);
                    return Readable.from([], { objectMode: true });
                },
                pipeline: () => ({ del() {}, exec: cb => cb(null, []) })
            })
        });
        const tokens = require('../lib/tokens');
        const origDeleteForAccount = tokens.deleteForAccount;
        tokens.deleteForAccount = async () => 0;
        try {
            const result = await accountObject.delete();
            assert.deepStrictEqual(result, { account: 'acc', deleted: true });
            assert.ok(accountObject.logger.entries.some(entry => entry.level === 'error' && entry.cmd === 'delete'));
            // The instance prefix is escaped like the account id: unescaped, `*` in it matched the
            // log keys of every account on a shared Redis
            assert.deepStrictEqual(scanMatches, ['ee\\[t\\]\\*:iam:acc:*']);
        } finally {
            tokens.deleteForAccount = origDeleteForAccount;
        }
    });
});

test('decrypt spy sanity', () => {
    // guards the premise of the listing test: the wrapper is what lib/account.js calls
    decryptCalls.length = 0;
    createAccount().unserializeAccountData({ account: 'acc', webhooks: encrypt('x', SECRET) });
    assert.strictEqual(decryptCalls.length, 1);
    assert.strictEqual(decrypt(encrypt('x', SECRET), SECRET), 'x');
});
