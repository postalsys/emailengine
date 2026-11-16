'use strict';

// Pins the account hash codec: serializeAccountData() turns an account object into the strings
// stored in Redis and unserializeAccountData() turns them back. Both run on every account read
// and write, so these tests compare whole outputs (deepStrictEqual, which tells a missing key from
// one holding undefined) and the key order of the stored hash, rather than spot-checking fields.

const test = require('node:test');
const assert = require('node:assert').strict;

require('./helpers/mock-db').installDbMock();

const { Account } = require('../lib/account');
const { encrypt, decrypt } = require('../lib/encrypt');
const { createMockLogger } = require('./helpers/mock-logger');
const exitWhenStandalone = require('./helpers/exit-standalone');

exitWhenStandalone();

const SECRET = 'account-serialize-test-secret';

function createAccount(extra) {
    return Object.assign(Object.create(Account.prototype), { logger: createMockLogger(), account: 'acc' }, extra || {});
}

const CREATED = new Date('2026-01-02T03:04:05.000Z');
const EXPIRES = new Date('2026-02-03T04:05:06.000Z');

// Every kind of field the codec treats differently, with the values a running instance stores
function fullAccount() {
    return {
        _internal: 'never stored',
        account: 'acc',
        name: 'Example Account',
        email: 'user@example.com',
        notifyFrom: new Date('2026-03-04T05:06:07.000Z'),
        lastWatch: '2026-03-05T06:07:08.000Z',
        path: ['INBOX', 'Sent'],
        copy: true,
        logs: false,
        expectedEmail: 'user@example.com',
        webhooks: 'https://hook.example.com/wh',
        webhooksCustomHeaders: [{ key: 'X-Token', value: 'abc' }],
        proxy: 'socks5://127.0.0.1:1080',
        subconnections: ['[Gmail]/Spam'],
        watchResponse: { historyId: '1234', expiration: '1777777777000' },
        outlookSubscription: { id: 'sub-1', expirationDateTime: '2026-04-05T06:07:08.000Z', clientState: 'cs' },
        imap: {
            auth: { user: 'user@example.com', pass: 'imap-secret' },
            host: 'imap.example.com',
            port: 993,
            secure: true,
            created: CREATED
        },
        smtp: {
            auth: { user: 'user@example.com', pass: 'smtp-secret' },
            host: 'smtp.example.com',
            port: 465,
            secure: true
        },
        oauth2: {
            provider: 'app-1',
            auth: { user: 'user@example.com' },
            accessToken: 'access-token',
            refreshToken: 'refresh-token',
            expires: EXPIRES,
            generated: CREATED
        },
        connections: 3,
        runIndex: 7,
        syncFrom: null,
        notSet: undefined
    };
}

test('serializeAccountData() without a secret', async t => {
    const accountObject = createAccount();

    await t.test('a full account becomes these exact hash fields, in this order', () => {
        const stored = accountObject.serializeAccountData(fullAccount());
        const expected = {
            account: 'acc',
            name: 'Example Account',
            email: 'user@example.com',
            notifyFrom: '2026-03-04T05:06:07.000Z',
            lastWatch: '2026-03-05T06:07:08.000Z',
            path: '["INBOX","Sent"]',
            copy: 'true',
            logs: 'false',
            expectedEmail: 'user@example.com',
            webhooks: 'https://hook.example.com/wh',
            webhooksCustomHeaders: '[{"key":"X-Token","value":"abc"}]',
            proxy: 'socks5://127.0.0.1:1080',
            subconnections: '["[Gmail]/Spam"]',
            watchResponse: '{"historyId":"1234","expiration":"1777777777000"}',
            outlookSubscription: '{"id":"sub-1","expirationDateTime":"2026-04-05T06:07:08.000Z","clientState":"cs"}',
            imap: '{"auth":{"user":"user@example.com","pass":"imap-secret"},"host":"imap.example.com","port":993,"secure":true,"created":"2026-01-02T03:04:05.000Z"}',
            smtp: '{"auth":{"user":"user@example.com","pass":"smtp-secret"},"host":"smtp.example.com","port":465,"secure":true}',
            oauth2: '{"provider":"app-1","auth":{"user":"user@example.com"},"accessToken":"access-token","refreshToken":"refresh-token","expires":"2026-02-03T04:05:06.000Z","generated":"2026-01-02T03:04:05.000Z"}',
            connections: '3',
            runIndex: '7'
        };
        assert.deepStrictEqual(stored, expected);
        assert.deepStrictEqual(Object.keys(stored), Object.keys(expected));
    });

    await t.test('date fields', () => {
        const encode = value => accountObject.serializeAccountData({ notifyFrom: value });
        assert.deepStrictEqual(encode(null), { notifyFrom: 'null' });
        assert.deepStrictEqual(encode('not a date'), {});
        assert.deepStrictEqual(encode(new Date('invalid')), {});
        assert.deepStrictEqual(encode(1700000000000), {});
        assert.deepStrictEqual(encode(undefined), {});
        assert.deepStrictEqual(encode('2026-03-04'), { notifyFrom: '2026-03-04T00:00:00.000Z' });

        const before = Date.now();
        const now = encode('now').notifyFrom;
        assert.match(now, /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/);
        assert.ok(Date.parse(now) >= before - 1000 && Date.parse(now) <= Date.now() + 1000);
    });

    await t.test('path variants', () => {
        const encode = value => accountObject.serializeAccountData({ path: value });
        assert.deepStrictEqual(encode(null), { path: '' });
        assert.deepStrictEqual(encode('*'), { path: '' });
        assert.deepStrictEqual(encode([]), { path: '' });
        assert.deepStrictEqual(encode(['*']), { path: '' });
        assert.deepStrictEqual(encode(['*', 'INBOX']), { path: '["*","INBOX"]' });
        assert.deepStrictEqual(encode('INBOX'), { path: '"INBOX"' });
        assert.deepStrictEqual(encode(['INBOX']), { path: '["INBOX"]' });
        // JSON.stringify(undefined) is undefined: the key is present and holds undefined
        assert.deepStrictEqual(encode(undefined), { path: undefined });
    });

    await t.test('boolean and clearable fields', () => {
        const encode = data => accountObject.serializeAccountData(data);
        assert.deepStrictEqual(encode({ copy: false, logs: true }), { copy: 'false', logs: 'true' });
        assert.deepStrictEqual(encode({ copy: null, logs: 'yes' }), { copy: '' });
        assert.deepStrictEqual(encode({ expectedEmail: null }), { expectedEmail: '' });
        assert.deepStrictEqual(encode({ expectedEmail: '' }), { expectedEmail: '' });
        assert.deepStrictEqual(encode({ expectedEmail: undefined }), {});
        assert.deepStrictEqual(encode({ expectedEmail: 5 }), {});
    });

    await t.test('JSON, encrypted and generic fields', () => {
        const encode = data => accountObject.serializeAccountData(data);
        assert.deepStrictEqual(encode({ webhooksCustomHeaders: null }), { webhooksCustomHeaders: 'null' });
        assert.deepStrictEqual(encode({ webhooksCustomHeaders: undefined }), { webhooksCustomHeaders: undefined });
        assert.deepStrictEqual(encode({ watchFailure: undefined, watchResponse: null }), { watchFailure: undefined, watchResponse: 'null' });
        assert.deepStrictEqual(encode({ proxy: null, webhooks: undefined }), {});
        assert.deepStrictEqual(encode({ proxy: false }), { proxy: 'false' });
        assert.deepStrictEqual(encode({ name: 5, lastErrorState: { a: 1 }, note: null }), { name: '5', lastErrorState: '[object Object]' });
    });

    await t.test('outlookSubscription expiry', () => {
        const encode = expirationDateTime => accountObject.serializeAccountData({ outlookSubscription: { id: 's', expirationDateTime } });
        assert.deepStrictEqual(encode(EXPIRES), { outlookSubscription: '{"id":"s","expirationDateTime":"2026-02-03T04:05:06.000Z"}' });
        assert.deepStrictEqual(encode(EXPIRES.getTime()), { outlookSubscription: '{"id":"s","expirationDateTime":"2026-02-03T04:05:06.000Z"}' });
        assert.deepStrictEqual(encode('garbage'), { outlookSubscription: '{"id":"s","expirationDateTime":null}' });
        assert.deepStrictEqual(encode(null), { outlookSubscription: '{"id":"s","expirationDateTime":null}' });
        assert.deepStrictEqual(encode(undefined), { outlookSubscription: '{"id":"s"}' });
        assert.deepStrictEqual(accountObject.serializeAccountData({ outlookSubscription: null }), { outlookSubscription: '{}' });
    });

    await t.test('connection objects', () => {
        const logger = createMockLogger();
        const encode = data => createAccount({ logger }).serializeAccountData(data);
        // An invalid date subkey is kept as JSON.stringify writes it
        assert.deepStrictEqual(encode({ imap: { host: 'h', created: new Date('invalid') } }), { imap: '{"host":"h","created":null}' });
        // A string subkey is not an object, so the copy keeps it unchanged
        assert.deepStrictEqual(encode({ smtp: { expires: '2026-01-01' } }), { smtp: '{"expires":"2026-01-01"}' });
        // Not serializable: logged, field left out
        assert.deepStrictEqual(encode({ oauth2: undefined }), {});
        assert.deepStrictEqual(encode({ imap: null }), {});
        assert.deepStrictEqual(
            logger.entries.map(entry => [entry.msg, entry.key]),
            [
                ['Failed to stringify input for Redis', 'oauth2'],
                ['Failed to stringify input for Redis', 'imap']
            ]
        );
    });

    await t.test('clearing webhooks resets the error flag, whichever key comes first', () => {
        const encode = data => accountObject.serializeAccountData(data);
        assert.deepStrictEqual(encode({ webhooks: '' }), { webhookErrorFlag: '{}', webhooks: '' });
        assert.deepStrictEqual(Object.keys(encode({ webhooks: '' })), ['webhookErrorFlag', 'webhooks']);

        // A later webhookErrorFlag key overwrites the reset, an earlier one is overwritten by it,
        // and the stored key keeps the position of its first write
        const flagLast = encode({ webhooks: '', webhookErrorFlag: '{"error":"x"}' });
        assert.deepStrictEqual(flagLast, { webhookErrorFlag: '{"error":"x"}', webhooks: '' });
        assert.deepStrictEqual(Object.keys(flagLast), ['webhookErrorFlag', 'webhooks']);

        const flagFirst = encode({ webhookErrorFlag: '{"error":"x"}', webhooks: '' });
        assert.deepStrictEqual(flagFirst, { webhookErrorFlag: '{}', webhooks: '' });
        assert.deepStrictEqual(Object.keys(flagFirst), ['webhookErrorFlag', 'webhooks']);

        // A non-empty value leaves the flag alone
        assert.deepStrictEqual(encode({ webhookErrorFlag: '{"error":"x"}', webhooks: 'https://example.com' }), {
            webhookErrorFlag: '{"error":"x"}',
            webhooks: 'https://example.com'
        });
    });
});

test('serializeAccountData() with a secret', async t => {
    const logger = createMockLogger();
    const accountObject = createAccount({ secret: SECRET, logger });

    await t.test('credentials and credential-bearing fields are stored encrypted', () => {
        const stored = accountObject.serializeAccountData(fullAccount());

        for (const key of ['webhooks', 'webhooksCustomHeaders', 'proxy']) {
            assert.ok(stored[key].startsWith('$wd02$'), key);
        }
        assert.equal(decrypt(stored.webhooks, SECRET), 'https://hook.example.com/wh');
        assert.equal(decrypt(stored.webhooksCustomHeaders, SECRET), '[{"key":"X-Token","value":"abc"}]');

        const imap = JSON.parse(stored.imap);
        assert.ok(imap.auth.pass.startsWith('$wd02$'));
        assert.equal(decrypt(imap.auth.pass, SECRET), 'imap-secret');
        assert.equal(imap.auth.user, 'user@example.com');

        // oauth2 keeps its tokens beside auth, not inside it
        const oauth2 = JSON.parse(stored.oauth2);
        assert.equal(decrypt(oauth2.accessToken, SECRET), 'access-token');
        assert.equal(decrypt(oauth2.refreshToken, SECRET), 'refresh-token');
        assert.deepStrictEqual(Object.keys(oauth2), ['provider', 'auth', 'accessToken', 'refreshToken', 'expires', 'generated']);
        assert.equal(oauth2.expires, '2026-02-03T04:05:06.000Z');

        // the caller's object is not touched
        const input = fullAccount();
        accountObject.serializeAccountData(input);
        assert.equal(input.imap.auth.pass, 'imap-secret');
    });

    await t.test('a credential that does not encrypt is logged under its own name and kept', () => {
        logger.entries.length = 0;
        const stored = accountObject.serializeAccountData({ smtp: { auth: { user: 'u', pass: 12345 } } });
        assert.deepStrictEqual(JSON.parse(stored.smtp), { auth: { user: 'u', pass: 12345 } });
        assert.deepStrictEqual(
            logger.entries.map(entry => [entry.level, entry.msg, entry.key, entry.account]),
            [['error', 'Failed to encrypt value', 'pass', 'acc']]
        );
    });

    await t.test('no auth object, nothing encrypted', () => {
        assert.deepStrictEqual(accountObject.serializeAccountData({ imap: { host: 'h', pass: 'x' } }), { imap: '{"host":"h","pass":"x"}' });
    });
});

test('unserializeAccountData()', async t => {
    const logger = createMockLogger();
    const accountObject = createAccount({ secret: SECRET, logger });

    await t.test('round trip of a full account', () => {
        const stored = accountObject.serializeAccountData(fullAccount());
        stored._authFailureDisabled = '1700000000000';
        stored['stats:count:messages:new'] = '12';
        stored['stats:count:messages:deleted'] = '3';
        stored['stats:count:sync:full'] = 'x';

        const data = accountObject.unserializeAccountData(stored);
        assert.deepStrictEqual(data, {
            _authFailureDisabledAt: '1700000000000',
            account: 'acc',
            name: 'Example Account',
            email: 'user@example.com',
            notifyFrom: new Date('2026-03-04T05:06:07.000Z'),
            lastWatch: new Date('2026-03-05T06:07:08.000Z'),
            path: ['INBOX', 'Sent'],
            copy: true,
            logs: false,
            expectedEmail: 'user@example.com',
            webhooks: 'https://hook.example.com/wh',
            webhooksCustomHeaders: [{ key: 'X-Token', value: 'abc' }],
            proxy: 'socks5://127.0.0.1:1080',
            subconnections: ['[Gmail]/Spam'],
            watchResponse: { historyId: '1234', expiration: '1777777777000' },
            outlookSubscription: { id: 'sub-1', expirationDateTime: new Date('2026-04-05T06:07:08.000Z'), clientState: 'cs' },
            imap: {
                auth: { user: 'user@example.com', pass: 'imap-secret' },
                host: 'imap.example.com',
                port: 993,
                secure: true,
                created: CREATED
            },
            smtp: {
                auth: { user: 'user@example.com', pass: 'smtp-secret' },
                host: 'smtp.example.com',
                port: 465,
                secure: true
            },
            oauth2: {
                provider: 'app-1',
                auth: { user: 'user@example.com' },
                accessToken: 'access-token',
                refreshToken: 'refresh-token',
                expires: EXPIRES,
                generated: CREATED
            },
            connections: 3,
            runIndex: 7,
            counters: { messages: { new: 12, deleted: 3 }, sync: { full: NaN } }
        });
        assert.deepStrictEqual(logger.entries, []);
    });

    await t.test('counter names that are Object.prototype members stay in the counters', () => {
        const data = accountObject.unserializeAccountData({
            account: 'acc',
            'stats:count:__proto__:polluted': '1',
            'stats:count:constructor:polluted': '2',
            'stats:count:toString:polluted': '3',
            'stats:count:messages:__proto__': '4'
        });
        assert.equal({}.polluted, undefined);
        assert.equal(Object.polluted, undefined);
        assert.equal(Object.prototype.toString.polluted, undefined);
        assert.deepStrictEqual(data.counters, { toString: { polluted: 3 } });
    });

    await t.test('defaults for an empty hash', () => {
        assert.deepStrictEqual(accountObject.unserializeAccountData({}), { path: '*', account: null, counters: {} });
    });

    await t.test('path variants', () => {
        const decode = path => accountObject.unserializeAccountData({ account: 'acc', path }).path;
        assert.equal(decode(''), '*');
        assert.equal(decode('"INBOX"'), 'INBOX');
        assert.deepStrictEqual(decode('["INBOX","Sent"]'), ['INBOX', 'Sent']);
        assert.equal(decode('INBOX'), 'INBOX');
        assert.equal(decode('"'), '"');
        assert.equal(decode('null'), 'null');
        assert.equal(decode('"null"'), 'null');

        logger.entries.length = 0;
        assert.equal(decode('[broken'), '*');
        assert.deepStrictEqual(
            logger.entries.map(entry => [entry.msg, entry.key, entry.valueLength, entry.account]),
            [['Failed to parse input from Redis', 'path', 7, 'acc']]
        );
    });

    await t.test('date, boolean, number and clearable fields', () => {
        const decode = data => accountObject.unserializeAccountData(Object.assign({ account: 'acc' }, data));
        assert.deepStrictEqual(decode({ notifyFrom: 'null', lastWatch: 'garbage' }), { account: 'acc', notifyFrom: null, path: '*', counters: {} });
        assert.deepStrictEqual(decode({ notifyFrom: '' }), { account: 'acc', path: '*', counters: {} });
        assert.deepStrictEqual(decode({ copy: 'true', logs: 'null' }), { account: 'acc', copy: true, path: '*', counters: {} });
        assert.deepStrictEqual(decode({ copy: '', logs: 'yes' }), { account: 'acc', logs: false, path: '*', counters: {} });
        assert.deepStrictEqual(decode({ expectedEmail: '' }), { account: 'acc', path: '*', counters: {} });
        assert.deepStrictEqual(decode({ connections: 'abc', listRegistry: '', runIndex: '4' }), {
            account: 'acc',
            connections: 0,
            listRegistry: 0,
            runIndex: 4,
            path: '*',
            counters: {}
        });
    });

    await t.test('connection JSON: date subkeys and nulls', () => {
        const decode = data => accountObject.unserializeAccountData(Object.assign({ account: 'acc' }, data));
        const data = decode({
            webhookErrorFlag: JSON.stringify({ error: 'x', created: '1700000000000', expires: null }),
            syncError: JSON.stringify({ created: '2026-01-02T03:04:05.000Z', generated: 'not a date', code: null }),
            smtpStatus: 'null',
            lastErrorState: '{}'
        });
        assert.deepStrictEqual(data, {
            account: 'acc',
            webhookErrorFlag: { error: 'x', created: new Date(1700000000000) },
            syncError: { created: CREATED, generated: 'not a date' },
            lastErrorState: {},
            path: '*',
            counters: {}
        });

        logger.entries.length = 0;
        assert.deepStrictEqual(decode({ imapServerInfo: '{bad' }), { account: 'acc', path: '*', counters: {} });
        assert.deepStrictEqual(
            logger.entries.map(entry => [entry.msg, entry.key]),
            [['Failed to parse input from Redis', 'imapServerInfo']]
        );
    });

    await t.test('outlookSubscription and generic JSON', () => {
        const decode = data => accountObject.unserializeAccountData(Object.assign({ account: 'acc' }, data));
        assert.deepStrictEqual(decode({ outlookSubscription: '{"id":"s","expirationDateTime":"garbage"}' }).outlookSubscription, {
            id: 's',
            expirationDateTime: null
        });
        assert.deepStrictEqual(decode({ outlookSubscription: '{"id":"s","expirationDateTime":""}' }).outlookSubscription, { id: 's', expirationDateTime: '' });
        assert.equal('outlookSubscription' in decode({ outlookSubscription: 'null' }), false);
        assert.equal('watchFailure' in decode({ watchFailure: 'null' }), false);
        assert.deepStrictEqual(decode({ watchFailure: '{"a":null}' }).watchFailure, { a: null });

        logger.entries.length = 0;
        assert.equal('outlookSubscription' in decode({ outlookSubscription: '{' }), false);
        assert.equal('subconnections' in decode({ subconnections: '' }), false);
        assert.deepStrictEqual(
            logger.entries.map(entry => entry.key),
            ['outlookSubscription', 'subconnections']
        );
    });

    await t.test('the email falls back to the OAuth2 user', () => {
        const decode = data => accountObject.unserializeAccountData(data);
        assert.equal(decode({ oauth2: JSON.stringify({ auth: { user: 'oauth@example.com' } }) }).email, 'oauth@example.com');
        assert.equal(decode({ oauth2: JSON.stringify({ auth: { user: 'not-an-address' } }) }).email, undefined);
        assert.equal(decode({ email: 'own@example.com', oauth2: JSON.stringify({ auth: { user: 'oauth@example.com' } }) }).email, 'own@example.com');
    });

    await t.test('decryption modes', () => {
        const stored = accountObject.serializeAccountData(fullAccount());

        logger.entries.length = 0;
        const skipped = accountObject.unserializeAccountData(stored, { skipDecrypt: true });
        assert.equal(skipped.webhooks, stored.webhooks);
        assert.equal(skipped.proxy, stored.proxy);
        assert.equal('webhooksCustomHeaders' in skipped, false, 'an encrypted header list is left out');
        assert.deepStrictEqual(logger.entries, [], 'left out without trying to parse it');
        assert.equal(skipped.imap.auth.pass, JSON.parse(stored.imap).auth.pass);

        const cleartextHeaders = accountObject.unserializeAccountData({ webhooksCustomHeaders: '[{"key":"a"}]' }, { skipDecrypt: true });
        assert.deepStrictEqual(cleartextHeaders.webhooksCustomHeaders, [{ key: 'a' }]);

        const deferred = accountObject.unserializeAccountData(stored, { deferCredentials: true });
        assert.equal(deferred.webhooks, 'https://hook.example.com/wh');
        assert.deepStrictEqual(deferred.webhooksCustomHeaders, [{ key: 'X-Token', value: 'abc' }]);
        assert.equal(deferred.imap.auth.pass, JSON.parse(stored.imap).auth.pass);
        assert.equal(deferred.oauth2.accessToken, JSON.parse(stored.oauth2).accessToken);

        // a value written under another secret reads as unset
        logger.entries.length = 0;
        const foreign = accountObject.unserializeAccountData({
            account: 'acc',
            webhooks: encrypt('https://example.com', 'other-secret'),
            webhooksCustomHeaders: encrypt('[]', 'other-secret'),
            proxy: encrypt('socks5://x', 'other-secret')
        });
        assert.deepStrictEqual(foreign, { account: 'acc', path: '*', counters: {} });
        assert.deepStrictEqual(
            logger.entries.map(entry => [entry.msg, entry.key]),
            [
                ['Failed to decrypt value', 'webhooks'],
                ['Failed to decrypt value', 'webhooksCustomHeaders'],
                ['Failed to decrypt value', 'proxy']
            ]
        );
    });

    await t.test('without a secret the stored values are read as they are', () => {
        const plain = createAccount();
        const stored = plain.serializeAccountData(fullAccount());
        const data = plain.unserializeAccountData(stored);
        assert.equal(data.imap.auth.pass, 'imap-secret');
        assert.equal(data.webhooks, 'https://hook.example.com/wh');
        assert.deepStrictEqual(data.webhooksCustomHeaders, [{ key: 'X-Token', value: 'abc' }]);
    });
});
