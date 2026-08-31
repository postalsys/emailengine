'use strict';

const test = require('node:test');
const assert = require('node:assert').strict;
const os = require('os');
const crypto = require('crypto');

const tools = require('../lib/tools');

test('Tools utility tests', async t => {
    t.after(() => {
        // Force exit after tests to prevent hanging on Redis connections from loaded modules
        setTimeout(() => process.exit(), 1000).unref();
    });

    // getDuration tests
    await t.test('getDuration() parses seconds', async () => {
        assert.strictEqual(tools.getDuration('5s'), 5000);
        assert.strictEqual(tools.getDuration('1s'), 1000);
        assert.strictEqual(tools.getDuration('30s'), 30000);
    });

    await t.test('getDuration() parses minutes', async () => {
        assert.strictEqual(tools.getDuration('1m'), 60000);
        assert.strictEqual(tools.getDuration('5m'), 300000);
        assert.strictEqual(tools.getDuration('30min'), 1800000);
    });

    await t.test('getDuration() parses hours', async () => {
        assert.strictEqual(tools.getDuration('1h'), 3600000);
        assert.strictEqual(tools.getDuration('2h'), 7200000);
        assert.strictEqual(tools.getDuration('24h'), 86400000);
    });

    await t.test('getDuration() parses days', async () => {
        assert.strictEqual(tools.getDuration('1d'), 86400000);
        assert.strictEqual(tools.getDuration('7d'), 604800000);
    });

    await t.test('getDuration() parses milliseconds', async () => {
        assert.strictEqual(tools.getDuration('100ms'), 100);
        assert.strictEqual(tools.getDuration('500ms'), 500);
    });

    await t.test('getDuration() parses months', async () => {
        assert.strictEqual(tools.getDuration('1mo'), 30 * 24 * 3600 * 1000);
        assert.strictEqual(tools.getDuration('1month'), 30 * 24 * 3600 * 1000);
    });

    await t.test('getDuration() parses years', async () => {
        assert.strictEqual(tools.getDuration('1y'), 365 * 24 * 3600 * 1000);
    });

    await t.test('getDuration() returns seconds when option set', async () => {
        assert.strictEqual(tools.getDuration('5m', { seconds: true }), 300);
        assert.strictEqual(tools.getDuration('1h', { seconds: true }), 3600);
    });

    await t.test('getDuration() handles numeric string input', async () => {
        assert.strictEqual(tools.getDuration('5000'), 5000);
    });

    await t.test('getDuration() handles empty/invalid input', async () => {
        assert.strictEqual(tools.getDuration(''), 0);
        assert.strictEqual(tools.getDuration(null), 0);
    });

    // getByteSize tests
    await t.test('getByteSize() passes through numbers', async () => {
        assert.strictEqual(tools.getByteSize(1024), 1024);
        assert.strictEqual(tools.getByteSize(0), 0);
    });

    await t.test('getByteSize() parses kilobytes', async () => {
        assert.strictEqual(tools.getByteSize('1KB'), 1024);
        assert.strictEqual(tools.getByteSize('1K'), 1024);
        assert.strictEqual(tools.getByteSize('10KB'), 10240);
    });

    await t.test('getByteSize() parses megabytes', async () => {
        assert.strictEqual(tools.getByteSize('1MB'), 1024 * 1024);
        assert.strictEqual(tools.getByteSize('1M'), 1024 * 1024);
        assert.strictEqual(tools.getByteSize('100MB'), 100 * 1024 * 1024);
    });

    await t.test('getByteSize() parses gigabytes', async () => {
        assert.strictEqual(tools.getByteSize('1GB'), 1024 * 1024 * 1024);
        assert.strictEqual(tools.getByteSize('2G'), 2 * 1024 * 1024 * 1024);
    });

    await t.test('getByteSize() parses terabytes', async () => {
        assert.strictEqual(tools.getByteSize('1TB'), 1024 * 1024 * 1024 * 1024);
    });

    await t.test('getByteSize() parses petabytes', async () => {
        assert.strictEqual(tools.getByteSize('1PB'), 1024 * 1024 * 1024 * 1024 * 1024);
    });

    await t.test('getByteSize() handles numeric string', async () => {
        assert.strictEqual(tools.getByteSize('1024'), 1024);
    });

    await t.test('getByteSize() handles empty/invalid input', async () => {
        assert.strictEqual(tools.getByteSize(''), 0);
        assert.strictEqual(tools.getByteSize(null), 0);
    });

    // getWorkerCount tests
    await t.test('getWorkerCount() returns number as-is', async () => {
        assert.strictEqual(tools.getWorkerCount(4), 4);
        assert.strictEqual(tools.getWorkerCount(0), 0);
    });

    await t.test('getWorkerCount() parses numeric string', async () => {
        assert.strictEqual(tools.getWorkerCount('4'), 4);
        assert.strictEqual(tools.getWorkerCount('8'), 8);
    });

    await t.test('getWorkerCount() handles "cpus" keyword', async () => {
        const cpuCount = os.cpus().length;
        assert.strictEqual(tools.getWorkerCount('cpus'), cpuCount);
        assert.strictEqual(tools.getWorkerCount(' CPUS '), cpuCount);
    });

    await t.test('getWorkerCount() returns 0 for invalid input', async () => {
        assert.strictEqual(tools.getWorkerCount('invalid'), 0);
        assert.strictEqual(tools.getWorkerCount(NaN), 0);
    });

    // selectRendezvousNode tests
    await t.test('selectRendezvousNode() returns consistent results for same key', async () => {
        const workers = [{ threadId: 1 }, { threadId: 2 }, { threadId: 3 }];

        const result1 = tools.selectRendezvousNode('test-key', workers);
        const result2 = tools.selectRendezvousNode('test-key', workers);

        assert.strictEqual(result1.threadId, result2.threadId);
    });

    await t.test('selectRendezvousNode() distributes keys across workers', async () => {
        const workers = [{ threadId: 1 }, { threadId: 2 }, { threadId: 3 }];

        const selections = new Set();
        for (let i = 0; i < 100; i++) {
            const result = tools.selectRendezvousNode(`key-${i}`, workers);
            selections.add(result.threadId);
        }

        // With 100 different keys, we should see more than 1 worker selected
        assert.ok(selections.size > 1, 'Should distribute across multiple workers');
    });

    await t.test('getRendezvousScore() returns consistent hash', async () => {
        const score1 = tools.getRendezvousScore('key', 'shard1');
        const score2 = tools.getRendezvousScore('key', 'shard1');

        assert.strictEqual(score1, score2);
    });

    // getSignedFormDataSync tests
    await t.test('getSignedFormDataSync() creates signed data', async () => {
        const secret = 'test-secret';
        const opts = { account: 'test-account', name: 'Test User' };

        const result = tools.getSignedFormDataSync(secret, opts);

        assert.ok(result.data, 'Should have data');
        assert.ok(result.signature, 'Should have signature');
        assert.strictEqual(typeof result.data, 'string');
        assert.strictEqual(typeof result.signature, 'string');
    });

    await t.test('getSignedFormDataSync() produces different signatures for different secrets', async () => {
        const opts = { account: 'test-account' };

        const result1 = tools.getSignedFormDataSync('secret1', opts);
        const result2 = tools.getSignedFormDataSync('secret2', opts);

        assert.notStrictEqual(result1.signature, result2.signature);
    });

    await t.test('getSignedFormDataSync() produces same signature for same input', async () => {
        const secret = 'test-secret';
        const opts = { account: 'test-account', name: 'Test User' };

        const result1 = tools.getSignedFormDataSync(secret, opts);
        const result2 = tools.getSignedFormDataSync(secret, opts);

        assert.strictEqual(result1.signature, result2.signature);
        assert.strictEqual(result1.data, result2.data);
    });

    await t.test('getSignedFormDataSync() data can be decoded', async () => {
        const secret = 'test-secret';
        const opts = { account: 'my-account', name: 'John Doe', expectedEmail: 'owner@example.com' };

        const result = tools.getSignedFormDataSync(secret, opts);
        const decoded = JSON.parse(Buffer.from(result.data, 'base64url').toString());

        assert.strictEqual(decoded.account, 'my-account');
        assert.strictEqual(decoded.name, 'John Doe');
        // The identity pin has to survive into the blob, otherwise the hosted form has nothing to enforce.
        assert.strictEqual(decoded.expectedEmail, 'owner@example.com');
    });

    await t.test('getSignedFormDataSync() filters empty values', async () => {
        const secret = 'test-secret';
        const opts = { account: 'test', name: '', email: null };

        const result = tools.getSignedFormDataSync(secret, opts);
        const decoded = JSON.parse(Buffer.from(result.data, 'base64url').toString());

        assert.strictEqual(decoded.account, 'test');
        assert.ok(!('name' in decoded), 'Should not include empty name');
        assert.ok(!('email' in decoded), 'Should not include null email');
    });

    await t.test('getSignedFormDataSync() asIs mode includes all values', async () => {
        const secret = 'test-secret';
        const opts = { custom: 'value', another: 123 };

        const result = tools.getSignedFormDataSync(secret, opts, true);
        const decoded = JSON.parse(Buffer.from(result.data, 'base64url').toString());

        assert.strictEqual(decoded.custom, 'value');
        assert.strictEqual(decoded.another, 123);
    });

    // NOTE: matchIp tests moved to test/network-utils-test.js

    // getBoolean tests
    await t.test('getBoolean() returns boolean as-is', async () => {
        assert.strictEqual(tools.getBoolean(true), true);
        assert.strictEqual(tools.getBoolean(false), false);
    });

    await t.test('getBoolean() parses string "true"/"false"', async () => {
        assert.strictEqual(tools.getBoolean('true'), true);
        assert.strictEqual(tools.getBoolean('True'), true);
        assert.strictEqual(tools.getBoolean('TRUE'), true);
        assert.strictEqual(tools.getBoolean('false'), false);
        assert.strictEqual(tools.getBoolean('False'), false);
    });

    await t.test('getBoolean() parses "y"/"yes"', async () => {
        assert.strictEqual(tools.getBoolean('y'), true);
        assert.strictEqual(tools.getBoolean('yes'), true);
        assert.strictEqual(tools.getBoolean('Y'), true);
        assert.strictEqual(tools.getBoolean('n'), false);
        assert.strictEqual(tools.getBoolean('no'), false);
    });

    await t.test('getBoolean() parses numeric strings', async () => {
        assert.strictEqual(tools.getBoolean('1'), true);
        assert.strictEqual(tools.getBoolean('0'), false);
        assert.strictEqual(tools.getBoolean('123'), true);
    });

    await t.test('getBoolean() handles numbers', async () => {
        assert.strictEqual(tools.getBoolean(1), true);
        assert.strictEqual(tools.getBoolean(0), false);
        assert.strictEqual(tools.getBoolean(100), true);
    });

    // setBit / readBit tests
    await t.test('setBit() sets bit correctly', async () => {
        const buffer = Buffer.alloc(2);

        tools.setBit(buffer, 0, 0, true);
        assert.strictEqual(buffer[0], 1);

        tools.setBit(buffer, 0, 1, true);
        assert.strictEqual(buffer[0], 3);

        tools.setBit(buffer, 0, 7, true);
        assert.strictEqual(buffer[0], 131);
    });

    await t.test('setBit() clears bit correctly', async () => {
        const buffer = Buffer.from([0xff]);

        tools.setBit(buffer, 0, 0, false);
        assert.strictEqual(buffer[0], 0xfe);

        tools.setBit(buffer, 0, 7, false);
        assert.strictEqual(buffer[0], 0x7e);
    });

    await t.test('readBit() reads bit correctly', async () => {
        const buffer = Buffer.from([0b10101010]);

        assert.strictEqual(tools.readBit(buffer, 0, 0), false);
        assert.strictEqual(tools.readBit(buffer, 0, 1), true);
        assert.strictEqual(tools.readBit(buffer, 0, 2), false);
        assert.strictEqual(tools.readBit(buffer, 0, 3), true);
    });

    await t.test('setBit() returns false for out of bounds', async () => {
        const buffer = Buffer.alloc(1);

        assert.strictEqual(tools.setBit(buffer, -1, 0, true), false);
        assert.strictEqual(tools.setBit(buffer, 1, 0, true), false);
    });

    // escapeRegExp tests
    await t.test('escapeRegExp() escapes special characters', async () => {
        assert.strictEqual(tools.escapeRegExp('test.string'), 'test\\.string');
        assert.strictEqual(tools.escapeRegExp('a*b+c?'), 'a\\*b\\+c\\?');
        assert.strictEqual(tools.escapeRegExp('[a-z]'), '\\[a-z\\]');
        assert.strictEqual(tools.escapeRegExp('$100'), '\\$100');
    });

    await t.test('escapeRegExp() leaves normal strings unchanged', async () => {
        assert.strictEqual(tools.escapeRegExp('hello'), 'hello');
        assert.strictEqual(tools.escapeRegExp('test123'), 'test123');
    });

    await t.test('escapeRedisGlob() escapes glob metacharacters', async () => {
        assert.strictEqual(tools.escapeRedisGlob('user123'), 'user123');
        assert.strictEqual(tools.escapeRedisGlob('acc@ex.com'), 'acc@ex.com');
        assert.strictEqual(tools.escapeRedisGlob('*'), '\\*');
        assert.strictEqual(tools.escapeRedisGlob('a*b?c'), 'a\\*b\\?c');
        assert.strictEqual(tools.escapeRedisGlob('x[y]'), 'x\\[y\\]');
        assert.strictEqual(tools.escapeRedisGlob('a\\b'), 'a\\\\b');
    });

    await t.test('escapeRedisGlob() coerces null/undefined to empty string', async () => {
        assert.strictEqual(tools.escapeRedisGlob(null), '');
        assert.strictEqual(tools.escapeRedisGlob(undefined), '');
    });

    await t.test('constantTimeEqual() matches equal values and rejects any difference', async () => {
        assert.strictEqual(tools.constantTimeEqual('s3cr3t-abc', 's3cr3t-abc'), true);
        assert.strictEqual(tools.constantTimeEqual('', ''), true);
        assert.strictEqual(tools.constantTimeEqual('s3cr3t-abc', 's3cr3t-abd'), false);
        // unequal lengths must return false, never throw
        assert.strictEqual(tools.constantTimeEqual('abc', 'abcdef'), false);
    });

    await t.test('constantTimeEqual() treats null/undefined as non-matching', async () => {
        assert.strictEqual(tools.constantTimeEqual(null, 'x'), false);
        assert.strictEqual(tools.constantTimeEqual('x', undefined), false);
        assert.strictEqual(tools.constantTimeEqual(null, null), false);
    });

    // filterEmptyObjectValues tests
    await t.test('filterEmptyObjectValues() removes falsy values', async () => {
        const input = { a: 'value', b: '', c: null, d: 0, e: false, f: 'keep' };
        const result = tools.filterEmptyObjectValues(input);

        assert.deepStrictEqual(result, { a: 'value', f: 'keep' });
    });

    await t.test('filterEmptyObjectValues() keeps truthy values', async () => {
        const input = { a: 1, b: 'text', c: true, d: [] };
        const result = tools.filterEmptyObjectValues(input);

        assert.deepStrictEqual(result, { a: 1, b: 'text', c: true, d: [] });
    });

    // formatByteSize tests
    await t.test('formatByteSize() formats bytes to human readable', async () => {
        assert.strictEqual(tools.formatByteSize(1024), '1kB');
        assert.strictEqual(tools.formatByteSize(1024 * 1024), '1MB');
        assert.strictEqual(tools.formatByteSize(1024 * 1024 * 1024), '1GB');
        assert.strictEqual(tools.formatByteSize(1024 * 1024 * 1024 * 1024), '1TB');
    });

    await t.test('formatByteSize() returns non-round numbers as-is', async () => {
        assert.strictEqual(tools.formatByteSize(1000), 1000);
        assert.strictEqual(tools.formatByteSize(1500), 1500);
    });

    // formatAccountListingResponse tests
    await t.test('formatAccountListingResponse() converts array to object', async () => {
        const input = ['key1', 'value1', 'key2', 'value2'];
        const result = tools.formatAccountListingResponse(input);

        assert.deepStrictEqual(result, { key1: 'value1', key2: 'value2' });
    });

    await t.test('formatAccountListingResponse() returns non-array as-is', async () => {
        const input = { already: 'object' };
        const result = tools.formatAccountListingResponse(input);

        assert.strictEqual(result, input);
    });

    // hasEnvValue tests
    await t.test('hasEnvValue() checks for env variable', async () => {
        process.env.TEST_ENV_VAR = 'value';
        assert.strictEqual(tools.hasEnvValue('TEST_ENV_VAR'), true);
        assert.strictEqual(tools.hasEnvValue('NON_EXISTENT_VAR_12345'), false);
        delete process.env.TEST_ENV_VAR;
    });

    await t.test('hasEnvValue() checks for _FILE variant', async () => {
        process.env.TEST_SECRET_FILE = '/path/to/file';
        assert.strictEqual(tools.hasEnvValue('TEST_SECRET'), true);
        delete process.env.TEST_SECRET_FILE;
    });

    // readEnvValue tests
    await t.test('readEnvValue() returns env variable value', async () => {
        process.env.TEST_READ_VAR = 'test-value';
        assert.strictEqual(tools.readEnvValue('TEST_READ_VAR'), 'test-value');
        delete process.env.TEST_READ_VAR;
    });

    await t.test('readEnvValue() returns undefined for non-existent', async () => {
        assert.strictEqual(tools.readEnvValue('NON_EXISTENT_VAR_67890'), undefined);
    });

    // prepareUrl tests
    await t.test('prepareUrl() handles base URL at root without trailing slash', async () => {
        const result = tools.prepareUrl('/oauth/msg/notification', 'https://example.com', { account: 'test' });
        assert.strictEqual(result, 'https://example.com/oauth/msg/notification?account=test');
    });

    await t.test('prepareUrl() handles base URL at root with trailing slash', async () => {
        const result = tools.prepareUrl('/oauth/msg/notification', 'https://example.com/', { account: 'test' });
        assert.strictEqual(result, 'https://example.com/oauth/msg/notification?account=test');
    });

    await t.test('prepareUrl() handles base URL with path without trailing slash', async () => {
        const result = tools.prepareUrl('/oauth/msg/notification', 'https://example.com/emailengine-api', { account: 'test' });
        assert.strictEqual(result, 'https://example.com/emailengine-api/oauth/msg/notification?account=test');
    });

    await t.test('prepareUrl() handles base URL with path with trailing slash', async () => {
        const result = tools.prepareUrl('/oauth/msg/notification', 'https://example.com/emailengine-api/', { account: 'test' });
        assert.strictEqual(result, 'https://example.com/emailengine-api/oauth/msg/notification?account=test');
    });

    await t.test('prepareUrl() handles endpoint without leading slash', async () => {
        const result = tools.prepareUrl('oauth/msg/notification', 'https://example.com/api/', { account: 'test' });
        assert.strictEqual(result, 'https://example.com/api/oauth/msg/notification?account=test');
    });

    await t.test('prepareUrl() handles multiple query parameters', async () => {
        const result = tools.prepareUrl('/path', 'https://example.com', { foo: 'bar', baz: 'qux' });
        assert.strictEqual(result, 'https://example.com/path?foo=bar&baz=qux');
    });

    await t.test('prepareUrl() skips null and undefined query params', async () => {
        const result = tools.prepareUrl('/path', 'https://example.com', { keep: 'value', skipNull: null, skipUndef: undefined });
        assert.strictEqual(result, 'https://example.com/path?keep=value');
    });

    await t.test('prepareUrl() handles empty query params', async () => {
        const result = tools.prepareUrl('/path', 'https://example.com', {});
        assert.strictEqual(result, 'https://example.com/path');
    });

    await t.test('prepareUrl() handles no query params', async () => {
        const result = tools.prepareUrl('/path', 'https://example.com');
        assert.strictEqual(result, 'https://example.com/path');
    });

    await t.test('readEnvList() parses, trims and drops blanks', async () => {
        process.env.EENGINE_TEST_ENV_LIST = ' 10.0.0.1 , , 192.168.0.0/16 ';
        try {
            assert.deepStrictEqual(tools.readEnvList('EENGINE_TEST_ENV_LIST'), ['10.0.0.1', '192.168.0.0/16']);
        } finally {
            delete process.env.EENGINE_TEST_ENV_LIST;
        }
    });

    await t.test('readEnvList() distinguishes unset from present-but-empty', async () => {
        // An empty value yields [], which is TRUTHY. Callers that gate a security warning or an
        // allowlist on this must check the length, not the value; see the X-Forwarded-For warning
        // in workers/api.js and resolveClientIp() in lib/utils/network.js
        assert.strictEqual(tools.readEnvList('EENGINE_TEST_ENV_LIST_UNSET'), null);

        process.env.EENGINE_TEST_ENV_LIST = '  ,  ';
        try {
            assert.deepStrictEqual(tools.readEnvList('EENGINE_TEST_ENV_LIST'), []);
        } finally {
            delete process.env.EENGINE_TEST_ENV_LIST;
        }
    });

    // The fallback credential predicates for shouldUseAuthServer(). They must only report
    // credentials the non-auth-server code paths can actually consume, or a stale useAuthServer
    // flag would be ignored in favor of credentials that cannot work.
    await t.test('hasStoredOAuth2Tokens() only counts top-level tokens', async () => {
        assert.strictEqual(tools.hasStoredOAuth2Tokens({ refreshToken: 'r' }), true);
        assert.strictEqual(tools.hasStoredOAuth2Tokens({ accessToken: 'a' }), true);
        assert.strictEqual(tools.hasStoredOAuth2Tokens({ auth: { user: 'u@example.com' } }), false);
        // The renew and cached-token paths never read tokens nested under `auth`
        assert.strictEqual(tools.hasStoredOAuth2Tokens({ auth: { user: 'u@example.com', accessToken: 'a' } }), false);
    });

    await t.test('hasStoredServerCredentials() requires a user and a password or token', async () => {
        assert.strictEqual(tools.hasStoredServerCredentials({ auth: { user: 'u', pass: 'p' } }), true);
        assert.strictEqual(tools.hasStoredServerCredentials({ auth: { user: 'u', accessToken: 'a' } }), true);
        assert.strictEqual(tools.hasStoredServerCredentials({ auth: { user: 'u' } }), false);
        assert.strictEqual(tools.hasStoredServerCredentials({ auth: false }), false);
        assert.strictEqual(tools.hasStoredServerCredentials({}), false);
    });

    // The signed subscription-management URL, shared by the mailer's List-Unsubscribe header
    // and the suppression-list admin UI
    await t.test('buildUnsubscribeUrl() signs the unsubscribe payload', async () => {
        const secret = 'unsub test secret';

        const url = new URL(
            tools.buildUnsubscribeUrl(secret, 'https://ee.example.com', {
                account: 'acc1',
                list: 'newsletter',
                recipient: 'User@Example.com',
                messageId: '<msg1@example.com>'
            })
        );

        assert.strictEqual(url.origin, 'https://ee.example.com');
        assert.strictEqual(url.pathname, '/unsubscribe');

        const raw = Buffer.from(url.searchParams.get('data'), 'base64url').toString();
        const payload = JSON.parse(raw);
        assert.deepStrictEqual(payload, { act: 'unsub', acc: 'acc1', list: 'newsletter', rcpt: 'User@Example.com', msg: '<msg1@example.com>' });

        // the signature must verify with the same HMAC the unsubscribe page checks
        const expected = crypto.createHmac('sha256', secret).update(raw).digest('base64url');
        assert.strictEqual(url.searchParams.get('sig'), expected);
    });

    await t.test('buildUnsubscribeUrl() stays host-relative without a base URL and omits a missing message ID', async () => {
        const link = tools.buildUnsubscribeUrl('unsub test secret', null, {
            account: 'acc1',
            list: 'newsletter',
            recipient: 'user@example.com'
        });

        // no placeholder host may leak into the link
        assert.ok(link.startsWith('/unsubscribe?data='), 'link is host-relative');

        const url = new URL(link, 'http://localhost');
        const payload = JSON.parse(Buffer.from(url.searchParams.get('data'), 'base64url').toString());
        assert.deepStrictEqual(payload, { act: 'unsub', acc: 'acc1', list: 'newsletter', rcpt: 'user@example.com' });
    });

    await t.test('collectCidReferences() finds ids in quoted and unquoted attributes', async () => {
        const cids = tools.collectCidReferences(
            '<img src="cid:part1@example.com"><img src=\'cid:part2@example.com\'><img src=cid:part3@example.com alt=x><img src=cid:part4@example.com>'
        );
        assert.ok(cids.has('part1@example.com'));
        assert.ok(cids.has('part2@example.com'));
        assert.ok(cids.has('part3@example.com'));
        assert.ok(cids.has('part4@example.com'));
    });

    await t.test('collectCidReferences() resolves CSS url(cid:...) references', async () => {
        const cids = tools.collectCidReferences('<div style="background: url(cid:bg1@example.com)">x</div>');
        assert.ok(cids.has('bg1@example.com'));
    });

    await t.test('collectCidReferences() matches whole reference tokens only', async () => {
        const cids = tools.collectCidReferences('<img src="cid:part1.extended@example.com">');
        // a content id that is only a prefix of the referenced id must not match
        assert.ok(!cids.has('part1'));
        assert.ok(!cids.has('part1.extended'));
        assert.ok(cids.has('part1.extended@example.com'));
    });

    await t.test('collectCidReferences() ignores ids that appear outside cid: links', async () => {
        const cids = tools.collectCidReferences('<p>the id part1@example.com is mentioned in text</p>');
        assert.strictEqual(cids.size, 0);
    });

    await t.test('collectCidReferences() never contains the empty id', async () => {
        const cids = tools.collectCidReferences('<img src="cid:"><a href="x">cid:</a>');
        assert.ok(!cids.has(''));
    });

    await t.test('collectCidReferences() returns an empty set for non-string or empty input', async () => {
        assert.strictEqual(tools.collectCidReferences(undefined).size, 0);
        assert.strictEqual(tools.collectCidReferences(false).size, 0);
        assert.strictEqual(tools.collectCidReferences('').size, 0);
        assert.strictEqual(tools.collectCidReferences(Buffer.from('<img src="cid:x@y">')).size, 0);
    });

    await t.test('collectCidReferences() handles a multi-megabyte body dense with partial matches', async () => {
        // the shape from the DELLI report: a large body full of similar cid:
        // references - the per-attachment indexOf scans this helper replaced
        // took seconds of blocking CPU on the same input
        let chunk = [];
        for (let i = 0; i < 100; i++) {
            chunk.push(`<img src="cid:part.${i.toString().padStart(8, '0')}.eeeeeeeeeeeeeeee@example.com">`);
        }
        let block = chunk.join('');
        let html = block.repeat(Math.ceil((6 * 1024 * 1024) / block.length));

        const cids = tools.collectCidReferences(html);
        assert.strictEqual(cids.size, 100);
        assert.ok(cids.has('part.00000000.eeeeeeeeeeeeeeee@example.com'));
        assert.ok(cids.has('part.00000099.eeeeeeeeeeeeeeee@example.com'));
        assert.ok(!cids.has('part.00000000.ffffffffffffffff@example.com'));
    });

    await t.test('truncateTextContents() caps each text type and reports truncation', async () => {
        const textContents = { plain: 'aaaaaaaaaa', html: 'bbb' };
        assert.strictEqual(tools.truncateTextContents(textContents, 5), true);
        assert.strictEqual(textContents.plain, 'aaaaa');
        assert.strictEqual(textContents.html, 'bbb');
    });

    await t.test('truncateTextContents() leaves content under the limit alone', async () => {
        const textContents = { plain: 'aaa', html: 'bbb' };
        assert.strictEqual(tools.truncateTextContents(textContents, 5), false);
        assert.deepStrictEqual(textContents, { plain: 'aaa', html: 'bbb' });
    });

    await t.test('truncateTextContents() without a limit is a no-op', async () => {
        const textContents = { plain: 'aaaaaaaaaa' };
        assert.strictEqual(tools.truncateTextContents(textContents, 0), false);
        assert.strictEqual(tools.truncateTextContents(textContents, undefined), false);
        assert.strictEqual(textContents.plain, 'aaaaaaaaaa');
        assert.strictEqual(tools.truncateTextContents(undefined, 5), false);
    });

    await t.test('truncateTextContents() only touches the plain and html keys', async () => {
        const textContents = { plain: 'aaaaaaaaaa', html: undefined, id: 'attachment-reference-id', hasMore: false };
        assert.strictEqual(tools.truncateTextContents(textContents, 5), true);
        assert.strictEqual(textContents.plain, 'aaaaa');
        assert.strictEqual(textContents.html, undefined);
        // a text id or flag riding on the same object must never be clipped
        assert.strictEqual(textContents.id, 'attachment-reference-id');
        assert.strictEqual(textContents.hasMore, false);
    });

    await t.test('cidReferenceRegex() returns a fresh regex each call so no lastIndex state leaks', async () => {
        const re = tools.cidReferenceRegex();
        assert.notStrictEqual(re, tools.cidReferenceRegex());
        assert.ok(re.global);

        // the collection helper must tokenize with this same grammar
        const html = '<img src="cid:part1@example.com">';
        assert.deepStrictEqual(
            [...html.matchAll(tools.cidReferenceRegex())].map(m => m[1]),
            ['part1@example.com']
        );
        assert.ok(tools.collectCidReferences(html).has('part1@example.com'));
    });

    await t.test('isEndedSession() ends a session only when a later version exists', () => {
        // The read side of the passwordVersion setAdminSession() stamps. Two Hapi strategies in
        // workers/api.js ask it about the same cookie - the admin session and the browse page's
        // sess_ API token - so "log out all sessions" ends both or neither.
        assert.strictEqual(tools.isEndedSession(2, { passwordVersion: 1 }), true);
        assert.strictEqual(tools.isEndedSession(2, { passwordVersion: 2 }), false);

        // A session stamped before the field existed, against an instance that has never bumped
        // the version, is not force-expired - but one bump ends it
        assert.strictEqual(tools.isEndedSession(0, {}), false);
        assert.strictEqual(tools.isEndedSession(1, {}), true);

        // No local password at all (an unsecured instance) never ends anything
        assert.strictEqual(tools.isEndedSession(0, { passwordVersion: 3 }), false);

        // A request carrying no cookie has no session to end; the credential checks that follow
        // are what refuse it
        assert.strictEqual(tools.isEndedSession(0, undefined), false);
        assert.strictEqual(tools.isEndedSession(1, undefined), true);
    });

    await t.test('reloadTlsServers() reloads both TLS servers', async () => {
        // The renewal path used to send smtpReload alone, which left the IMAP proxy offering the
        // previous certificate. Both servers read the certificate once when their worker starts,
        // so both have to be told.
        let sent = [];
        const noopLogger = { error: () => {} };

        await tools.reloadTlsServers(async message => sent.push(message.cmd), noopLogger);
        assert.deepStrictEqual(sent, ['smtpReload', 'imapProxyReload']);
    });

    await t.test('reloadTlsServers() still reloads the second server when the first fails', async () => {
        // A server that fails to come back must not cost the other one its new certificate.
        let sent = [];
        let logged = [];
        const logger = { error: entry => logged.push(entry.cmd) };

        await tools.reloadTlsServers(async message => {
            sent.push(message.cmd);
            if (message.cmd === 'smtpReload') {
                throw new Error('worker is gone');
            }
        }, logger);

        assert.deepStrictEqual(sent, ['smtpReload', 'imapProxyReload']);
        assert.deepStrictEqual(logged, ['smtpReload']);
    });

    await t.test('reloadTlsServers() merges context into the failure log', async () => {
        let logged = [];
        const logger = { error: entry => logged.push(entry) };

        await tools.reloadTlsServers(
            async () => {
                throw new Error('nope');
            },
            logger,
            { serviceDomain: 'example.com' }
        );

        assert.strictEqual(logged.length, 2);
        assert.strictEqual(logged[0].serviceDomain, 'example.com');
        assert.strictEqual(logged[0].cmd, 'smtpReload');
        assert.strictEqual(logged[1].cmd, 'imapProxyReload');
    });
});
