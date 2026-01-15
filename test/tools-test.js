'use strict';

const test = require('node:test');
const assert = require('node:assert').strict;
const os = require('os');

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
        const opts = { account: 'my-account', name: 'John Doe' };

        const result = tools.getSignedFormDataSync(secret, opts);
        const decoded = JSON.parse(Buffer.from(result.data, 'base64url').toString());

        assert.strictEqual(decoded.account, 'my-account');
        assert.strictEqual(decoded.name, 'John Doe');
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
});
