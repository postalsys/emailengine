'use strict';

// Redis connection URL parsing (lib/redis-url.js).
//
// This is the very first thing EmailEngine does with operator input: EENGINE_REDIS / REDIS_URL
// is turned into the ioredis connection options for every worker. It had no coverage, yet a
// misparse is silent and expensive - the wrong `db` number means an instance quietly starts on
// somebody else's data set, a dropped `rediss:` means credentials go over plaintext, and a
// mangled password means the whole process fails to boot with an opaque AUTH error.
//
// The module is pure (no Redis, no settings, no lib/db import), so these are plain unit tests.

const test = require('node:test');
const assert = require('node:assert').strict;

const parseRedisUrl = require('../lib/redis-url');

test('Redis URL parsing', async t => {
    await t.test('parses a plain host and port', () => {
        assert.deepStrictEqual(parseRedisUrl('redis://127.0.0.1:6379'), { host: '127.0.0.1', port: 6379 });
    });

    await t.test('the port is a number, not the string the URL parser hands back', () => {
        // ioredis silently misbehaves if port arrives as a string
        const parsed = parseRedisUrl('redis://127.0.0.1:6380');
        assert.strictEqual(typeof parsed.port, 'number');
        assert.strictEqual(parsed.port, 6380);
    });

    await t.test('the path segment selects the database', () => {
        assert.strictEqual(parseRedisUrl('redis://127.0.0.1:6379/8').db, 8);
        assert.strictEqual(parseRedisUrl('redis://127.0.0.1:6379/0').db, 0, 'db 0 must be honoured, not dropped as falsy');
        assert.strictEqual(parseRedisUrl('redis://127.0.0.1:6379/13').db, 13);
    });

    await t.test('a missing or non-numeric path leaves the database unset', () => {
        assert.strictEqual(parseRedisUrl('redis://127.0.0.1:6379').db, undefined);
        assert.strictEqual(parseRedisUrl('redis://127.0.0.1:6379/').db, undefined);
        assert.strictEqual(parseRedisUrl('redis://127.0.0.1:6379/notanumber').db, undefined);
    });

    await t.test('a ?db= query argument also selects the database', () => {
        assert.strictEqual(parseRedisUrl('redis://127.0.0.1:6379?db=5').db, 5);
    });

    await t.test('the path segment wins over a ?db= query argument', () => {
        // The query params are read first and the URL fields second, so the path overwrites
        assert.strictEqual(parseRedisUrl('redis://127.0.0.1:6379/9?db=5').db, 9);
    });

    await t.test('rediss: turns on TLS', () => {
        const parsed = parseRedisUrl('rediss://redis.example.com:6380/1');
        assert.deepStrictEqual(parsed.tls, {}, 'ioredis enables TLS on the presence of the tls option');
        assert.strictEqual(parsed.host, 'redis.example.com');
        assert.strictEqual(parsed.db, 1);
    });

    await t.test('REDISS:// is matched case-insensitively', () => {
        assert.deepStrictEqual(parseRedisUrl('REDISS://redis.example.com:6380').tls, {});
    });

    await t.test('redis: does not turn on TLS', () => {
        assert.strictEqual(parseRedisUrl('redis://127.0.0.1:6379').tls, undefined);
    });

    await t.test('a password in the userinfo section is decoded', () => {
        assert.strictEqual(parseRedisUrl('redis://:secret@127.0.0.1:6379').password, 'secret');
    });

    await t.test('percent-encoded password characters survive', () => {
        // Passwords routinely contain @ : / # ? which have to be percent-encoded in a URL
        assert.strictEqual(parseRedisUrl('redis://:p%40ss%3Aword%2F%23%3F@127.0.0.1:6379').password, 'p@ss:word/#?');
    });

    await t.test('a ?password= query argument works too', () => {
        assert.strictEqual(parseRedisUrl('redis://127.0.0.1:6379?password=querysecret').password, 'querysecret');
    });

    await t.test('the userinfo password wins over the query argument', () => {
        assert.strictEqual(parseRedisUrl('redis://:userinfosecret@127.0.0.1:6379?password=querysecret').password, 'userinfosecret');
    });

    await t.test('the implicit "default" username is dropped', () => {
        // Redis 6 ACL URLs are commonly written as redis://default:pass@host. Sending
        // username "default" makes ioredis issue a two-argument AUTH, which pre-ACL servers
        // and several hosted proxies reject - so the plain-password form is used instead.
        const parsed = parseRedisUrl('redis://default:secret@127.0.0.1:6379');
        assert.strictEqual(parsed.username, undefined);
        assert.strictEqual(parsed.password, 'secret');
    });

    await t.test('a non-default username is kept', () => {
        const parsed = parseRedisUrl('redis://appuser:secret@127.0.0.1:6379');
        assert.strictEqual(parsed.username, 'appuser');
        assert.strictEqual(parsed.password, 'secret');
    });

    await t.test('allowUsernameInURI forces the "default" username through', () => {
        // Escape hatch for servers that genuinely require the ACL two-argument AUTH
        for (const flag of ['true', '1', 'yes', 'y', 'TRUE', 'Yes']) {
            const parsed = parseRedisUrl(`redis://default:secret@127.0.0.1:6379?allowUsernameInURI=${flag}`);
            assert.strictEqual(parsed.username, 'default', `allowUsernameInURI=${flag} should keep the username`);
        }
    });

    await t.test('allowUsernameInURI with a falsy value keeps dropping "default"', () => {
        for (const flag of ['false', '0', 'no', 'off']) {
            const parsed = parseRedisUrl(`redis://default:secret@127.0.0.1:6379?allowUsernameInURI=${flag}`);
            assert.strictEqual(parsed.username, undefined, `allowUsernameInURI=${flag} should not keep the username`);
        }
    });

    await t.test('a percent-encoded username is decoded', () => {
        assert.strictEqual(parseRedisUrl('redis://user%40example.com:secret@127.0.0.1:6379').username, 'user@example.com');
    });

    await t.test('?family= selects the IP family', () => {
        assert.strictEqual(parseRedisUrl('redis://127.0.0.1:6379?family=4').family, 4);
        assert.strictEqual(parseRedisUrl('redis://127.0.0.1:6379?family=6').family, 6);
    });

    await t.test('?family= accepts the ipv4/ipv6 spellings by pulling out the digits', () => {
        assert.strictEqual(parseRedisUrl('redis://127.0.0.1:6379?family=ipv4').family, 4);
        assert.strictEqual(parseRedisUrl('redis://127.0.0.1:6379?family=IPv6').family, 6);
    });

    await t.test('a ?family= with no digits at all degrades to 0 rather than NaN', () => {
        // 0 means "let the resolver decide"; NaN would make ioredis throw on connect
        const parsed = parseRedisUrl('redis://127.0.0.1:6379?family=auto');
        assert.strictEqual(parsed.family, 0);
        assert.ok(!Number.isNaN(parsed.family));
    });

    await t.test('empty query values are ignored', () => {
        const parsed = parseRedisUrl('redis://127.0.0.1:6379?password=&db=&family=');
        assert.strictEqual(parsed.password, undefined);
        assert.strictEqual(parsed.db, undefined);
        assert.strictEqual(parsed.family, undefined);
    });

    await t.test('unknown query arguments are ignored', () => {
        assert.deepStrictEqual(parseRedisUrl('redis://127.0.0.1:6379?keyPrefix=foo&sentinel=bar'), { host: '127.0.0.1', port: 6379 });
    });

    await t.test('a full production style URL parses into every option at once', () => {
        assert.deepStrictEqual(parseRedisUrl('rediss://appuser:p%40ss@redis.internal:6380/3?family=6'), {
            family: 6,
            host: 'redis.internal',
            port: 6380,
            password: 'p@ss',
            username: 'appuser',
            db: 3,
            tls: {}
        });
    });

    await t.test('a URL with no port omits the port so ioredis applies its default', () => {
        const parsed = parseRedisUrl('redis://redis.internal');
        assert.strictEqual(parsed.host, 'redis.internal');
        assert.strictEqual(parsed.port, undefined);
    });

    await t.test('an unparseable URL throws rather than returning a half-built config', () => {
        // Booting against a silently wrong Redis is worse than failing loudly at startup
        assert.throws(() => parseRedisUrl('not a url at all'));
        assert.throws(() => parseRedisUrl(''));
    });
});
