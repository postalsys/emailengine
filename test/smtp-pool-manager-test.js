'use strict';

// Unit tests for lib/email-client/smtp-pool-manager.js. The security-relevant
// invariant is the pool key: getMailTransport reuses a cached transport keyed by
// a SHA256 of the connection-identity settings (host/port/secure/auth/...). If
// two configurations with different credentials collapsed to the same key, one
// account would send through another account's authenticated connection. These
// tests pin down that the key is sensitive to every identity field (especially
// auth), ignores non-identity fields, is order-independent, and that
// getMailTransport reuses vs. creates transports accordingly.

const test = require('node:test');
const assert = require('node:assert').strict;

const {
    getMailTransport,
    closePooledConnection,
    getPoolSize,
    generatePoolKey,
    SMTP_POOL_MAX_IDLE,
    SMTP_POOL_CLEANUP_INTERVAL
} = require('../lib/email-client/smtp-pool-manager');
const registerRedisTeardown = require('./helpers/redis-teardown');

// Track transports/keys created during the run so they can be torn down. The
// module keeps a process-wide Map; leaving pooled transports behind could keep
// the event loop alive, so force-exit after closing them (no Redis here).
const createdKeys = new Set();

function makeSettings(overrides) {
    return Object.assign(
        {
            host: 'smtp.example.com',
            port: 587,
            secure: false,
            auth: { user: 'alice@example.com', pass: 'secret' }
        },
        overrides
    );
}

function transportFor(settings) {
    const transport = getMailTransport(settings);
    createdKeys.add(generatePoolKey(settings));
    return transport;
}

registerRedisTeardown(null, async () => {
    for (const key of createdKeys) {
        closePooledConnection(key);
    }
});

test('generatePoolKey', async t => {
    await t.test('is a deterministic 64-char hex digest', () => {
        const key = generatePoolKey(makeSettings());
        assert.match(key, /^[0-9a-f]{64}$/);
        assert.strictEqual(key, generatePoolKey(makeSettings()));
    });

    await t.test('is independent of property insertion order', () => {
        const a = { host: 'h', port: 25, secure: true, auth: { user: 'u' } };
        const b = { auth: { user: 'u' }, secure: true, port: 25, host: 'h' };
        assert.strictEqual(generatePoolKey(a), generatePoolKey(b));
    });

    await t.test('ignores fields that are not connection-identity keys', () => {
        const base = makeSettings();
        const withExtras = makeSettings({ from: 'noreply@example.com', subject: 'x', pool: false, unrelated: 123 });
        assert.strictEqual(generatePoolKey(base), generatePoolKey(withExtras));
    });

    await t.test('changes when credentials differ (no cross-account reuse)', () => {
        const a = generatePoolKey(makeSettings({ auth: { user: 'alice@example.com', pass: 'secret' } }));
        const b = generatePoolKey(makeSettings({ auth: { user: 'bob@example.com', pass: 'secret' } }));
        const c = generatePoolKey(makeSettings({ auth: { user: 'alice@example.com', pass: 'different' } }));
        assert.notStrictEqual(a, b);
        assert.notStrictEqual(a, c);
    });

    await t.test('changes when any individual identity field changes', () => {
        const base = generatePoolKey(makeSettings());
        const variants = {
            host: makeSettings({ host: 'smtp.other.com' }),
            port: makeSettings({ port: 465 }),
            secure: makeSettings({ secure: true }),
            name: makeSettings({ name: 'clienthost' }),
            localAddress: makeSettings({ localAddress: '10.0.0.9' }),
            proxy: makeSettings({ proxy: 'socks5://127.0.0.1:1080' }),
            transactionLog: makeSettings({ transactionLog: true })
        };
        for (const [field, settings] of Object.entries(variants)) {
            assert.notStrictEqual(generatePoolKey(settings), base, `${field} should affect the pool key`);
        }
    });
});

test('getMailTransport pooling', async t => {
    await t.test('returns the same cached transport for identical settings', () => {
        const before = getPoolSize();
        const t1 = transportFor(makeSettings({ host: 'reuse.example.com' }));
        const sizeAfterFirst = getPoolSize();
        const t2 = transportFor(makeSettings({ host: 'reuse.example.com' }));

        assert.strictEqual(t1, t2, 'identical settings must reuse the same transport');
        assert.strictEqual(getPoolSize(), sizeAfterFirst, 'reuse must not grow the pool');
        assert.strictEqual(sizeAfterFirst, before + 1);
    });

    await t.test('creates a distinct transport when credentials differ', () => {
        const t1 = transportFor(makeSettings({ host: 'distinct.example.com', auth: { user: 'alice@example.com', pass: 'p1' } }));
        const sizeAfterFirst = getPoolSize();
        const t2 = transportFor(makeSettings({ host: 'distinct.example.com', auth: { user: 'bob@example.com', pass: 'p2' } }));

        assert.notStrictEqual(t1, t2, 'different credentials must not share a transport');
        assert.strictEqual(getPoolSize(), sizeAfterFirst + 1);
    });
});

test('closePooledConnection', async t => {
    await t.test('removes a pooled transport so the next get recreates it', () => {
        const settings = makeSettings({ host: 'close.example.com' });
        const key = generatePoolKey(settings);
        const t1 = transportFor(settings);

        closePooledConnection(key);
        createdKeys.delete(key);
        assert.strictEqual(getMailTransport(settings) === t1, false, 'a fresh transport should be created after close');
        createdKeys.add(key);
    });

    await t.test('is a no-op for an unknown key', () => {
        const before = getPoolSize();
        assert.doesNotThrow(() => closePooledConnection('0'.repeat(64)));
        assert.strictEqual(getPoolSize(), before);
    });
});

test('exported metadata', () => {
    assert.strictEqual(typeof getPoolSize(), 'number');
    assert.strictEqual(SMTP_POOL_MAX_IDLE, 10 * 60 * 1000);
    assert.strictEqual(SMTP_POOL_CLEANUP_INTERVAL, 2 * 60 * 1000);
});
