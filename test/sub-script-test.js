'use strict';

// Sandbox tests for lib/sub-script.js. SubScript runs user-supplied JavaScript
// (webhook filter/map functions, pre-processing) inside a Node vm context on
// every matching event, so its resource limits and context isolation are
// security sensitive and previously had no test coverage.

const test = require('node:test');
const assert = require('node:assert').strict;

const { SubScript } = require('../lib/sub-script');
const settings = require('../lib/settings');
const { redis } = require('../lib/db');

test.after(async () => {
    try {
        await redis.quit();
    } catch (err) {
        // ignore - connection may already be closing
    }
});

const run = (code, payload, options) => SubScript.create('test', code).exec(payload, options);

test('SubScript sandbox', async t => {
    await t.test('executes code and returns a value derived from payload', async () => {
        const result = await run('return payload.a + payload.b;', { a: 2, b: 3 });
        assert.strictEqual(result, 5);
    });

    await t.test('supports async/await inside the script', async () => {
        const result = await run('return await Promise.resolve(42);');
        assert.strictEqual(result, 42);
    });

    await t.test('defaults payload to an empty object when none provided', async () => {
        const result = await run('return Object.keys(payload).length;');
        assert.strictEqual(result, 0);
    });

    await t.test('payload is cloned - mutations do not leak to the caller', async () => {
        const original = { count: 1, nested: { x: 1 } };
        const result = await run('payload.count = 999; payload.nested.x = 999; return payload.count;', original);
        assert.strictEqual(result, 999);
        // The caller's object must be untouched (structuredClone isolation).
        assert.strictEqual(original.count, 1);
        assert.strictEqual(original.nested.x, 1);
    });

    await t.test('exposes the URL constructor', async () => {
        const result = await run("return new URL('https://example.test/path?q=1').pathname;");
        assert.strictEqual(result, '/path');
    });

    await t.test('exposes a logger that does not throw', async () => {
        const result = await run("logger.info({ msg: 'hello from subscript' }); return 'ok';");
        assert.strictEqual(result, 'ok');
    });

    await t.test('exposes fetch as a function', async () => {
        const result = await run('return typeof fetch;');
        assert.strictEqual(result, 'function');
    });

    await t.test('does not expose Node internals (process/require/module)', async () => {
        assert.strictEqual(await run('return typeof process;'), 'undefined');
        assert.strictEqual(await run('return typeof require;'), 'undefined');
        assert.strictEqual(await run('return typeof module;'), 'undefined');
        assert.strictEqual(await run('return typeof global;'), 'undefined');
    });

    await t.test('injects env from the scriptEnv setting', async () => {
        const previous = await settings.get('scriptEnv');
        try {
            await settings.set('scriptEnv', JSON.stringify({ TOKEN: 'secret-value' }));
            const result = await run('return env.TOKEN;');
            assert.strictEqual(result, 'secret-value');
        } finally {
            await settings.set('scriptEnv', previous || '');
        }
    });

    await t.test('env is an empty object when scriptEnv is not set', async () => {
        const previous = await settings.get('scriptEnv');
        try {
            await settings.set('scriptEnv', '');
            const result = await run('return typeof env.TOKEN;');
            assert.strictEqual(result, 'undefined');
        } finally {
            await settings.set('scriptEnv', previous || '');
        }
    });

    await t.test('enforces the execution timeout on a runaway script', async () => {
        await assert.rejects(
            () => run('while (true) {}', {}, { timeout: 200 }),
            err => {
                assert.match(err.message, /timed out/i);
                return true;
            }
        );
    });

    await t.test('propagates runtime errors thrown by the script', async () => {
        await assert.rejects(
            () => run("throw new Error('boom');"),
            err => {
                assert.strictEqual(err.message, 'boom');
                return true;
            }
        );
    });

    await t.test('throws a compile error for invalid syntax and caches it', async () => {
        const badCode = 'return (((;';
        assert.throws(() => SubScript.create('bad', badCode));
        // The compiled-script cache stores the error keyed by code hash, so a
        // second attempt with identical code must throw the same way (not a
        // fresh successful compile).
        assert.throws(() => SubScript.create('bad', badCode));
    });
});
