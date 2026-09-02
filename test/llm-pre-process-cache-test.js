'use strict';

const test = require('node:test');
const assert = require('node:assert').strict;

// Set test Redis prefix before loading modules
process.env.EENGINE_REDIS_PREFIX = 'test_llm_pre_process_cache';

const { llmPreProcess } = require('../lib/llm-pre-process');
const settings = require('../lib/settings');
const { redis } = require('../lib/db');
const { REDIS_PREFIX } = require('../lib/consts');
const registerRedisTeardown = require('./helpers/redis-teardown');

registerRedisTeardown(redis, async () => {
    const keys = await redis.keys(`${REDIS_PREFIX}*`);
    if (keys.length > 0) {
        await redis.del(keys);
    }
});

// Regression tests for the handler cache in getPreProcessHandler(). The version marker was never
// assigned after a rebuild, so the comparison was always true and the handler (one hget plus four
// settings reads and a script compile) was rebuilt for every message. lib/pre-process.js carries
// the same cache; it is exercised through the same code shape.
test('LLM pre-process handler cache', async t => {
    const storedVersion = async () => Number(await redis.hget(`${REDIS_PREFIX}settings`, 'openAiSettingsVersion')) || 0;

    await t.test('builds the handler once and marks the cache current', async () => {
        await settings.set('openAiAPIKey', 'test-key');
        await settings.set('generateEmailSummary', true);
        await settings.set('openAiPreProcessingFn', 'return true;');

        const version = await storedVersion();
        assert.ok(version >= 1, 'writing the settings must bump the version counter');

        const first = await llmPreProcess.getPreProcessHandler();
        assert.ok(first && typeof first.filterFn === 'function', 'the handler must be built');
        assert.strictEqual(llmPreProcess.handlerCacheV, version, 'the cache marker must match the stored version');

        const second = await llmPreProcess.getPreProcessHandler();
        assert.strictEqual(second, first, 'an unchanged version must return the cached handler');
    });

    await t.test('a settings change rebuilds the handler', async () => {
        const cached = await llmPreProcess.getPreProcessHandler();

        await settings.set('openAiPreProcessingFn', 'return false;');

        const rebuilt = await llmPreProcess.getPreProcessHandler();
        assert.notStrictEqual(rebuilt, cached, 'a bumped version must rebuild the handler');
        assert.strictEqual(llmPreProcess.handlerCacheV, await storedVersion());
        assert.strictEqual(await rebuilt.filterFn({}), false, 'the rebuilt handler must run the new script');
    });

    await t.test('disabling the feature caches the absence of a handler', async () => {
        await settings.set('generateEmailSummary', false);

        assert.strictEqual(await llmPreProcess.getPreProcessHandler(), null);
        assert.strictEqual(llmPreProcess.handlerCacheV, await storedVersion(), 'a null handler is a valid cached state');
    });
});
