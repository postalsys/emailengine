'use strict';

const test = require('node:test');
const assert = require('node:assert').strict;

// Set test Redis prefix before loading modules
process.env.EENGINE_REDIS_PREFIX = 'test_settings_coupling';

const settings = require('../lib/settings');
const { redis } = require('../lib/db');
const { REDIS_PREFIX } = require('../lib/consts');

// Regression tests for settings.set() side effects. The AI/notifyText coupling used to be dead
// code (`key in [...]` tests array indices, never the values) and, had it matched, its early
// return would have skipped storing the actual key.
test('Settings AI text coupling', async t => {
    t.after(async () => {
        // Clean up any remaining test keys
        const keys = await redis.keys(`${REDIS_PREFIX}*`);
        if (keys.length > 0) {
            await redis.del(keys);
        }

        redis.quit();

        // Force exit after cleanup to prevent hanging on any remaining connections
        setTimeout(() => process.exit(), 1000).unref();
    });

    await t.test('enabling generateEmailSummary also enables notifyText and still stores the key', async () => {
        await settings.set('generateEmailSummary', true);

        assert.strictEqual(await settings.get('generateEmailSummary'), true, 'the actual key must be stored');
        assert.strictEqual(await settings.get('notifyText'), true, 'notifyText must be auto-enabled for AI processing');

        const version = Number(await redis.hget(`${REDIS_PREFIX}settings`, 'openAiSettingsVersion'));
        assert.ok(version >= 1, 'the OpenAI settings version must still be bumped');
    });

    await t.test('enabling openAiGenerateEmbeddings also enables notifyText', async () => {
        await redis.hdel(`${REDIS_PREFIX}settings`, 'notifyText');

        await settings.set('openAiGenerateEmbeddings', true);

        assert.strictEqual(await settings.get('openAiGenerateEmbeddings'), true);
        assert.strictEqual(await settings.get('notifyText'), true);
    });

    await t.test('disabling the AI keys does not touch notifyText', async () => {
        await redis.hdel(`${REDIS_PREFIX}settings`, 'notifyText');

        await settings.set('generateEmailSummary', false);
        await settings.set('openAiGenerateEmbeddings', false);

        assert.strictEqual(await redis.hget(`${REDIS_PREFIX}settings`, 'notifyText'), null, 'notifyText must stay unset');
        assert.strictEqual(await settings.get('generateEmailSummary'), false);
    });
});
