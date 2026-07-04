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
// return would have skipped storing the actual key. Also covers settings.setIfMissing(), the
// atomic HSETNX mint path used by getServiceSecret().
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

    // serviceSecret is an ENCRYPTED_KEYS member, so these also exercise the encryption round trip.
    await t.test('setIfMissing stores when the key is absent', async () => {
        await redis.hdel(`${REDIS_PREFIX}settings`, 'serviceSecret');

        assert.strictEqual(await settings.setIfMissing('serviceSecret', 'secret-a'), true, 'must report the value as stored');
        assert.strictEqual(await settings.get('serviceSecret'), 'secret-a', 'get() must round-trip the stored value');
    });

    await t.test('setIfMissing preserves an existing value', async () => {
        assert.strictEqual(await settings.setIfMissing('serviceSecret', 'secret-b'), false, 'must report the value as not stored');
        assert.strictEqual(await settings.get('serviceSecret'), 'secret-a', 'the existing value must be preserved');
    });

    // A blank serviceSecret must never overwrite a stored one: an empty secret would break HMAC signing
    // and make getServiceSecret() silently mint a fresh secret, invalidating every outstanding tracking
    // and hosted-form link. set()/setMulti() treat a blank value as "keep the current secret".
    await t.test('set() refuses to blank an existing serviceSecret', async () => {
        await settings.set('serviceSecret', 'keep-me');

        await settings.set('serviceSecret', '');
        assert.strictEqual(await settings.get('serviceSecret'), 'keep-me', 'an empty string must not clear the stored secret');

        await settings.set('serviceSecret', '   ');
        assert.strictEqual(await settings.get('serviceSecret'), 'keep-me', 'a whitespace-only value must not clear the stored secret');

        await settings.set('serviceSecret', null);
        assert.strictEqual(await settings.get('serviceSecret'), 'keep-me', 'a null value must not clear the stored secret');

        // A non-empty value still rotates it.
        await settings.set('serviceSecret', 'rotated');
        assert.strictEqual(await settings.get('serviceSecret'), 'rotated', 'a non-empty value must still update the secret');
    });

    await t.test('setMulti refuses to blank an existing serviceSecret', async () => {
        await settings.set('serviceSecret', 'keep-me-multi');

        await settings.setMulti({ serviceSecret: '', pageBrandName: 'Example' });
        assert.strictEqual(await settings.get('serviceSecret'), 'keep-me-multi', 'setMulti must not clear the stored secret');
        assert.strictEqual(await settings.get('pageBrandName'), 'Example', 'other keys in the same setMulti must still be stored');
    });
});
