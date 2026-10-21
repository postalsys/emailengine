'use strict';

// lib/env-setting-overrides.js: the limits that used to be environment-only and are now settings
// too, the environment winning. The resolution rule is checked as a pure function over every key
// and every combination of sources, and the Redis-backed read and write paths against a real
// settings store.

const test = require('node:test');
const assert = require('node:assert').strict;

const { redis } = require('../lib/db');
const registerRedisTeardown = require('./helpers/redis-teardown');
const settings = require('../lib/settings');
const overrides = require('../lib/env-setting-overrides');
const { buildRetentionPolicy } = require('../lib/queue-retention');

const { OVERRIDABLE_SETTINGS, resolveOverridableSetting } = overrides;
const KEYS = Object.keys(OVERRIDABLE_SETTINGS);

// One valid environment string, one valid stored value, and one unusable value of each, per key
const SAMPLES = {
    disableThreadCollapse: { env: 'true', envValue: true, stored: true, badEnv: undefined, badStored: 'yes' },
    queueKeepFailed: { env: '750', envValue: 750, stored: 900, badEnv: 'many', badStored: 0 },
    queueKeepFailedAge: { env: '3600', envValue: 3600, stored: 7200, badEnv: '-1', badStored: -5 },
    queueKeepFailedContent: { env: '0', envValue: 0, stored: 25, badEnv: 'none', badStored: -1 },
    queueKeepFailedContentSize: { env: '5MB', envValue: 5 * 1024 * 1024, stored: 2048, badEnv: 'lots', badStored: 'big' },
    tokenLogEntries: { env: '50', envValue: 50, stored: 75, badEnv: '0', badStored: 0 },
    tokenLogAge: { env: '600', envValue: 600, stored: 1200, badEnv: 'week', badStored: null }
};

registerRedisTeardown(redis, async () => {
    for (const key of KEYS) {
        await settings.clear(key);
    }
});

test('every overridable setting has a test sample and a settings schema entry', () => {
    const { settingsSchema } = require('../lib/schemas');
    for (const key of KEYS) {
        assert.ok(SAMPLES[key], `no sample for ${key}`);
        assert.ok(settingsSchema[key], `${key} is not in settingsSchema, so the settings API would refuse it`);
        assert.match(OVERRIDABLE_SETTINGS[key].env, /^EENGINE_[A-Z_]+$/);
    }
});

test('resolveOverridableSetting(): the environment wins, then the setting, then the default', async t => {
    // Every combination of the three sources being present, valid, or unusable, for every key.
    // The expected answer is derived from the rule, not written out per case, so a key added to
    // the table is covered by adding its sample.
    const envStates = ['unset', 'valid', 'invalid'];
    const storedStates = ['unset', 'valid', 'invalid'];

    for (const key of KEYS) {
        const sample = SAMPLES[key];
        const { defaultValue } = OVERRIDABLE_SETTINGS[key];

        for (const envState of envStates) {
            for (const storedState of storedStates) {
                // a boolean environment value is never unusable (anything not truthy reads as false)
                if (envState === 'invalid' && sample.badEnv === undefined) {
                    continue;
                }
                await t.test(`${key}: environment ${envState}, setting ${storedState}`, () => {
                    const sources = {
                        envSet: envState !== 'unset',
                        envValue: envState === 'valid' ? sample.env : envState === 'invalid' ? sample.badEnv : undefined,
                        storedValue: storedState === 'valid' ? sample.stored : storedState === 'invalid' ? sample.badStored : undefined
                    };
                    let expected;
                    if (envState === 'valid') {
                        expected = { value: sample.envValue, source: 'env' };
                    } else if (storedState === 'valid') {
                        expected = { value: sample.stored, source: 'setting' };
                    } else {
                        expected = { value: defaultValue, source: 'default' };
                    }
                    assert.deepEqual(resolveOverridableSetting(key, sources), expected);
                });
            }
        }
    }
});

test('resolveOverridableSetting(): 0 keeps no failed content, but is not a valid count or age', () => {
    assert.equal(resolveOverridableSetting('queueKeepFailedContent', { envSet: true, envValue: '0' }).value, 0);
    assert.equal(resolveOverridableSetting('queueKeepFailedContentSize', { envSet: false, storedValue: 0 }).value, 0);
    assert.equal(resolveOverridableSetting('queueKeepFailed', { envSet: true, envValue: '0' }).source, 'default');
    assert.equal(resolveOverridableSetting('tokenLogAge', { envSet: false, storedValue: 0 }).source, 'default');
});

test('resolveOverridableSetting(): unknown keys are a programming error', () => {
    assert.throws(() => resolveOverridableSetting('queueKeep', { envSet: false }), /Unknown overridable setting/);
});

test('getOverridableSettings() reads stored settings and caches them', async () => {
    overrides.resetOverridableSettingsCache();
    await settings.setMulti({ queueKeepFailed: 1234, queueKeepFailedAge: 5678 });
    overrides.resetOverridableSettingsCache();

    assert.deepEqual(await overrides.getFailedJobRetention(), { age: 5678, count: 1234 });

    // a write that bypasses this module is not seen until the cache window passes
    await settings.set('queueKeepFailed', 4321);
    assert.equal((await overrides.getOverridableSettings('queueKeepFailed')).queueKeepFailed, 1234);
    overrides.resetOverridableSettingsCache();
    assert.equal((await overrides.getOverridableSettings('queueKeepFailed')).queueKeepFailed, 4321);

    // the resolved bounds are what the job options carry
    const { removeOnFail } = buildRetentionPolicy(0, await overrides.getFailedJobRetention());
    assert.deepEqual(removeOnFail, { age: 5678, count: 4321 });

    await settings.clear('queueKeepFailed');
    await settings.clear('queueKeepFailedAge');
    overrides.resetOverridableSettingsCache();
});

test('writeOverridableSettings()', async t => {
    await t.test('writes plain keys, writes overridable keys, and clears an overridable key given null', async () => {
        await settings.set('queueKeepFailedContent', 10);
        await overrides.writeOverridableSettings({ queueKeep: 7, queueKeepFailed: 800, queueKeepFailedContent: null });

        assert.equal(await settings.get('queueKeep'), 7);
        assert.equal(await settings.get('queueKeepFailed'), 800);
        assert.equal(await settings.get('queueKeepFailedContent'), null);
        // and this process sees the write at once
        assert.equal((await overrides.getOverridableSettings('queueKeepFailed')).queueKeepFailed, 800);
    });

    await t.test('does not copy a pinned environment value into the setting', async () => {
        await settings.clear('queueKeepFailed');
        process.env.EENGINE_QUEUE_KEEP_FAILED = '999';
        try {
            assert.deepEqual(overrides.envOverriddenSettings(['queueKeepFailed', 'queueKeepFailedAge']), [
                { key: 'queueKeepFailed', env: 'EENGINE_QUEUE_KEEP_FAILED' }
            ]);
            await overrides.writeOverridableSettings({ queueKeepFailed: 999 });
            assert.equal(await settings.get('queueKeepFailed'), null, 'the environment value was not stored');
            assert.equal((await overrides.getOverridableSettings('queueKeepFailed')).queueKeepFailed, 999);
        } finally {
            delete process.env.EENGINE_QUEUE_KEEP_FAILED;
            overrides.resetOverridableSettingsCache();
        }
    });

    await t.test('an unparsable environment value is not reported as pinning the field', () => {
        process.env.EENGINE_TOKEN_LOG_ENTRIES = 'lots';
        try {
            assert.deepEqual(overrides.envOverriddenSettings(['tokenLogEntries']), []);
        } finally {
            delete process.env.EENGINE_TOKEN_LOG_ENTRIES;
        }
    });

    await settings.clear('queueKeep');
    await settings.clear('queueKeepFailed');
});

test('the token log limits are privileged, like the switch that turns the log on', () => {
    const { PRIVILEGED_SETTINGS_KEYS } = require('../lib/privileged-settings');
    for (const key of ['tokenAuditLog', 'tokenLogEntries', 'tokenLogAge']) {
        assert.ok(PRIVILEGED_SETTINGS_KEYS.includes(key), key);
    }
});
