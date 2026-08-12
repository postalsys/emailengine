'use strict';

const test = require('node:test');
const assert = require('node:assert').strict;

const { redis } = require('../lib/db');
const settings = require('../lib/settings');
const { oauth2Apps } = require('../lib/oauth2-apps');
const { REDIS_PREFIX } = require('../lib/consts');

const ACCOUNT_ID = 'legacy-migrate-test-account';

const LEGACY_SETTINGS = {
    gmailEnabled: true,
    gmailClientId: 'legacy-client-id.apps.googleusercontent.com',
    gmailClientSecret: 'legacy-client-secret-value',
    gmailRedirectUrl: 'https://example.com/oauth',
    gmailExtraScopes: ['https://www.googleapis.com/auth/userinfo.profile'],
    gmailAuthFlag: { message: 'Failed to renew the grant' },

    gmailServiceClient: '113111114523866710494',
    gmailServiceKey: '-----BEGIN PRIVATE KEY-----\nMIItest\n-----END PRIVATE KEY-----',

    // a stray key without client credentials never surfaced an app; it must only be cleaned up
    outlookRedirectUrl: 'https://example.com/oauth',

    // orphaned pre-gmailService generic service keys
    serviceClient: 'orphan-service-client'
};

async function cleanup() {
    for (let id of ['gmail', 'gmailService', 'outlook', 'mailRu']) {
        await redis.srem(`${REDIS_PREFIX}oapp:i`, id);
        await redis.hdel(`${REDIS_PREFIX}oapp:c`, `${id}:data`, `${id}:meta`);
        await redis.del(`${REDIS_PREFIX}oapp:a:${id}`);
    }
    await redis.hdel(`${REDIS_PREFIX}settings`, ...Object.keys(LEGACY_SETTINGS));
    await redis.srem(`${REDIS_PREFIX}ia:accounts`, ACCOUNT_ID);
    await redis.del(`${REDIS_PREFIX}iad:${ACCOUNT_ID}`);
}

test('Legacy OAuth2 app migration', async t => {
    t.after(() => {
        // Force exit after tests to prevent hanging on Redis connections from loaded modules
        setTimeout(() => process.exit(), 1000).unref();
    });

    t.beforeEach(async () => {
        await cleanup();
    });

    t.afterEach(async () => {
        await cleanup();
    });

    await t.test('migrateLegacyApps() converts settings into app records', async () => {
        for (let key of Object.keys(LEGACY_SETTINGS)) {
            await settings.set(key, LEGACY_SETTINGS[key]);
        }

        // an existing account referencing the legacy app id gets linked to the migrated app
        await redis.sadd(`${REDIS_PREFIX}ia:accounts`, ACCOUNT_ID);
        await redis.hset(`${REDIS_PREFIX}iad:${ACCOUNT_ID}`, 'oauth2', JSON.stringify({ provider: 'gmail', auth: { user: 'legacy.user@example.com' } }));

        let migrated = await oauth2Apps.migrateLegacyApps();
        assert.deepStrictEqual(migrated.sort(), ['gmail', 'gmailService']);

        // gmail: a fully configured, enabled app under the historical id
        let gmailApp = await oauth2Apps.get('gmail');
        assert.ok(gmailApp, 'gmail app exists');
        assert.equal(gmailApp.id, 'gmail');
        assert.equal(gmailApp.provider, 'gmail');
        assert.equal(gmailApp.enabled, true);
        assert.equal(gmailApp.baseScopes, 'imap');
        assert.equal(gmailApp.clientId, LEGACY_SETTINGS.gmailClientId);
        assert.equal(gmailApp.redirectUrl, LEGACY_SETTINGS.gmailRedirectUrl);
        assert.deepStrictEqual(gmailApp.extraScopes, LEGACY_SETTINGS.gmailExtraScopes);

        // the secret moved to app-level encryption and round-trips
        assert.notEqual(gmailApp.clientSecret, LEGACY_SETTINGS.gmailClientSecret, 'stored secret is not plaintext');
        assert.equal(await oauth2Apps.decrypt(gmailApp.clientSecret), LEGACY_SETTINGS.gmailClientSecret);

        // the auth error flag survived into app meta
        assert.equal(gmailApp.meta.authFlag.message, LEGACY_SETTINGS.gmailAuthFlag.message);

        // the account membership set was backfilled
        assert.equal(gmailApp.accounts, 1, 'existing account is linked');

        // gmailService: service apps are always enabled
        let serviceApp = await oauth2Apps.get('gmailService');
        assert.ok(serviceApp, 'gmailService app exists');
        assert.equal(serviceApp.enabled, true);
        assert.equal(serviceApp.authMethod, 'serviceKey');
        assert.equal(serviceApp.serviceClient, LEGACY_SETTINGS.gmailServiceClient);
        assert.equal(await oauth2Apps.decrypt(serviceApp.serviceKey), LEGACY_SETTINGS.gmailServiceKey);

        // outlook had no client configured, so no app was created
        assert.equal(await oauth2Apps.get('outlook'), false, 'stray outlook keys do not create an app');

        // every legacy settings key is gone, including strays and orphans
        for (let key of Object.keys(LEGACY_SETTINGS)) {
            assert.equal(await settings.get(key), null, `${key} was removed`);
        }

        // second run is a no-op
        assert.deepStrictEqual(await oauth2Apps.migrateLegacyApps(), []);
    });

    await t.test('migrated apps update through the regular app store', async () => {
        await settings.set('gmailEnabled', true);
        await settings.set('gmailClientId', LEGACY_SETTINGS.gmailClientId);
        await settings.set('gmailClientSecret', LEGACY_SETTINGS.gmailClientSecret);
        await settings.set('gmailRedirectUrl', LEGACY_SETTINGS.gmailRedirectUrl);

        await oauth2Apps.migrateLegacyApps();

        let updateResult = await oauth2Apps.update('gmail', { name: 'Renamed Gmail app', description: 'Edited after migration' });
        assert.deepStrictEqual(updateResult, { id: 'gmail', updated: true });

        let gmailApp = await oauth2Apps.get('gmail');
        assert.equal(gmailApp.name, 'Renamed Gmail app');
        assert.equal(gmailApp.description, 'Edited after migration');
        // updating did not touch the credential
        assert.equal(await oauth2Apps.decrypt(gmailApp.clientSecret), LEGACY_SETTINGS.gmailClientSecret);
    });

    await t.test('migrateLegacyApps() does not overwrite an existing app record', async () => {
        // simulate a half-done earlier migration: the app record exists, settings linger
        await redis.sadd(`${REDIS_PREFIX}oapp:i`, 'mailRu');
        await redis.hset(`${REDIS_PREFIX}oapp:c`, 'mailRu:data', require('../lib/msgpack').encode({ id: 'mailRu', provider: 'mailRu', name: 'Existing' }));

        await settings.set('mailRuEnabled', true);
        await settings.set('mailRuClientId', 'existing-client');

        let migrated = await oauth2Apps.migrateLegacyApps();
        assert.deepStrictEqual(migrated, [], 'existing record is not migrated again');

        let mailRuApp = await oauth2Apps.get('mailRu');
        assert.equal(mailRuApp.name, 'Existing', 'record was not overwritten');

        assert.equal(await settings.get('mailRuClientId'), null, 'lingering settings were still cleaned up');

        await redis.srem(`${REDIS_PREFIX}oapp:i`, 'mailRu');
        await redis.hdel(`${REDIS_PREFIX}oapp:c`, 'mailRu:data');
    });
});
