'use strict';

// Unit tests for the OAuth2AppsHandler stateful core (lib/oauth2-apps.js):
// create/get/update/list/del and, crucially, credential encryption at rest.
// Provider client secrets (clientSecret, serviceKey, accessToken,
// externalAccount) must be stored encrypted and only decrypted when building a
// client. Previously only the pure helpers (formatExtraScopes, scope detection)
// were covered, not the handler that persists credentials.

const test = require('node:test');
const assert = require('node:assert').strict;

const { oauth2Apps } = require('../lib/oauth2-apps');
const { redis } = require('../lib/db');
const registerRedisTeardown = require('./helpers/redis-teardown');
const { REDIS_PREFIX } = require('../lib/consts');

const msgpack = require('msgpack5')();

const createdIds = [];

async function createApp(overrides) {
    const data = Object.assign(
        {
            provider: 'gmail',
            name: 'CRUD Test App',
            enabled: true,
            clientId: 'client-id-123',
            clientSecret: 'super-secret-value',
            redirectUrl: 'https://example.test/oauth/redirect',
            baseScopes: 'imap'
        },
        overrides || {}
    );
    const res = await oauth2Apps.create(data);
    createdIds.push(res.id);
    return res.id;
}

// Read the raw stored entry straight out of Redis (bypassing get()).
async function rawEntry(id) {
    const buf = await redis.hgetBuffer(`${REDIS_PREFIX}oapp:c`, `${id}:data`);
    return buf ? msgpack.decode(buf) : null;
}

registerRedisTeardown(redis, async () => {
    for (const id of createdIds) {
        try {
            await oauth2Apps.del(id);
        } catch (err) {
            // ignore
        }
    }
});

test('OAuth2AppsHandler CRUD and encryption', async t => {
    await t.test('create then get round-trips non-secret fields', async () => {
        const id = await createApp();
        const app = await oauth2Apps.get(id);
        assert.ok(app, 'created app must be retrievable');
        assert.strictEqual(app.id, id);
        assert.strictEqual(app.provider, 'gmail');
        assert.strictEqual(app.clientId, 'client-id-123');
        assert.ok(app.created, 'app records a creation timestamp');
    });

    await t.test('clientSecret is stored encrypted, not in cleartext', async () => {
        const id = await createApp({ clientSecret: 'plaintext-secret-xyz' });

        const stored = await rawEntry(id);
        assert.ok(stored.clientSecret, 'clientSecret must be persisted');
        assert.notStrictEqual(stored.clientSecret, 'plaintext-secret-xyz', 'clientSecret must not be stored as cleartext');
        assert.ok(!stored.clientSecret.toString().includes('plaintext-secret-xyz'), 'cleartext secret must not appear in the stored value');

        // The handler can decrypt it back to the original.
        const decrypted = await oauth2Apps.decrypt(stored.clientSecret);
        assert.strictEqual(decrypted, 'plaintext-secret-xyz');
    });

    await t.test('get() returns the data unchanged for missing app', async () => {
        assert.strictEqual(await oauth2Apps.get('does-not-exist-id'), false);
    });

    await t.test('update re-encrypts a changed secret', async () => {
        const id = await createApp({ clientSecret: 'original-secret' });

        await oauth2Apps.update(id, { clientSecret: 'rotated-secret' });

        const stored = await rawEntry(id);
        assert.notStrictEqual(stored.clientSecret, 'rotated-secret', 'rotated secret must be encrypted at rest');
        assert.strictEqual(await oauth2Apps.decrypt(stored.clientSecret), 'rotated-secret');
    });

    await t.test('update of a missing app throws NotFound', async () => {
        await assert.rejects(
            () => oauth2Apps.update('does-not-exist-id', { name: 'x' }),
            err => err.statusCode === 404 || err.code === 'NotFound'
        );
    });

    await t.test('list includes a created app', async () => {
        const id = await createApp({ name: 'Listed App' });
        const listing = await oauth2Apps.list(0, 1000);
        const apps = listing.apps || listing.entries || [];
        assert.ok(
            apps.some(app => app.id === id),
            'the created app should appear in the listing'
        );
    });

    await t.test('del removes the app and its index entry', async () => {
        const id = await createApp();
        // sanity: present before delete
        assert.ok(await oauth2Apps.get(id));

        await oauth2Apps.del(id);

        assert.strictEqual(await oauth2Apps.get(id), false, 'app must be gone after delete');
        assert.strictEqual(await redis.sismember(`${REDIS_PREFIX}oapp:i`, id), 0, 'index set must no longer reference the app');

        // Remove from cleanup list (already deleted).
        const idx = createdIds.indexOf(id);
        if (idx >= 0) {
            createdIds.splice(idx, 1);
        }
    });
});
