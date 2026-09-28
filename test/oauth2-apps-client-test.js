'use strict';

// OAuth2AppsHandler behaviors around the provider clients it builds: the Workload Identity
// Federation signer shared across clients, the auth flag bookkeeping done after each request,
// and the service token renewal. Runs against the test Redis like oauth2-apps-crud-test.js.

const test = require('node:test');
const assert = require('node:assert').strict;

const { oauth2Apps } = require('../lib/oauth2-apps');
const { redis } = require('../lib/db');
const registerRedisTeardown = require('./helpers/redis-teardown');
const { REDIS_PREFIX } = require('../lib/consts');
const msgpack = require('../lib/msgpack');

const createdIds = [];

registerRedisTeardown(redis, async () => {
    for (const id of createdIds) {
        try {
            await oauth2Apps.del(id);
        } catch (err) {
            // ignore
        }
    }
});

const WIF_CONFIG = {
    type: 'external_account',
    audience: '//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/provider',
    subject_token_type: 'urn:ietf:params:oauth:token-type:jwt',
    token_url: 'https://sts.googleapis.com/v1/token',
    service_account_impersonation_url:
        'https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/svc%40proj.iam.gserviceaccount.com:generateAccessToken',
    credential_source: { file: '/var/run/secrets/tokens/gcp-ksa/token', format: { type: 'text' } }
};

async function createApp(data) {
    const res = await oauth2Apps.create(data);
    createdIds.push(res.id);
    return res.id;
}

function createGmailApp() {
    return createApp({
        provider: 'gmail',
        name: 'Client test app',
        enabled: true,
        clientId: 'client-id',
        clientSecret: 'client-secret',
        redirectUrl: 'https://example.test/oauth',
        baseScopes: 'api'
    });
}

async function readMeta(id) {
    const buf = await redis.hgetBuffer(`${REDIS_PREFIX}oapp:c`, `${id}:meta`);
    return buf ? msgpack.decode(buf) : null;
}

// Counts the meta writes (setMeta is the only writer of the meta entry)
function countMetaWrites() {
    const original = oauth2Apps.setMeta;
    const counter = { writes: 0 };
    oauth2Apps.setMeta = async function (...args) {
        counter.writes++;
        return original.apply(this, args);
    };
    counter.restore = () => {
        oauth2Apps.setMeta = original;
    };
    return counter;
}

test('OAuth2AppsHandler client helpers', async t => {
    // Every renewal builds a new GmailOauth; with a signer per client the federated token cache
    // and the refresh deduplication never outlived one renewal
    await t.test('WIF clients of one app share their signer until the app changes', async () => {
        const id = await createApp({
            provider: 'gmailService',
            name: 'WIF app',
            serviceClient: '1234567890',
            serviceClientEmail: 'svc@proj.iam.gserviceaccount.com',
            authMethod: 'externalAccount',
            externalAccount: JSON.stringify(WIF_CONFIG),
            baseScopes: 'imap'
        });

        const first = await oauth2Apps.getClient(id);
        const second = await oauth2Apps.getClient(id);
        assert.ok(first.signer, 'a WIF client has a signer');
        assert.strictEqual(first.signer, second.signer);

        await oauth2Apps.update(id, { name: 'WIF app renamed' });
        const third = await oauth2Apps.getClient(id);
        assert.notStrictEqual(third.signer, first.signer, 'an app update drops the cached signer');
    });

    await t.test('a successful request with no flag set writes no meta', async () => {
        const id = await createGmailApp();
        const client = await oauth2Apps.getClient(id);
        const counter = countMetaWrites();
        try {
            await client.setFlag();
            await client.setFlag();
            await client.setFlag();
        } finally {
            counter.restore();
        }
        assert.strictEqual(counter.writes, 0);
    });

    await t.test('a set flag is written at once and cleared by the next success', async () => {
        const id = await createGmailApp();
        const client = await oauth2Apps.getClient(id);

        await client.setFlag({ message: 'Failed to renew' });
        assert.deepStrictEqual((await readMeta(id)).authFlag, { message: 'Failed to renew' });

        await client.setFlag();
        assert.strictEqual((await readMeta(id)).authFlag, null);
    });

    await t.test('a flag set elsewhere is cleared by the first success of a client', async () => {
        const id = await createGmailApp();
        await oauth2Apps.setMeta(id, { authFlag: { message: 'set by another worker' }, pubSubFlag: { message: 'keep me' } });

        const client = await oauth2Apps.getClient(id);
        await client.setFlag();

        const meta = await readMeta(id);
        assert.strictEqual(meta.authFlag, null);
        assert.deepStrictEqual(meta.pubSubFlag, { message: 'keep me' }, 'other meta fields are kept');
    });

    await t.test('setMeta replaces an unreadable meta entry instead of throwing', async () => {
        const id = await createGmailApp();
        await redis.hset(`${REDIS_PREFIX}oapp:c`, `${id}:meta`, Buffer.from([0xc1]));

        await oauth2Apps.setMeta(id, { authFlag: { message: 'x' } });

        assert.deepStrictEqual((await readMeta(id)).authFlag, { message: 'x' });
    });

    // new Date(now + undefined * 1000).toISOString() threw a RangeError after a successful renewal
    await t.test('getServiceAccessToken() defaults a missing expires_in to an hour', async () => {
        const id = await createGmailApp();
        const appData = await oauth2Apps.get(id);
        const client = { refreshToken: async () => ({ access_token: 'service-token' }) };

        const before = Date.now();
        const token = await oauth2Apps.getServiceAccessToken(appData, client);

        assert.strictEqual(token, 'service-token');
        const stored = await oauth2Apps.get(id);
        const expires = new Date(stored.accessTokenExpires).getTime();
        assert.ok(expires >= before + 3599 * 1000 && expires <= Date.now() + 3600 * 1000);
    });

    await t.test('invalidateServiceAccessToken() drops the cached token', async () => {
        const id = await createGmailApp();
        await oauth2Apps.update(id, { accessToken: 'cached', accessTokenExpires: new Date(Date.now() + 3600 * 1000).toISOString() }, { partial: true });

        await oauth2Apps.invalidateServiceAccessToken(id);

        const stored = await oauth2Apps.get(id);
        assert.strictEqual(stored.accessToken, null);
        assert.strictEqual(stored.accessTokenExpires, null);
    });
});
