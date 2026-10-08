'use strict';

// The `metadataServer` authentication method: a Cloud Pub/Sub app that authenticates as the service
// account attached to the Google Cloud VM, GKE workload or Cloud Run service EmailEngine runs on,
// with no credential stored. Covers the client (token from the metadata server, never delegated),
// the stored app (accepted without credentials, its method pinned on every later update), the
// token cache, the verify report, and the schemas that keep the method to Pub/Sub apps.
//
// A local HTTP server stands in for the metadata server through EENGINE_GCP_METADATA_HOST, which is
// what that override exists for. Requests to the Pub/Sub API are answered by a stubbed
// GmailOauth.prototype.request, so nothing here leaves the host.

const test = require('node:test');
const assert = require('node:assert').strict;
const http = require('node:http');
const Joi = require('joi');

const { GmailOauth, normalizeAuthMethod } = require('../lib/oauth/gmail');
const { oauth2Apps, isAuthMethodLocked } = require('../lib/oauth2-apps');
const { verifyOAuth2App, __test__: verifyTest } = require('../lib/oauth/verify-app');
const { oauthCreateSchema, oauthUpdateSchema } = require('../lib/schemas');
const { redis } = require('../lib/db');
const registerRedisTeardown = require('./helpers/redis-teardown');

const SERVICE_ACCOUNT_EMAIL = 'ee-pubsub@proj-meta-1.iam.gserviceaccount.com';

// ---- metadata server double ----

const metadata = { mode: 'ok', tokenRequests: 0, token: 'metadata-token-1' };

const metadataServer = http.createServer((req, res) => {
    if (req.headers['metadata-flavor'] !== 'Google') {
        res.writeHead(403);
        return res.end('Missing Metadata-Flavor:Google header.');
    }
    const reply = (status, body, type = 'text/plain') => {
        res.writeHead(status, { 'Content-Type': type, 'Metadata-Flavor': 'Google' });
        res.end(body);
    };
    switch (req.url) {
        case '/computeMetadata/v1/instance/service-accounts/default/token':
            metadata.tokenRequests++;
            if (metadata.mode === 'no-service-account') {
                return reply(404, 'Not Found');
            }
            return reply(200, JSON.stringify({ access_token: metadata.token, expires_in: 3599, token_type: 'Bearer' }), 'application/json');
        case '/computeMetadata/v1/instance/service-accounts/default/email':
            return reply(200, SERVICE_ACCOUNT_EMAIL);
        case '/computeMetadata/v1/project/project-id':
            return reply(200, 'proj-meta-1');
        default:
            return reply(404, 'Not Found');
    }
});

// ---- Pub/Sub API double ----

const pubsubCalls = [];
let pubsubAnswer = async () => ({ topics: [] });
const originalRequest = GmailOauth.prototype.request;
GmailOauth.prototype.request = async function (accessToken, url, method) {
    pubsubCalls.push({ accessToken, url, method });
    return pubsubAnswer(url);
};

const createdIds = [];

registerRedisTeardown(redis, async () => {
    GmailOauth.prototype.request = originalRequest;
    for (const id of createdIds) {
        try {
            await oauth2Apps.del(id);
        } catch (err) {
            // ignore
        }
    }
    await new Promise(resolve => metadataServer.close(resolve));
});

test.before(async () => {
    await new Promise(resolve => metadataServer.listen(0, '127.0.0.1', resolve));
    process.env.EENGINE_GCP_METADATA_HOST = `127.0.0.1:${metadataServer.address().port}`;
});

async function createApp(data) {
    const res = await oauth2Apps.create(data);
    createdIds.push(res.id);
    return res.id;
}

// No googleProjectId at creation, so creating the app does not run the Pub/Sub setup; the tests
// that need a project add it with a partial update, which skips that too
function createMetadataApp(extra = {}) {
    return createApp(
        Object.assign({ provider: 'gmailService', name: 'Metadata server app', enabled: true, baseScopes: 'pubsub', authMethod: 'metadataServer' }, extra)
    );
}

function apiError(statusCode, message) {
    return Object.assign(new Error('Request failed'), { statusCode, oauthRequest: { response: { error: { code: statusCode, message } } } });
}

test('GmailOauth with the attached service account', async t => {
    const flags = [];
    const setFlag = async flag => flags.push(flag);
    const build = metadataClient => new GmailOauth({ provider: 'gmailService', authMethod: 'metadataServer', baseScopes: 'pubsub', metadataClient, setFlag });

    await t.test('is a service app with no signer and no OpenID scopes', () => {
        const client = build({ fetchAccessToken: async () => ({}) });
        assert.equal(client.authMethod, 'metadataServer');
        assert.equal(client.signer, undefined);
        assert.ok(!client.scopes.includes('openid'), 'a service app never asks for OpenID scopes');
    });

    await t.test('takes the token from the metadata server and clears the flag', async () => {
        flags.length = 0;
        const token = { access_token: 'from-metadata', expires_in: 3599, token_type: 'Bearer' };
        const client = build({ fetchAccessToken: async () => token });

        assert.deepEqual(await client.refreshToken({ isPrincipal: true }), token);
        assert.deepEqual(flags, [undefined]);
    });

    await t.test('refuses a delegated request without asking the metadata server', async () => {
        let asked = false;
        const client = build({
            fetchAccessToken: async () => {
                asked = true;
                return { access_token: 'x' };
            }
        });

        await assert.rejects(client.refreshToken({ user: 'someone@example.com' }), { code: 'EDelegationUnsupported' });
        assert.equal(asked, false);
    });

    await t.test('a failure sets a flag the app page can show, and rethrows', async () => {
        flags.length = 0;
        const failure = Object.assign(new Error('The metadata server at http://x returned HTTP 404'), { code: 'EMetadataServer', statusCode: 404 });
        const client = build({
            fetchAccessToken: async () => {
                throw failure;
            }
        });

        await assert.rejects(client.refreshToken({ isPrincipal: true }), err => {
            assert.equal(err, failure);
            assert.equal(err.tokenRequest.flag.code, 'METADATA_SERVER');
            assert.equal(err.tokenRequest.signer, 'metadataServer');
            return true;
        });
        assert.equal(flags.length, 1);
        assert.equal(flags[0].code, 'METADATA_SERVER');
        assert.match(flags[0].message, /HTTP 404/);
    });

    await t.test('the key-signed method is unchanged', () => {
        const client = new GmailOauth({
            provider: 'gmailService',
            serviceClient: '123',
            serviceClientEmail: 'a@b.iam.gserviceaccount.com',
            serviceKey: 'k',
            setFlag
        });
        assert.equal(client.authMethod, 'serviceKey');
        assert.ok(client.signer, 'a key-signed app still builds its signer');
    });

    await t.test('normalizeAuthMethod() keeps every known method and defaults the rest to serviceKey', () => {
        for (const method of ['serviceKey', 'externalAccount', 'metadataServer']) {
            assert.equal(normalizeAuthMethod(method), method);
        }
        for (const method of [undefined, null, '', 'bogus']) {
            assert.equal(normalizeAuthMethod(method), 'serviceKey');
        }
    });
});

test('a stored app using the attached service account', async t => {
    await t.test('is created without any credential, and a key sent along is not stored', async () => {
        // create() is also reached by the legacy settings migration, which no schema runs on
        const id = await createMetadataApp({ serviceKey: '-----BEGIN PRIVATE KEY-----\nabc', externalAccount: '{"type":"external_account"}' });
        const stored = await oauth2Apps.get(id);

        assert.equal(stored.authMethod, 'metadataServer');
        assert.equal(stored.serviceKey, undefined);
        assert.equal(stored.externalAccount, undefined);

        const client = await oauth2Apps.getClient(id);
        assert.equal(client.authMethod, 'metadataServer');
    });

    await t.test('renews its token from the metadata server and caches it like any service token', async () => {
        const id = await createMetadataApp();
        metadata.token = 'metadata-token-cache';
        const before = metadata.tokenRequests;

        const client = await oauth2Apps.getClient(id);
        assert.equal(await oauth2Apps.getServiceAccessToken(await oauth2Apps.get(id), client), 'metadata-token-cache');
        assert.equal(metadata.tokenRequests, before + 1);

        const stored = await oauth2Apps.get(id);
        assert.ok(new Date(stored.accessTokenExpires).getTime() > Date.now() + 3500 * 1000, 'expiry taken from expires_in');

        // a second caller is served from the record, not from the metadata server
        assert.equal(await oauth2Apps.getServiceAccessToken(stored, client), 'metadata-token-cache');
        assert.equal(metadata.tokenRequests, before + 1);

        // what the Pub/Sub puller does after a 401: drop the cached token and fetch a new one
        await oauth2Apps.invalidateServiceAccessToken(id);
        metadata.token = 'metadata-token-renewed';
        assert.equal(await oauth2Apps.getServiceAccessToken(await oauth2Apps.get(id), client), 'metadata-token-renewed');
        assert.equal(metadata.tokenRequests, before + 2);
    });

    await t.test('keeps its method on an update that does not name one', async () => {
        // The admin form's update schema defaults an omitted authMethod to serviceKey; unpinned,
        // renaming the app turned it into a key-signed app with no key, and the puller died
        const id = await createMetadataApp();

        await oauth2Apps.update(id, { name: 'Renamed', authMethod: 'serviceKey' });
        await oauth2Apps.update(id, { name: 'Renamed again' });

        const stored = await oauth2Apps.get(id);
        assert.equal(stored.name, 'Renamed again');
        assert.equal(stored.authMethod, 'metadataServer');
        assert.equal((await oauth2Apps.getClient(id)).authMethod, 'metadataServer');
    });

    await t.test('does not store a credential sent to it on update', async () => {
        const id = await createMetadataApp();

        await oauth2Apps.update(id, { serviceKey: '-----BEGIN PRIVATE KEY-----\nabc', externalAccount: '{"type":"external_account"}' });

        const stored = await oauth2Apps.get(id);
        assert.equal(stored.serviceKey, undefined);
        assert.equal(stored.externalAccount, undefined);
    });

    await t.test('a key-signed app keeps its method and does not take on another credential', async () => {
        const id = await createApp({
            provider: 'gmailService',
            name: 'Key app',
            enabled: true,
            baseScopes: 'pubsub',
            serviceClient: '1234567890',
            serviceClientEmail: 'key-app@proj.iam.gserviceaccount.com',
            serviceKey: '-----BEGIN PRIVATE KEY-----\nkey'
        });

        await oauth2Apps.update(id, { authMethod: 'metadataServer', externalAccount: '{"type":"external_account"}' });

        const stored = await oauth2Apps.get(id);
        assert.equal(stored.authMethod, 'serviceKey');
        assert.ok(stored.serviceKey, 'the key it has stays');
        assert.equal(stored.externalAccount, undefined);
    });

    await t.test('isAuthMethodLocked() holds for every saved gmailService app', () => {
        assert.equal(isAuthMethodLocked({ provider: 'gmailService', authMethod: 'metadataServer' }), true);
        assert.equal(isAuthMethodLocked({ provider: 'gmailService', serviceKey: 'x' }), true);
        assert.equal(isAuthMethodLocked({ provider: 'gmail' }), false);
        assert.equal(isAuthMethodLocked(null), false);
    });
});

test('verifying an app that uses the attached service account', async t => {
    const stepsById = report => Object.fromEntries(report.steps.map(step => [step.id, step]));

    await t.test('reports the metadata host, the identity and Pub/Sub access', async () => {
        metadata.mode = 'ok';
        pubsubCalls.length = 0;
        pubsubAnswer = async () => ({ topics: [] });
        const id = await createMetadataApp();
        await oauth2Apps.update(id, { googleProjectId: 'proj-meta-1' }, { partial: true });

        const report = await verifyOAuth2App(id);
        const steps = stepsById(report);

        assert.equal(report.ok, true, JSON.stringify(report.steps));
        assert.equal(report.authMethod, 'metadataServer');
        assert.deepEqual(
            report.steps.map(step => step.id),
            ['config', 'token', 'pubsub']
        );
        assert.match(steps.config.message, new RegExp(`127\\.0\\.0\\.1:${metadataServer.address().port}`));
        assert.match(steps.token.message, new RegExp(SERVICE_ACCOUNT_EMAIL.replace(/\./g, '\\.')));
        assert.equal(pubsubCalls.length, 1);
        assert.equal(pubsubCalls[0].url, `https://pubsub.googleapis.com/v1/projects/proj-meta-1/topics/ee-pub-${id}`);
        assert.equal(pubsubCalls[0].method, 'get');
    });

    await t.test('names a missing service account', async () => {
        metadata.mode = 'no-service-account';
        try {
            const id = await createMetadataApp();
            const report = await verifyOAuth2App(id);
            const steps = stepsById(report);

            assert.equal(report.ok, false);
            assert.equal(steps.token.status, 'fail');
            assert.match(steps.token.hint, /No service account is attached/);
            assert.equal(steps.pubsub, undefined, 'nothing to probe without a token');
        } finally {
            metadata.mode = 'ok';
        }
    });

    await t.test('tells a missing access scope from a missing role', async () => {
        const id = await createMetadataApp();
        await oauth2Apps.update(id, { googleProjectId: 'proj-meta-1' }, { partial: true });

        pubsubAnswer = async () => {
            throw apiError(403, 'Request had insufficient authentication scopes.');
        };
        let steps = stepsById(await verifyOAuth2App(id));
        assert.equal(steps.pubsub.status, 'fail');
        assert.match(steps.pubsub.message, /insufficient authentication scopes/);
        assert.match(steps.pubsub.hint, /cloud-platform/);

        pubsubAnswer = async () => {
            throw apiError(403, 'User not authorized to perform this action.');
        };
        steps = stepsById(await verifyOAuth2App(id));
        assert.match(steps.pubsub.hint, /Pub\/Sub Admin/);

        pubsubAnswer = async () => ({ topics: [] });
    });

    await t.test("probes the app's own topic, under a custom name too, and reports one that is missing", async () => {
        const id = await createMetadataApp();
        await oauth2Apps.update(id, { googleProjectId: 'proj-meta-1', googleTopicName: 'custom-topic' }, { partial: true });

        pubsubCalls.length = 0;
        pubsubAnswer = async () => {
            throw apiError(404, 'Resource not found (resource=custom-topic).');
        };
        try {
            const steps = stepsById(await verifyOAuth2App(id));
            assert.equal(pubsubCalls[0].url, 'https://pubsub.googleapis.com/v1/projects/proj-meta-1/topics/custom-topic');
            assert.equal(steps.pubsub.status, 'fail');
            assert.match(steps.pubsub.hint, /topic does not exist/);
        } finally {
            pubsubAnswer = async () => ({ topics: [] });
        }
    });

    await t.test('skips the Pub/Sub probe when no project is set', async () => {
        const id = await createMetadataApp();
        const steps = stepsById(await verifyOAuth2App(id));
        assert.equal(steps.token.status, 'ok');
        assert.equal(steps.pubsub.status, 'skip');
    });

    await t.test('every metadata failure has its own hint', () => {
        const { metadataServerHint } = verifyTest;
        const hints = [
            metadataServerHint({ code: 'EMetadataConfig' }),
            metadataServerHint({ code: 'EMetadataUnreachable' }),
            metadataServerHint({ code: 'EMetadataServer', wrongFlavor: true }),
            metadataServerHint({ code: 'EMetadataServer', statusCode: 404 }),
            metadataServerHint({ code: 'EMetadataServer', statusCode: 403 }),
            metadataServerHint({ code: 'EMetadataServer', statusCode: 500 }),
            metadataServerHint({ code: 'EMetadataResponse' })
        ];
        assert.equal(new Set(hints).size, hints.length);
        assert.match(hints[0], /EENGINE_GCP_METADATA_HOST/);
        assert.match(hints[1], /not running on Google Cloud/);
    });
});

test('the Pub/Sub probe runs for the signing methods too', async () => {
    pubsubCalls.length = 0;
    const id = await createApp({
        provider: 'gmailService',
        name: 'Key app verify',
        enabled: true,
        baseScopes: 'pubsub',
        serviceClient: '1234567890',
        serviceClientEmail: 'key-app@proj.iam.gserviceaccount.com',
        serviceKey: '-----BEGIN PRIVATE KEY-----\nkey'
    });
    await oauth2Apps.update(id, { googleProjectId: 'proj-key-1' }, { partial: true });

    // Stand in for the token endpoint: what matters is that a token leads on to the probe
    const originalRefresh = GmailOauth.prototype.refreshToken;
    const originalGenerate = GmailOauth.prototype.generateServiceRequest;
    GmailOauth.prototype.generateServiceRequest = async () => ({ payload: {} });
    GmailOauth.prototype.refreshToken = async () => ({ access_token: 'jwt-bearer-token', expires_in: 3600 });
    try {
        const report = await verifyOAuth2App(id);
        assert.deepEqual(
            report.steps.map(step => [step.id, step.status]),
            [
                ['config', 'ok'],
                ['sign', 'ok'],
                ['token', 'ok'],
                ['pubsub', 'ok']
            ]
        );
        assert.equal(pubsubCalls.length, 1);
        assert.equal(pubsubCalls[0].accessToken, 'jwt-bearer-token');
    } finally {
        GmailOauth.prototype.refreshToken = originalRefresh;
        GmailOauth.prototype.generateServiceRequest = originalGenerate;
    }
});

test('the schemas keep the attached service account to Pub/Sub apps', async t => {
    const create = Joi.object(oauthCreateSchema).tailor('api');
    const validate = payload => create.validate(payload, { abortEarly: false, stripUnknown: true });
    const base = { provider: 'gmailService', name: 'x', authMethod: 'metadataServer' };

    await t.test('a Pub/Sub app needs no service account fields or credential', () => {
        // a credential sent anyway passes here and is dropped by the storage layer, see above
        const { error, value } = validate({ ...base, baseScopes: 'pubsub', googleProjectId: 'proj-meta-1' });
        assert.equal(error, undefined);
        assert.equal(value.authMethod, 'metadataServer');
    });

    await t.test('any other app is refused with one error that gives the reason', () => {
        for (const baseScopes of ['imap', 'api', undefined]) {
            const { error } = validate({ ...base, baseScopes });
            assert.ok(error, String(baseScopes));
            assert.equal(error.details.length, 1, error.message);
            assert.match(error.message, /only available to a Cloud Pub\/Sub application/);
        }
        const { error } = validate({
            provider: 'gmail',
            name: 'x',
            authMethod: 'metadataServer',
            clientId: 'a',
            clientSecret: 'b',
            redirectUrl: 'https://x.test/oauth'
        });
        assert.ok(error, 'not for the interactive provider either');
    });

    await t.test('the other methods still need their credentials', () => {
        const { error } = validate({ provider: 'gmailService', name: 'x', baseScopes: 'pubsub', serviceClient: '1', serviceClientEmail: 'a@b.com' });
        assert.match(error.message, /"serviceKey" is required/);
    });

    await t.test('the edit form may omit the service account fields for this method only', () => {
        const update = Joi.object(oauthUpdateSchema);
        const form = { app: 'a', provider: 'gmailService', name: 'x', extraScopes: '', skipScopes: '' };
        assert.equal(update.validate({ ...form, authMethod: 'metadataServer' }).error, undefined);
        assert.match(update.validate({ ...form, authMethod: 'serviceKey' }).error.message, /"serviceClient" is required/);
    });
});
