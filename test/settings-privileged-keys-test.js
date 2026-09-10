'use strict';

// The privileged-settings rule (assertNoPrivilegedSettings in lib/api-routes/route-helpers.js),
// driven through the real POST /v1/settings route on a bare Hapi server. `write/settings` is a
// grantable permission since the admin group was split, and the settings blob is the one endpoint
// whose fields span every trust level, so a narrowed credential is refused the keys that would
// make it more than a settings editor - and refused whole, so nothing is half-applied.
//
// The route module is registered with stand-ins for what workers/api.js provides around it: an
// `api-token` strategy that reads the token record off a test header, and no-op notify/call
// helpers. Settings, Redis and the permission model are the real thing.

const test = require('node:test');
const assert = require('node:assert').strict;

const Hapi = require('@hapi/hapi');

const { redis } = require('../lib/db');
const registerRedisTeardown = require('./helpers/redis-teardown');
const { captureApiRoutes } = require('./helpers/capture-api-routes');
const { buildToolRegistry } = require('../lib/mcp/tools');
const settings = require('../lib/settings');
const { settingsSchema } = require('../lib/schemas');
const settingsRoutes = require('../lib/api-routes/settings-routes');

registerRedisTeardown(redis, () => Promise.all(['pageBrandName', 'sentryEnabled'].map(key => settings.set(key, null))));

const NARROWED = { permissions: { grants: [{ action: 'write', group: 'settings' }] } };
const UNNARROWED = {};

let server;

async function post(payload, tokenData, extraHeaders) {
    return server.inject({
        method: 'POST',
        url: '/v1/settings',
        payload,
        headers: Object.assign({ 'x-test-token': JSON.stringify(tokenData) }, extraHeaders || {})
    });
}

test('privileged settings keys', async t => {
    t.before(async () => {
        server = Hapi.server({});

        server.auth.scheme('test-token', () => ({
            authenticate(request, h) {
                const tokenData = JSON.parse(request.headers['x-test-token'] || '{}');
                if (request.headers['x-test-session']) {
                    // What the api-token strategy sets for a browse-page session credential
                    request.app.sessionToken = true;
                }
                return h.authenticated({ credentials: { token: 'test' }, artifacts: tokenData });
            }
        }));
        server.auth.strategy('api-token', 'test-token');

        server.ext('onRequest', (request, h) => {
            request.logger = { info() {}, error() {}, debug() {}, warn() {}, child: () => request.logger };
            return h.continue;
        });

        await settingsRoutes({ server, call: async () => ({}), notify: () => {}, CORS_CONFIG: false });
        await server.initialize();
    });

    await t.test('every privileged key is a settings key, so a renamed setting cannot fall out of the rule', () => {
        const unknown = settings.privilegedKeys.filter(key => !Object.hasOwn(settingsSchema, key));
        assert.deepEqual(unknown, [], `privileged keys that the settings schema does not declare: ${JSON.stringify(unknown)}`);

        // The list is not vacuous, and the keys that motivate it are on it
        for (const key of ['openAiPreProcessingFn', 'scriptEnv', 'serviceSecret', 'proxyUrl', 'enableApiProxy', 'mcpOAuthEnabled', 'tokenAuditLog']) {
            assert.ok(settings.privilegedKeys.includes(key), `${key} must be privileged`);
        }

        // Every whole secret is privileged too - the privileged list is wider than the secrets, but
        // it must not be narrower
        for (const key of settings.secretKeys.filter(key => Object.hasOwn(settingsSchema, key))) {
            assert.ok(settings.privilegedKeys.includes(key), `secret ${key} must be privileged`);
        }

        // Every setting of the built-in listeners: a credential that could switch authentication
        // off on the SMTP server would send as any account with no credential at all, and one
        // that could move a listener onto a public interface or off TLS is not a settings editor
        for (const key of Object.keys(settingsSchema).filter(key => /^(smtpServer|imapProxyServer)/.test(key))) {
            assert.ok(settings.privilegedKeys.includes(key), `listener setting ${key} must be privileged`);
        }

        // Every URL a stored secret is sent to, beside the secret itself
        for (const key of ['openAiAPIUrl', 'authServer', 'proxyUrl', 'httpProxyUrl', 'documentStoreUrl']) {
            assert.ok(settings.privilegedKeys.includes(key), `${key} names where a stored secret is sent, so it must be privileged`);
        }
    });

    await t.test('the MCP settings tools offer exactly the keys the REST rule allows', async () => {
        // The two rules are one policy on two surfaces: what update_settings puts in front of an
        // agent has to be what a narrowed token may write, and get_settings reads the same set
        // (plus the virtual eventTypes). Derived from the real route table, like the registry
        // itself, so a key hidden from the schema converter shows up here rather than as a build
        // failure on the next setting someone adds.
        const { routes } = await captureApiRoutes();
        const { byName } = buildToolRegistry(routes);

        const hidden = key => (settingsSchema[key].describe().metas || []).some(meta => meta && meta.swaggerHidden);
        const expected = Object.keys(settingsSchema)
            .filter(key => !settings.privilegedKeys.includes(key) && !hidden(key))
            .sort();

        assert.deepEqual(Object.keys(byName.get('update_settings').definition.inputSchema.properties).sort(), expected);
        assert.deepEqual(Object.keys(byName.get('get_settings').definition.inputSchema.properties).sort(), expected.concat('eventTypes').sort());
    });

    await t.test('a narrowed token is refused reading a privileged key, and the ordinary ones still read', async () => {
        // The read side of the same rule: several of the keys are secrets by the project's own
        // definition (scriptEnv is where the admin UI tells operators to keep API keys), and the
        // write guard alone left a read/settings grant able to fetch them
        const get = (query, tokenData) =>
            server.inject({ method: 'GET', url: `/v1/settings?${query}`, headers: { 'x-test-token': JSON.stringify(tokenData) } });

        const refused = await get('scriptEnv=true&pageBrandName=true', { permissions: { grants: [{ action: 'read', group: 'settings' }] } });
        assert.equal(refused.statusCode, 403);
        assert.match(refused.result.message, /can not read scriptEnv/);

        const allowed = await get('pageBrandName=true&scriptEnv=false', { permissions: { grants: [{ action: 'read', group: 'settings' }] } });
        assert.equal(allowed.statusCode, 200);
        assert.ok(Object.hasOwn(allowed.result, 'pageBrandName'));
        assert.ok(!Object.hasOwn(allowed.result, 'scriptEnv'), 'a flag set to false asks for nothing, so it is not a refusal either');

        const unnarrowed = await get('scriptEnv=true', UNNARROWED);
        assert.equal(unnarrowed.statusCode, 200);
    });

    await t.test('a narrowed token is refused a privileged key, and told which one', async () => {
        const res = await post({ openAiPreProcessingFn: 'return true' }, NARROWED);
        assert.equal(res.statusCode, 403);
        assert.match(res.result.message, /openAiPreProcessingFn/);
    });

    await t.test('a refused payload writes nothing, not even its harmless keys', async () => {
        await settings.set('pageBrandName', 'before');

        const res = await post({ pageBrandName: 'after', mcpEnabled: true }, NARROWED);
        assert.equal(res.statusCode, 403);
        assert.match(res.result.message, /mcpEnabled/);

        assert.equal(await settings.get('pageBrandName'), 'before');
    });

    await t.test('a narrowed token may still write the ordinary keys', async () => {
        const res = await post({ pageBrandName: 'narrowed write' }, NARROWED);
        assert.equal(res.statusCode, 200);
        assert.deepEqual(res.result.updated, ['pageBrandName']);
        assert.equal(await settings.get('pageBrandName'), 'narrowed write');
    });

    await t.test('a browse-page session token is refused like a narrowed one', async () => {
        const res = await post({ sentryEnabled: false }, UNNARROWED, { 'x-test-session': '1' });
        assert.equal(res.statusCode, 403);
    });

    await t.test('an unnarrowed token is not affected', async () => {
        const res = await post({ sentryEnabled: false }, UNNARROWED);
        assert.equal(res.statusCode, 200);
        assert.deepEqual(res.result.updated, ['sentryEnabled']);
    });

    await t.test('an unreadable record is refused, not read as unnarrowed', async () => {
        // The same direction the permission check fails in: a record this version cannot read
        // grants nothing, so it certainly does not grant the privileged keys
        const res = await post({ sentryEnabled: false }, { permissions: { nonsense: true } });
        assert.equal(res.statusCode, 403);
    });
});
