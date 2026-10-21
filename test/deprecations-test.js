'use strict';

// lib/deprecations.js: the announcement of the pre-2.79 token endpoints and of the legacy SMTP
// server options, both removed after REMOVAL_DATE.

const test = require('node:test');
const assert = require('node:assert').strict;
const Hapi = require('@hapi/hapi');
const Boom = require('@hapi/boom');

const {
    REMOVAL_DATE,
    SUNSET_HTTP_DATE,
    TOKEN_ROUTES_DEPRECATED_AT,
    LOG_INTERVAL,
    deprecationHeaders,
    deprecationExt,
    legacySmtpOptionsInUse
} = require('../lib/deprecations');
const { createMockLogger } = require('./helpers/mock-logger');
const { redis } = require('../lib/db');
const registerRedisTeardown = require('./helpers/redis-teardown');

registerRedisTeardown(redis);

test('deprecationHeaders', async t => {
    await t.test('announces the deprecation, the removal date and the successor', () => {
        assert.strictEqual(REMOVAL_DATE, '2027-01-01');
        assert.strictEqual(SUNSET_HTTP_DATE, 'Fri, 01 Jan 2027 00:00:00 GMT');
        assert.deepStrictEqual(deprecationHeaders(Date.parse('2026-08-18T07:47:01Z'), '/v1/tokens'), {
            Deprecation: '@1787039221',
            Sunset: 'Fri, 01 Jan 2027 00:00:00 GMT',
            Link: '</v1/tokens>; rel="successor-version"'
        });
    });

    await t.test('leaves the Link out when there is no plain successor path', () => {
        assert.ok(!('Link' in deprecationHeaders(TOKEN_ROUTES_DEPRECATED_AT)));
    });
});

test('deprecationExt on a real Hapi server', async t => {
    const logger = createMockLogger();
    let clock = 1000;
    const server = Hapi.server();
    server.ext('onPreResponse', deprecationExt({ logger, now: () => clock }));

    const handler = request => {
        if (request.params.fail) {
            throw Boom.notFound('gone');
        }
        return { ok: true };
    };
    server.route({
        method: 'GET',
        path: '/old/{fail?}',
        handler,
        options: { plugins: { deprecation: { since: TOKEN_ROUTES_DEPRECATED_AT, successor: 'GET /new', link: '/new' } } }
    });
    server.route({ method: 'GET', path: '/other', handler, options: { plugins: { deprecation: { since: TOKEN_ROUTES_DEPRECATED_AT, successor: 'GET /x' } } } });
    server.route({ method: 'GET', path: '/current', handler });
    await server.initialize();

    await t.test('stamps a successful response', async () => {
        const res = await server.inject('/old');
        assert.strictEqual(res.statusCode, 200);
        assert.strictEqual(res.headers.sunset, SUNSET_HTTP_DATE);
        assert.strictEqual(res.headers.deprecation, `@${Math.floor(TOKEN_ROUTES_DEPRECATED_AT / 1000)}`);
        assert.strictEqual(res.headers.link, '</new>; rel="successor-version"');
    });

    await t.test('stamps an error response too', async () => {
        const res = await server.inject('/old/yes');
        assert.strictEqual(res.statusCode, 404);
        assert.strictEqual(res.headers.sunset, SUNSET_HTTP_DATE);
    });

    await t.test('leaves a route that declares nothing alone', async () => {
        const res = await server.inject('/current');
        assert.strictEqual(res.headers.sunset, undefined);
        assert.strictEqual(res.headers.deprecation, undefined);
    });

    await t.test('logs each endpoint at most once an hour', async () => {
        const warned = () => logger.entries.filter(e => e.msg === 'Deprecated API endpoint called');
        assert.strictEqual(warned().length, 1, 'two calls within the hour, one entry');
        assert.deepStrictEqual(
            { method: warned()[0].method, path: warned()[0].path, successor: warned()[0].successor, removal: warned()[0].removal },
            { method: 'GET', path: '/old/{fail?}', successor: 'GET /new', removal: REMOVAL_DATE }
        );

        // another endpoint has its own interval
        await server.inject('/other');
        assert.strictEqual(warned().length, 2);

        clock += LOG_INTERVAL;
        await server.inject('/old');
        assert.strictEqual(warned().length, 3);
    });

    await t.test('logs the token id, never a credential', () => {
        const recorder = createMockLogger();
        const proceed = Symbol('continue');
        const request = {
            method: 'post',
            route: { path: '/v1/token', settings: { plugins: { deprecation: { since: 0, successor: 'POST /v1/tokens' } } } },
            response: { headers: {} },
            auth: { credentials: { token: 'a'.repeat(64) }, artifacts: { id: 'hashed-id' } }
        };
        assert.strictEqual(deprecationExt({ logger: recorder })(request, { continue: proceed }), proceed);
        assert.strictEqual(recorder.entries[0].token, 'hashed-id');
        assert.ok(!JSON.stringify(recorder.entries[0]).includes('a'.repeat(64)));
    });
});

test('the pre-2.79 token endpoints declare their deprecation and the current ones do not', async () => {
    const routes = [];
    await require('../lib/api-routes/token-routes')({ server: { route: cfg => routes.push(cfg) }, call: async () => ({}), CORS_CONFIG: false });

    const declared = routes.filter(r => r.options.plugins && r.options.plugins.deprecation);
    assert.deepStrictEqual(declared.map(r => `${r.method} ${r.path}`).sort(), [
        'DELETE /v1/token/{token}',
        'GET /v1/tokens/account/{account}',
        'POST /v1/token'
    ]);
    for (const route of declared) {
        assert.strictEqual(route.options.plugins.deprecation.since, TOKEN_ROUTES_DEPRECATED_AT);
        // the same routes the published document leaves out
        assert.strictEqual(route.options.plugins.openapi.deprecated, true, route.path);
        assert.ok(route.options.notes.includes(`removed after ${REMOVAL_DATE}`), route.path);
    }
});

test('legacySmtpOptionsInUse', async t => {
    const defaults = { enabled: false, port: 2525, host: '127.0.0.1', secret: '', proxy: false, maxClients: 50 };
    const noEnv = () => false;

    await t.test('reports nothing for the shipped defaults, whatever the current [smtp] keys hold', () => {
        assert.deepStrictEqual(legacySmtpOptionsInUse({ hasEnvValue: noEnv, smtpConfig: defaults }), []);
        assert.deepStrictEqual(legacySmtpOptionsInUse({ hasEnvValue: noEnv }), []);
    });

    await t.test('reports the legacy environment variables, not the current EENGINE_SMTP_TLS_* ones', () => {
        const env = new Set(['EENGINE_SMTP_ENABLED', 'EENGINE_SMTP_PORT', 'EENGINE_SMTP_TLS_CERT']);
        assert.deepStrictEqual(legacySmtpOptionsInUse({ hasEnvValue: name => env.has(name), smtpConfig: defaults }), [
            'EENGINE_SMTP_ENABLED',
            'EENGINE_SMTP_PORT'
        ]);
    });

    await t.test('reports [smtp] keys changed from their defaults, comparing command line strings by value', () => {
        assert.deepStrictEqual(
            legacySmtpOptionsInUse({ hasEnvValue: noEnv, smtpConfig: Object.assign({}, defaults, { enabled: true, secret: 'pw', port: '2525' }) }),
            ['[smtp] enabled', '[smtp] secret']
        );
    });
});

test('deprecated request fields', async t => {
    const { DEPRECATED_FIELDS, createFieldReporter, deprecatedField, setFieldReporter, BULL_BOARD_REDIRECTS_DEPRECATED_AT } = require('../lib/deprecations');
    const schemas = require('../lib/schemas');

    await t.test('a field is reported once an hour, each field on its own clock', () => {
        const logger = createMockLogger();
        let clock = 0;
        const report = createFieldReporter({ getLogger: () => logger, now: () => clock });

        report('syncFrom');
        report('syncFrom');
        report('documentStore');
        assert.deepStrictEqual(
            logger.entries.map(entry => entry.field),
            ['syncFrom', 'documentStore']
        );
        assert.strictEqual(logger.entries[0].msg, 'Deprecated request field used');
        assert.strictEqual(logger.entries[0].removal, REMOVAL_DATE);
        assert.strictEqual(logger.entries[0].successor, DEPRECATED_FIELDS.syncFrom);

        clock += LOG_INTERVAL;
        report('syncFrom');
        assert.strictEqual(logger.entries.length, 3);
    });

    await t.test('only a known field can be marked', () => {
        assert.throws(() => deprecatedField('somethingElse'), /not a deprecated field/);
    });

    await t.test('every listed field is marked on a schema, and reported when a request carries it', async t => {
        const reported = [];
        const previous = setFieldReporter(field => reported.push(field));
        t.after(() => setFieldReporter(previous));

        const oauth2AppRoutes = [];
        const { buildMockArgs } = require('./helpers/capture-api-routes');
        await require('../lib/api-routes/oauth2-app-routes')(buildMockArgs({ route: cfg => oauth2AppRoutes.push(cfg) }));
        const appUpdate = oauth2AppRoutes.find(route => route.method === 'PUT' && route.path === '/v1/oauth2/{app}').options.validate.payload;

        const cases = [
            ['documentStore', () => schemas.documentStoreSchema.validate(true)],
            ['syncFrom', () => schemas.accountSchemas.syncFrom.validate('2026-01-01')],
            ['documentStoreEnabled', () => schemas.settingsSchema.documentStoreEnabled.validate(true)],
            ['generateRiskAssessment', () => schemas.settingsSchema.generateRiskAssessment.validate(true)],
            ['openAiGenerateEmbeddings', () => schemas.settingsSchema.openAiGenerateEmbeddings.validate(true)],
            ['trackSentMessages', () => schemas.settingsSchema.trackSentMessages.validate(true)],
            ['oauth2.authority', () => schemas.oauth2Schema.authority.validate('consumers')],
            ['oauth2.authority', () => schemas.oauth2UpdateSchema.authority.validate('consumers')],
            ['tenant', () => appUpdate.extract('tenant').validate('f8cdef31-a31e-4b4a-93e4-5f571e91255a')]
        ];
        for (const [field, run] of cases) {
            reported.length = 0;
            const { error } = run();
            assert.ifError(error);
            assert.deepStrictEqual(reported, [field], field);
        }
        assert.deepStrictEqual([...new Set(cases.map(([field]) => field))].sort(), Object.keys(DEPRECATED_FIELDS).sort(), 'every listed field has a case');

        // A value that is not there is not a use: absent, or an empty form field
        reported.length = 0;
        schemas.oauth2Schema.authority.validate('');
        schemas.settingsSchema.trackSentMessages.validate(undefined);
        assert.deepStrictEqual(reported, []);
    });

    await t.test('the bull-board redirects announce their removal', () => {
        const { captureRouteConfigs } = require('./helpers/capture-ui-routes');
        const declared = captureRouteConfigs().filter(route => route.options && route.options.plugins && route.options.plugins.deprecation);
        assert.deepStrictEqual(declared.map(route => `${route.method} ${route.path}`).sort(), ['GET /admin/bull-board', 'GET /admin/bull-board/{path*}']);
        for (const route of declared) {
            assert.strictEqual(route.options.plugins.deprecation.since, BULL_BOARD_REDIRECTS_DEPRECATED_AT);
            assert.strictEqual(route.options.plugins.deprecation.link, '/admin/queues');
        }
    });
});
