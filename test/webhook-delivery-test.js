'use strict';

// Unit tests for lib/webhook-delivery.js, the notify queue's job processor. It used to be inline in
// workers/webhooks.js, where no test could reach it; every side effect is injected, so these run
// against in-memory fakes. Requiring the module still loads lib/tools, hence the Redis teardown.

const test = require('node:test');
const assert = require('node:assert').strict;
const { createHmac } = require('crypto');
const { DelayedError, UnrecoverableError } = require('bullmq');

const { createWebhookProcessor, filterLogData } = require('../lib/webhook-delivery');
const { penaltyKey } = require('../lib/webhook-penalty');
const { REDIS_PREFIX } = require('../lib/consts');
const { redis } = require('../lib/db');
const registerRedisTeardown = require('./helpers/redis-teardown');
const { createMockLogger } = require('./helpers/mock-logger');

registerRedisTeardown(redis);

const SECRET = 'test-service-secret';
const ACCOUNT_KEY = `${REDIS_PREFIX}iad:acc1`;
const CONTENT_KEY = 'webhooks:content';

function makeDeps(opts) {
    opts = opts || {};
    const state = {
        hashes: new Map(),
        pttl: opts.pttl || -2,
        sets: [],
        settingsWrites: [],
        settingsCleared: [],
        metrics: [],
        requests: []
    };
    const logger = createMockLogger();
    state.logs = logger.entries;

    state.hashes.set(
        ACCOUNT_KEY,
        new Map(
            Object.entries(
                Object.assign({ account: 'acc1' }, opts.account === null ? { account: null } : {}, {
                    webhooks: opts.accountWebhooks || null,
                    webhooksCustomHeaders: opts.accountHeaders ? JSON.stringify(opts.accountHeaders) : opts.accountHeadersRaw || null
                })
            )
        )
    );

    const settingsValues = Object.assign(
        {
            webhooksEnabled: true,
            webhooks: 'https://user:secret@global.example.com/hook',
            webhookEvents: ['*'],
            inboxNewOnly: false,
            webhooksCustomHeaders: [{ key: 'X-Global', value: 'g' }]
        },
        opts.settings
    );

    const deps = {
        redis: {
            async hmget(key, ...fields) {
                let hash = state.hashes.get(key) || new Map();
                return fields.map(f => (hash.has(f) ? hash.get(f) : null));
            },
            async pttl() {
                return state.pttl;
            },
            async set(...args) {
                state.sets.push(args);
                return 'OK';
            },
            async hset(key, field, value) {
                if (!state.hashes.has(key)) {
                    state.hashes.set(key, new Map());
                }
                state.hashes.get(key).set(field, value);
                return 1;
            }
        },
        settings: {
            async get(key) {
                return settingsValues[key];
            },
            async getMulti(...keys) {
                return Object.fromEntries(keys.map(k => [k, settingsValues[k]]));
            },
            async set(key, value) {
                state.settingsWrites.push([key, value]);
            },
            async clear(key) {
                state.settingsCleared.push(key);
            }
        },
        webhooks: {
            async getMeta(id) {
                return (opts.routes || {})[id] || null;
            },
            getWebhooksContentKey: () => CONTENT_KEY
        },
        logger,
        metrics: (...args) => state.metrics.push(args),
        openAccountField: async (field, value) => value,
        getServiceSecret: async () => SECRET,
        fetch: async (url, fetchOpts) => {
            state.requests.push({ url, opts: fetchOpts });
            if (opts.fetchError) {
                throw opts.fetchError;
            }
            return new Response('ok', { status: opts.status || 200 });
        },
        timeout: 30000
    };
    if (opts.validateTarget) {
        deps.validateTarget = opts.validateTarget;
    }

    return { deps, state };
}

function makeJob(overrides) {
    overrides = overrides || {};
    const job = {
        id: '42',
        name: overrides.name || 'messageNew',
        queue: { name: 'notify' },
        attemptsMade: overrides.attemptsMade || 0,
        opts: { attempts: overrides.attempts || 10 },
        timestamp: Date.now() - 2000,
        data: Object.assign(
            {
                account: 'acc1',
                path: 'INBOX',
                event: overrides.name || 'messageNew',
                data: { id: 'AAA', uid: 1, subject: 'hello', text: { plain: 'secret body' } }
            },
            overrides.data
        ),
        progress: [],
        delayedUntil: null,
        async updateProgress(value) {
            this.progress.push(value);
        },
        async moveToDelayed(ts, token) {
            this.delayedUntil = ts;
            this.delayToken = token;
        }
    };
    return job;
}

const headerOf = (state, name) => state.requests[0].opts.headers[name];

test('webhook delivery: what is skipped', async t => {
    await t.test('completes without sending when the account no longer exists', async () => {
        const { deps, state } = makeDeps({ account: null });
        const result = await createWebhookProcessor(deps)(makeJob());
        assert.strictEqual(result, undefined);
        assert.strictEqual(state.requests.length, 0);
        assert.ok(state.logs.some(l => l.code === 'account_not_found'));
    });

    await t.test('still delivers accountDeleted for a removed account', async () => {
        const { deps, state } = makeDeps({ account: null });
        const result = await createWebhookProcessor(deps)(makeJob({ name: 'accountDeleted' }));
        assert.strictEqual(result.status, 'delivered');
        assert.strictEqual(state.requests.length, 1);
    });

    await t.test('completes without sending when webhooks are disabled', async () => {
        const { deps, state } = makeDeps({ settings: { webhooksEnabled: false } });
        assert.strictEqual(await createWebhookProcessor(deps)(makeJob()), undefined);
        assert.strictEqual(state.requests.length, 0);
        assert.ok(state.logs.some(l => l.code === 'webhooks_disabled'));
    });

    await t.test('completes without sending when no target is configured', async () => {
        const { deps, state } = makeDeps({ settings: { webhooks: '' } });
        assert.strictEqual(await createWebhookProcessor(deps)(makeJob()), undefined);
        assert.strictEqual(state.requests.length, 0);
        assert.ok(state.logs.some(l => l.code === 'no_target_url'));
    });

    await t.test('drops a custom route job whose route is disabled, but keeps its id for the event handlers', async () => {
        const { deps, state } = makeDeps({ routes: { r1: { id: 'r1', enabled: false, targetUrl: 'https://route.example.com/' } } });
        const job = makeJob({ data: { _route: { id: 'r1' } } });
        assert.strictEqual(await createWebhookProcessor(deps)(job), undefined);
        assert.strictEqual(state.requests.length, 0);
        assert.strictEqual(job.__routeId, 'r1');
        assert.ok(!('_route' in job.data));
    });

    await t.test('drops a custom route job queued with a failed mapping instead of sending the raw payload', async () => {
        const { deps, state } = makeDeps({ routes: { r1: { id: 'r1', enabled: true, targetUrl: 'https://route.example.com/' } } });
        const job = makeJob({ data: { _route: { id: 'r1', mapping: null } } });
        assert.strictEqual(await createWebhookProcessor(deps)(job), undefined);
        assert.strictEqual(state.requests.length, 0);
        assert.ok(state.logs.some(l => l.level === 'warn' && l.code === 'missing_mapping'));
    });

    await t.test('the default route follows webhookEvents', async () => {
        const { deps, state } = makeDeps({ settings: { webhookEvents: ['messageDeleted'] } });
        assert.strictEqual(await createWebhookProcessor(deps)(makeJob()), undefined);
        assert.strictEqual(state.requests.length, 0);
        assert.ok(state.logs.some(l => l.code === 'event_not_whitelisted'));
    });

    await t.test('the default route follows inboxNewOnly', async () => {
        const { deps, state } = makeDeps({ settings: { inboxNewOnly: true } });
        const job = makeJob({ data: { path: 'Archive' } });
        assert.strictEqual(await createWebhookProcessor(deps)(job), undefined);
        assert.strictEqual(state.requests.length, 0);
        assert.ok(state.logs.some(l => l.code === 'inbox_new_only'));
    });

    await t.test('a custom route ignores webhookEvents', async () => {
        const { deps, state } = makeDeps({
            settings: { webhookEvents: [] },
            routes: { r1: { id: 'r1', enabled: true, targetUrl: 'https://route.example.com/' } }
        });
        const result = await createWebhookProcessor(deps)(makeJob({ data: { _route: { id: 'r1', mapping: { mapped: true } } } }));
        assert.strictEqual(result.status, 'delivered');
        assert.strictEqual(state.requests.length, 1);
    });

    await t.test('waits out a penalised target in the delayed set without sending', async () => {
        const { deps, state } = makeDeps({ pttl: 5000 });
        const job = makeJob();
        const before = Date.now();
        await assert.rejects(createWebhookProcessor(deps)(job, 'lock-token'), DelayedError);
        assert.strictEqual(state.requests.length, 0);
        assert.ok(job.delayedUntil >= before + 5000);
        assert.strictEqual(job.delayToken, 'lock-token');
    });
});

test('webhook delivery: the request', async t => {
    await t.test('signs the body and strips the URL credentials into an Authorization header', async () => {
        const { deps, state } = makeDeps();
        const job = makeJob({ attemptsMade: 3 });
        const result = await createWebhookProcessor(deps)(job);

        assert.strictEqual(result.status, 'delivered');
        assert.strictEqual(result.statusCode, 200);
        assert.strictEqual(typeof result.duration, 'number');

        const { url, opts } = state.requests[0];
        assert.strictEqual(url, 'https://global.example.com/hook');
        assert.strictEqual(opts.method, 'post');
        assert.strictEqual(opts.headers.Authorization, `Basic ${Buffer.from('user:secret').toString('base64')}`);
        assert.strictEqual(opts.headers['X-EE-Wh-Id'], '42');
        assert.strictEqual(opts.headers['X-EE-Wh-Attempts-Made'], '3');
        assert.match(opts.headers['X-EE-Wh-Queued-Time'], /^\d+s$/);
        assert.strictEqual(opts.headers['Content-Length'], String(opts.body.length));
        assert.strictEqual(opts.headers['X-EE-Wh-Signature'], createHmac('sha256', SECRET).update(opts.body).digest('base64url'));
        assert.deepStrictEqual(JSON.parse(opts.body.toString()), job.data);

        // the redacted target stays reachable for the failed-event handler, never the credentials
        assert.ok(!job.__redactedTargetUrl.includes('secret'));
        assert.ok(state.logs.every(l => !JSON.stringify(l).includes('secret body')));
    });

    await t.test('moves the event id into a header and out of the body', async () => {
        const { deps, state } = makeDeps();
        await createWebhookProcessor(deps)(makeJob({ data: { eventId: 'evt-1' } }));
        assert.strictEqual(headerOf(state, 'X-EE-Wh-Event-Id'), 'evt-1');
        assert.ok(!('eventId' in JSON.parse(state.requests[0].opts.body.toString())));
    });

    await t.test('the global target carries the global and the account headers', async () => {
        const { deps, state } = makeDeps({ accountHeaders: [{ key: 'X-Account', value: 'a' }] });
        await createWebhookProcessor(deps)(makeJob());
        assert.strictEqual(headerOf(state, 'X-Global'), 'g');
        assert.strictEqual(headerOf(state, 'X-Account'), 'a');
    });

    await t.test('an account target never carries the global headers', async () => {
        const { deps, state } = makeDeps({ accountWebhooks: 'https://account.example.com/', accountHeaders: [{ key: 'X-Account', value: 'a' }] });
        await createWebhookProcessor(deps)(makeJob());
        assert.strictEqual(state.requests[0].url, 'https://account.example.com/');
        assert.strictEqual(headerOf(state, 'X-Global'), undefined);
        assert.strictEqual(headerOf(state, 'X-Account'), 'a');
    });

    await t.test('an unparseable account header list is ignored', async () => {
        const { deps, state } = makeDeps({ accountHeadersRaw: '{not json' });
        const result = await createWebhookProcessor(deps)(makeJob());
        assert.strictEqual(result.status, 'delivered');
        assert.strictEqual(headerOf(state, 'X-Global'), 'g');
        assert.ok(state.logs.some(l => l.msg === 'Failed to parse custom webhook headers' && !JSON.stringify(l).includes('not json')));
    });

    await t.test('a custom route sends its mapping with its own headers only', async () => {
        const { deps, state } = makeDeps({
            accountHeaders: [{ key: 'X-Account', value: 'a' }],
            routes: { r1: { id: 'r1', enabled: true, targetUrl: 'https://route.example.com/in', customHeaders: [{ key: 'X-Route', value: 'r' }] } }
        });
        await createWebhookProcessor(deps)(makeJob({ data: { _route: { id: 'r1', mapping: { mapped: 1 } } } }));
        assert.strictEqual(state.requests[0].url, 'https://route.example.com/in');
        assert.deepStrictEqual(JSON.parse(state.requests[0].opts.body.toString()), { mapped: 1 });
        assert.strictEqual(headerOf(state, 'X-EE-Wh-Custom-Route'), 'r1');
        assert.strictEqual(headerOf(state, 'X-Route'), 'r');
        assert.strictEqual(headerOf(state, 'X-Global'), undefined);
        assert.strictEqual(headerOf(state, 'X-Account'), undefined);
    });
});

test('webhook delivery: recording the outcome', async t => {
    await t.test('a success clears the global error flag and counts the delivery', async () => {
        const { deps, state } = makeDeps();
        await createWebhookProcessor(deps)(makeJob());
        assert.deepStrictEqual(state.settingsCleared, ['webhookErrorFlag']);
        assert.deepStrictEqual(state.metrics[0], ['webhooks', 'inc', { event: 'messageNew', status: 'success' }]);
        // the request duration is observed only when it is measurable, a fake fetch takes 0ms
        assert.ok(state.metrics.slice(1).every(m => m[0] === 'webhookReq'));
    });

    await t.test('a success clears the flag of the level that decided the target', async () => {
        let { deps, state } = makeDeps({ accountWebhooks: 'https://account.example.com/' });
        await createWebhookProcessor(deps)(makeJob());
        assert.strictEqual(state.hashes.get(ACCOUNT_KEY).get('webhookErrorFlag'), '{}');
        assert.deepStrictEqual(state.settingsCleared, []);

        ({ deps, state } = makeDeps({ routes: { r1: { id: 'r1', enabled: true, targetUrl: 'https://route.example.com/' } } }));
        await createWebhookProcessor(deps)(makeJob({ data: { _route: { id: 'r1', mapping: {} } } }));
        assert.strictEqual(state.hashes.get(CONTENT_KEY).get('r1:webhookErrorFlag'), '{}');
    });

    await t.test('a failed attempt records the reason everywhere it is read back, then rethrows', async () => {
        const { deps, state } = makeDeps({ status: 503 });
        const job = makeJob();
        await assert.rejects(createWebhookProcessor(deps)(job), err => err.statusCode === 503);

        assert.strictEqual(job.progress[0].status, 'error');
        assert.strictEqual(job.progress[0].error.statusCode, 503);

        const [[key, flag]] = state.settingsWrites;
        assert.strictEqual(key, 'webhookErrorFlag');
        assert.strictEqual(flag.statusCode, 503);
        assert.strictEqual(flag.event, 'messageNew');
        assert.ok(!flag.url.includes('secret'), 'stored without credentials');

        assert.deepStrictEqual(state.metrics[0], ['webhooks', 'inc', { event: 'messageNew', status: 'fail' }]);
        // a 503 is not a timeout, so the target is not penalised
        assert.strictEqual(state.sets.length, 0);
        // not the last attempt, so not an error yet
        assert.ok(state.logs.some(l => l.level === 'warn' && l.code === 'result_fail'));
    });

    await t.test('the last attempt logs at error', async () => {
        const { deps, state } = makeDeps({ status: 500 });
        await assert.rejects(createWebhookProcessor(deps)(makeJob({ attemptsMade: 9, attempts: 10 })));
        assert.ok(state.logs.some(l => l.level === 'error' && l.code === 'result_fail'));
    });

    await t.test('a route failure stores the route URL without its credentials', async () => {
        const { deps, state } = makeDeps({
            status: 500,
            routes: { r1: { id: 'r1', enabled: true, targetUrl: 'https://u:topsecret@route.example.com/' } }
        });
        await assert.rejects(createWebhookProcessor(deps)(makeJob({ data: { _route: { id: 'r1', mapping: {} } } })));
        const flag = JSON.parse(state.hashes.get(CONTENT_KEY).get('r1:webhookErrorFlag'));
        assert.strictEqual(flag.statusCode, 500);
        assert.ok(!flag.url.includes('topsecret'));
    });

    await t.test('a timed out attempt penalises the target origin', async () => {
        const timeout = Object.assign(new Error('Webhook request timed out after 30s'), { code: 'ETIMEDOUT' });
        const { deps, state } = makeDeps({ fetchError: timeout });
        await assert.rejects(createWebhookProcessor(deps)(makeJob()), /timed out/);
        assert.deepStrictEqual(state.sets[0], [penaltyKey('https://global.example.com/hook'), '1', 'PX', 60000]);
    });

    await t.test('an unfollowed redirect fails the job for good and keeps the code', async () => {
        const { deps, state } = makeDeps({ status: 302, validateTarget: async () => true });
        let thrown;
        await assert.rejects(createWebhookProcessor(deps)(makeJob()), err => {
            thrown = err;
            return true;
        });
        assert.ok(thrown instanceof UnrecoverableError);
        assert.strictEqual(thrown.code, 'EREDIRECTNOTFOLLOWED');
        // final on its first failure, so it logs at error with attempts left
        assert.ok(state.logs.some(l => l.level === 'error' && l.code === 'result_fail'));
    });

    await t.test('an error flag write that fails does not change the outcome', async () => {
        const { deps } = makeDeps();
        deps.settings.clear = async () => {
            throw new Error("OOM command not allowed when used memory > 'maxmemory'.");
        };
        const result = await createWebhookProcessor(deps)(makeJob());
        assert.strictEqual(result.status, 'delivered');
    });
});

test('filterLogData keeps only the identifying payload fields', () => {
    assert.deepStrictEqual(filterLogData({ account: 'a', event: 'messageNew', data: { id: 'X', uid: 1, path: 'INBOX', messageId: '<m>', subject: 's' } }), {
        account: 'a',
        event: 'messageNew',
        data: { id: 'X', uid: 1, path: 'INBOX', messageId: '<m>', partial: true }
    });
    assert.deepStrictEqual(filterLogData({ data: { subject: 's' } }), { data: true });
    assert.deepStrictEqual(filterLogData({ data: { id: 'X' } }), { data: { id: 'X' } });
    assert.deepStrictEqual(filterLogData({ data: null }), { data: {} });
});
