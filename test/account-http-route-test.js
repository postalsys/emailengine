'use strict';

// The HTTP traffic of an account (Gmail API and MS Graph calls, OAuth2 token requests) follows the
// same network route as its IMAP and SMTP connections: the account's own proxy, or the local address
// the IMAP address strategy picks for it. See getAccountHttpRoute() in lib/utils/network.js and
// httpAgent.forRoute() in lib/tools.js.

const test = require('node:test');
const assert = require('node:assert').strict;

const { redis } = require('../lib/db');
const settings = require('../lib/settings');
const { REDIS_PREFIX } = require('../lib/consts');
const { httpAgent, ROUTE_DISPATCHER_IDLE_MS } = require('../lib/tools');
const { getAccountHttpRoute } = require('../lib/utils/network');
const { fetchTokenRequest } = require('../lib/oauth/token-fetch');
const { oauth2Apps } = require('../lib/oauth2-apps');
const { GmailOauth } = require('../lib/oauth/gmail');
const { OutlookOauth } = require('../lib/oauth/outlook');
const { MailRuOauth } = require('../lib/oauth/mail-ru');
const { startCapturingServer, stopServer } = require('./helpers/capture-http-server');
const { startProxyServer } = require('./helpers/http-proxy-server');
const registerRedisTeardown = require('./helpers/redis-teardown');

const { fetch: fetchCmd } = require('undici');

const createdApps = [];

registerRedisTeardown(redis, async () => {
    for (const id of createdApps) {
        await oauth2Apps.del(id).catch(() => false);
    }
});

const baseOpts = { clientId: 'test-id', clientSecret: 'test-secret', redirectUrl: 'http://localhost/callback', setFlag: async () => {} };

test('account HTTP route', async t => {
    // Answers with JSON naming the address the connection came from, and closes every connection
    // after one response, so each request through the proxy opens a tunnel the proxy counts
    const target = await startCapturingServer(res => {
        res.writeHead(200, { 'Content-Type': 'application/json', Connection: 'close' });
        res.end(JSON.stringify({ remoteAddress: res.socket.remoteAddress, access_token: 'token', expires_in: 3600 }));
    });
    const proxy = await startProxyServer();

    t.after(async () => {
        target.server.closeAllConnections();
        proxy.server.closeAllConnections();
        await stopServer(target.server);
        await stopServer(proxy.server);
    });

    const proxyHits = () => proxy.getConnectCount() + proxy.getHttpCount();

    await t.test('an empty route uses the shared dispatchers', () => {
        for (const route of [undefined, null, {}, { proxy: null, localAddress: null }]) {
            const dispatchers = httpAgent.forRoute(route);
            assert.equal(dispatchers.fetch, httpAgent.fetch);
            assert.equal(dispatchers.retry, httpAgent.retry);
        }
    });

    await t.test('a route reuses its dispatchers, a different route gets its own', () => {
        const first = httpAgent.forRoute({ proxy: proxy.url });
        assert.equal(httpAgent.forRoute({ proxy: proxy.url }), first);
        assert.notEqual(httpAgent.forRoute({ localAddress: '127.0.0.1' }), first);
        assert.notEqual(first.fetch, httpAgent.fetch);
    });

    await t.test('an account proxy carries the request, and wins over a local address', async () => {
        const before = proxyHits();
        const res = await fetchCmd(target.baseUrl, { dispatcher: httpAgent.forRoute({ proxy: proxy.url, localAddress: '192.0.2.1' }).fetch });
        assert.equal(res.status, 200);
        await res.text();
        assert.ok(proxyHits() > before, 'the request went through the proxy');
    });

    await t.test('a local address binds the source of the connection', async () => {
        const res = await fetchCmd(target.baseUrl, { dispatcher: httpAgent.forRoute({ localAddress: '127.0.0.1' }).fetch });
        assert.equal((await res.json()).remoteAddress, '127.0.0.1');

        // An address the host does not hold cannot be bound, which only fails if it was applied
        await assert.rejects(
            fetchCmd(target.baseUrl, { dispatcher: httpAgent.forRoute({ localAddress: '192.0.2.1' }).fetch }),
            err => (err.cause && err.cause.code) === 'EADDRNOTAVAIL'
        );
    });

    await t.test('the instance-wide HTTP proxy takes precedence over a local address, not over an account proxy', () => {
        const saved = httpAgent.proxyUrl;
        httpAgent.proxyUrl = proxy.url;
        try {
            assert.equal(httpAgent.forRoute({ localAddress: '127.0.0.1' }).fetch, httpAgent.fetch);
            assert.notEqual(httpAgent.forRoute({ proxy: proxy.url }).fetch, httpAgent.fetch);
        } finally {
            httpAgent.proxyUrl = saved;
        }
    });

    await t.test('a route left idle is dropped on the next miss, one in use is kept', () => {
        const idle = httpAgent.forRoute({ proxy: 'http://127.0.0.1:10001' });
        const busy = httpAgent.forRoute({ proxy: 'http://127.0.0.1:10002' });

        const realNow = Date.now;
        const later = realNow() + ROUTE_DISPATCHER_IDLE_MS + 1000;
        Date.now = () => later;
        try {
            // used again just now, so it survives the sweep the next miss runs
            assert.equal(httpAgent.forRoute({ proxy: 'http://127.0.0.1:10002' }), busy);
            httpAgent.forRoute({ proxy: 'http://127.0.0.1:10003' });
            assert.equal(httpAgent.forRoute({ proxy: 'http://127.0.0.1:10002' }), busy);
            assert.notEqual(httpAgent.forRoute({ proxy: 'http://127.0.0.1:10001' }), idle);
        } finally {
            Date.now = realNow;
        }
    });

    await t.test('token requests take the route', async () => {
        const before = proxyHits();
        const res = await fetchTokenRequest(`${target.baseUrl}/token`, { method: 'post', body: 'grant_type=refresh_token' }, {}, { proxy: proxy.url });
        await res.text();
        assert.ok(proxyHits() > before);

        // and without one they stay direct
        const direct = proxyHits();
        await (await fetchTokenRequest(`${target.baseUrl}/token`, { method: 'post', body: 'x' }, {})).text();
        assert.equal(proxyHits(), direct);
    });

    await t.test('a provider client built with a route sends every token and API request through it', async () => {
        const route = { proxy: proxy.url };

        const gmail = new GmailOauth({ ...baseOpts, route });
        gmail.tokenUrl = `${target.baseUrl}/token`;
        const outlook = new OutlookOauth({ ...baseOpts, authority: 'common', route });
        outlook.entraEndpoint = target.baseUrl;
        const outlookService = new OutlookOauth({ ...baseOpts, authority: 'tenant-id', useClientCredentials: true, route });
        outlookService.entraEndpoint = target.baseUrl;
        const mailRu = new MailRuOauth({ ...baseOpts, route });

        const calls = [
            ['Gmail code exchange', () => gmail.getToken('code')],
            ['Gmail refresh', () => gmail.refreshToken({ refreshToken: 'r' })],
            ['Gmail API request', () => gmail.request('token', `${target.baseUrl}/gmail`)],
            ['Outlook code exchange', () => outlook.getToken('code')],
            ['Outlook refresh', () => outlook.refreshToken({ refreshToken: 'r' })],
            ['Outlook client credentials', () => outlookService.refreshToken({})],
            ['Outlook API request', () => outlook.request('token', `${target.baseUrl}/graph`)],
            ['Mail.ru API request', () => mailRu.request('token', `${target.baseUrl}/mailru`)]
        ];

        for (const [label, call] of calls) {
            const before = proxyHits();
            await call();
            assert.ok(proxyHits() > before, `${label} went through the proxy`);
        }

        // an app-level client, built without a route, stays direct
        const appLevel = new GmailOauth(baseOpts);
        const before = proxyHits();
        await appLevel.request('token', `${target.baseUrl}/gmail`);
        assert.equal(proxyHits(), before);
    });

    await t.test('oauth2Apps.getClient() binds the route it is given', async () => {
        const created = await oauth2Apps.create({
            provider: 'gmail',
            name: 'Route test app',
            enabled: true,
            clientId: 'client-id',
            clientSecret: 'client-secret',
            redirectUrl: 'https://example.test/oauth',
            baseScopes: 'api'
        });
        createdApps.push(created.id);

        const route = { proxy: proxy.url, localAddress: null };
        assert.deepEqual((await oauth2Apps.getClient(created.id, { route })).route, route);
        assert.equal((await oauth2Apps.getClient(created.id)).route, null);
    });

    await t.test('getAccountHttpRoute mirrors the IMAP connection route', async () => {
        assert.deepEqual(await getAccountHttpRoute(redis, { account: 'route-test', proxy: 'socks5://127.0.0.1:1080' }), {
            proxy: 'socks5://127.0.0.1:1080',
            localAddress: null
        });

        const savedAddresses = await settings.get('localAddresses');
        const interfaceKey = `${REDIS_PREFIX}interfaces`;
        const savedInterface = await redis.hget(interfaceKey, '127.0.0.1');
        try {
            await settings.set('localAddresses', []);
            assert.deepEqual(await getAccountHttpRoute(redis, { account: 'route-test' }), { proxy: null, localAddress: null });

            await settings.set('localAddresses', ['127.0.0.1']);
            await redis.hset(interfaceKey, '127.0.0.1', JSON.stringify({ localAddress: '127.0.0.1', ip: '127.0.0.1', name: 'localhost' }));

            assert.deepEqual(await getAccountHttpRoute(redis, { account: 'route-test' }), { proxy: null, localAddress: '127.0.0.1' });
            // the account proxy still wins
            assert.deepEqual(await getAccountHttpRoute(redis, { account: 'route-test', proxy: proxy.url }), { proxy: proxy.url, localAddress: null });
            // a pending OAuth2 setup without an account id yet has nothing to key the strategy on
            assert.deepEqual(await getAccountHttpRoute(redis, { account: null }), { proxy: null, localAddress: null });
        } finally {
            await settings.set('localAddresses', savedAddresses || []);
            if (savedInterface) {
                await redis.hset(interfaceKey, '127.0.0.1', savedInterface);
            } else {
                await redis.hdel(interfaceKey, '127.0.0.1');
            }
        }
    });
});
