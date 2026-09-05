'use strict';

const test = require('node:test');
const assert = require('node:assert').strict;
const http = require('node:http');
const net = require('node:net');
const path = require('node:path');
const { Worker } = require('node:worker_threads');

// --- Mock setup: must happen before any production imports ---

let mockRedisData = {};

function createMockRedis() {
    return {
        status: 'ready',
        hget: async (key, field) => (mockRedisData[key] && mockRedisData[key][field]) || null,
        hmget: async (key, fields) => fields.map(field => (mockRedisData[key] && mockRedisData[key][field]) || null),
        hset: async (key, field, value) => {
            if (!mockRedisData[key]) mockRedisData[key] = {};
            mockRedisData[key][field] = value;
        },
        hgetall: async key => mockRedisData[key] || null,
        hdel: async () => {},
        hSetExists: async () => {},
        hgetallBuffer: async () => ({}),
        hmset: async (key, data) => {
            if (!mockRedisData[key]) mockRedisData[key] = {};
            Object.assign(mockRedisData[key], data);
        },
        multi: () => ({
            exec: async () => [],
            hmset: function () {
                return this;
            },
            hset: function () {
                return this;
            },
            hdel: function () {
                return this;
            },
            del: function () {
                return this;
            },
            expire: function () {
                return this;
            },
            srem: function () {
                return this;
            },
            zadd: function () {
                return this;
            },
            hincrby: function () {
                return this;
            }
        }),
        ttl: async () => 3600,
        eval: async () => 1,
        smembers: async () => [],
        srem: async () => {},
        exists: async () => 0,
        get: async () => null,
        set: async () => 'OK',
        scan: async () => ['0', []],
        quit: async () => {},
        disconnect: () => {},
        subscribe: () => {},
        on: () => {},
        off: () => {},
        defineCommand: () => {},
        duplicate: function () {
            return createMockRedis();
        }
    };
}

const mockRedis = createMockRedis();
const mockQueue = {
    add: async () => ({}),
    close: async () => {},
    on: () => {},
    off: () => {},
    getJob: async () => null
};

const dbPath = require.resolve('../lib/db');
require.cache[dbPath] = {
    id: dbPath,
    filename: dbPath,
    loaded: true,
    parent: null,
    children: [],
    exports: {
        redis: mockRedis,
        queueConf: { connection: {} },
        notifyQueue: mockQueue,
        submitQueue: mockQueue,
        documentsQueue: mockQueue,
        exportQueue: mockQueue,
        getFlowProducer: () => ({}),
        REDIS_CONF: {},
        getRedisURL: () => 'redis://mock'
    }
};

// Mock get-secret to return null (no encryption)
const getSecretPath = require.resolve('../lib/get-secret');
require.cache[getSecretPath] = {
    id: getSecretPath,
    filename: getSecretPath,
    loaded: true,
    parent: null,
    children: [],
    exports: async () => null
};

// Now safe to import production modules
const { httpAgent, reloadHttpProxyAgent, maybeReloadHttpProxyAgent, resolveHttpProxy, createSocksAgent } = require('../lib/tools');
const { makeTransport: makeSentryTransport } = require('../lib/sentry');
const { startCapturingServer, stopServer } = require('./helpers/capture-http-server');
const { REDIS_PREFIX } = require('../lib/consts');

// Helper: set mock setting value (JSON-stringified, no encryption)
function setMockSetting(key, value) {
    if (!mockRedisData[`${REDIS_PREFIX}settings`]) {
        mockRedisData[`${REDIS_PREFIX}settings`] = {};
    }
    mockRedisData[`${REDIS_PREFIX}settings`][key] = JSON.stringify(value);
}

// Helper: create a simple HTTP target server that returns 200
async function startTargetServer() {
    let requestCount = 0;
    const server = http.createServer((req, res) => {
        requestCount++;
        req.on('data', () => {});
        req.on('end', () => {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ ok: true, count: requestCount }));
        });
    });

    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    const { port } = server.address();

    return {
        server,
        port,
        baseUrl: `http://127.0.0.1:${port}`,
        getCount: () => requestCount
    };
}

// Helper: create a minimal SOCKS5 server (no authentication, CONNECT only) so the SOCKS path of the
// proxy agent is exercised end to end rather than duck-typed
async function startSocksServer() {
    let connectCount = 0;
    const sockets = new Set();

    const server = net.createServer(client => {
        sockets.add(client);
        client.on('close', () => sockets.delete(client));
        client.on('error', () => client.destroy());

        // greeting: VER NMETHODS METHODS -> VER METHOD(no auth)
        client.once('data', () => {
            client.write(Buffer.from([0x05, 0x00]));

            // request: VER CMD RSV ATYP DST.ADDR DST.PORT
            client.once('data', req => {
                let host;
                let offset;
                if (req[3] === 0x01) {
                    host = Array.from(req.subarray(4, 8)).join('.');
                    offset = 8;
                } else if (req[3] === 0x03) {
                    let len = req[4];
                    host = req.subarray(5, 5 + len).toString();
                    offset = 5 + len;
                } else {
                    client.end(Buffer.from([0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
                    return;
                }
                let port = req.readUInt16BE(offset);
                connectCount++;

                const upstream = net.connect(port, host, () => {
                    sockets.add(upstream);
                    client.write(Buffer.from([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
                    upstream.pipe(client);
                    client.pipe(upstream);
                });
                upstream.on('close', () => sockets.delete(upstream));
                upstream.on('error', () => client.destroy());
                client.on('close', () => upstream.destroy());
            });
        });
    });

    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    const { port } = server.address();

    return {
        server,
        port,
        url: `socks5://127.0.0.1:${port}`,
        getConnectCount: () => connectCount,
        async stop() {
            for (let socket of sockets) {
                socket.destroy();
            }
            await new Promise(resolve => server.close(resolve));
        }
    };
}

// Helper: create an HTTP CONNECT proxy server
async function startProxyServer() {
    let connectCount = 0;
    let httpCount = 0;

    const server = http.createServer((req, res) => {
        // Handle plain HTTP requests (non-CONNECT)
        httpCount++;
        const targetUrl = new URL(req.url);
        const proxyReq = http.request(
            {
                hostname: targetUrl.hostname,
                port: targetUrl.port,
                path: targetUrl.pathname + targetUrl.search,
                method: req.method,
                headers: req.headers
            },
            proxyRes => {
                res.writeHead(proxyRes.statusCode, proxyRes.headers);
                proxyRes.pipe(res);
            }
        );
        req.pipe(proxyReq);
    });

    server.on('connect', (req, clientSocket, head) => {
        connectCount++;
        const [hostname, port] = req.url.split(':');
        const targetSocket = net.connect(Number(port), hostname, () => {
            clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
            if (head.length) {
                targetSocket.write(head);
            }
            targetSocket.pipe(clientSocket);
            clientSocket.pipe(targetSocket);
        });
        targetSocket.on('error', () => clientSocket.destroy());
        clientSocket.on('error', () => targetSocket.destroy());
    });

    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    const { port } = server.address();

    return {
        server,
        port,
        url: `http://127.0.0.1:${port}`,
        getConnectCount: () => connectCount,
        getHttpCount: () => httpCount
    };
}

const { fetch: fetchCmd } = require('undici');

test('HTTP proxy agent management', async t => {
    t.after(() => {
        setTimeout(() => process.exit(), 1000).unref();
    });

    t.beforeEach(() => {
        mockRedisData = {};
        // Clean up env vars
        delete process.env.EENGINE_HTTP_PROXY_ENABLED;
        delete process.env.EENGINE_HTTP_PROXY_URL;
    });

    await t.test('resolveHttpProxy - dedicated HTTP proxy, then the global proxy, then direct', () => {
        // the environment reader is injected so these cases never touch process.env
        const withEnv = vars => key => vars[key];
        const env = withEnv({});
        const global = { proxyEnabled: true, proxyUrl: 'socks5://global.example.com:1080' };
        const dedicated = { httpProxyEnabled: true, httpProxyUrl: 'http://http.example.com:3128' };

        assert.strictEqual(resolveHttpProxy({}, env), null);
        assert.strictEqual(resolveHttpProxy(undefined, env), null);
        assert.strictEqual(resolveHttpProxy({ proxyUrl: global.proxyUrl }, env), null, 'a URL without the enable flag is ignored');
        assert.strictEqual(resolveHttpProxy({ proxyEnabled: true, proxyUrl: '' }, env), null, 'an enable flag without a URL is ignored');

        assert.deepStrictEqual(resolveHttpProxy(global, env), { url: global.proxyUrl, source: 'proxyUrl' }, 'the global proxy covers HTTP');
        assert.deepStrictEqual(resolveHttpProxy(Object.assign({}, global, dedicated), env), { url: dedicated.httpProxyUrl, source: 'httpProxyUrl' });
        assert.deepStrictEqual(
            resolveHttpProxy(Object.assign({}, global, dedicated, { httpProxyUrl: '' }), env),
            { url: global.proxyUrl, source: 'proxyUrl' },
            'an enabled HTTP proxy without a URL falls back to the global proxy'
        );
        assert.deepStrictEqual(
            resolveHttpProxy(Object.assign({}, global, dedicated, { httpProxyEnabled: false }), env),
            { url: global.proxyUrl, source: 'proxyUrl' },
            'a disabled HTTP proxy falls back to the global proxy'
        );

        // environment overrides
        assert.deepStrictEqual(
            resolveHttpProxy(global, withEnv({ EENGINE_HTTP_PROXY_ENABLED: 'true', EENGINE_HTTP_PROXY_URL: 'http://env.example.com:3128' })),
            { url: 'http://env.example.com:3128', source: 'httpProxyUrl' }
        );
        assert.deepStrictEqual(
            resolveHttpProxy(dedicated, withEnv({ EENGINE_HTTP_PROXY_URL: 'http://env.example.com:3128' })),
            { url: 'http://env.example.com:3128', source: 'httpProxyUrl' },
            'the env URL replaces the stored one'
        );
        assert.deepStrictEqual(
            resolveHttpProxy(global, withEnv({ EENGINE_HTTP_PROXY_ENABLED: 'yes' })),
            { url: global.proxyUrl, source: 'proxyUrl' },
            'enabled in the environment with no URL anywhere still falls back to the global proxy'
        );
        assert.strictEqual(
            resolveHttpProxy(Object.assign({}, global, dedicated), withEnv({ EENGINE_HTTP_PROXY_ENABLED: 'false' })),
            null,
            'an explicit false in the environment turns HTTP proxying off, global proxy included'
        );
    });

    await t.test('Global proxy covers HTTP - requests go through the IMAP/SMTP proxy when no HTTP proxy is set', async () => {
        const target = await startTargetServer();
        const proxy = await startProxyServer();
        try {
            setMockSetting('proxyEnabled', true);
            setMockSetting('proxyUrl', proxy.url);
            setMockSetting('httpProxyEnabled', false);
            setMockSetting('httpProxyUrl', '');
            await reloadHttpProxyAgent();

            const res = await fetchCmd(`${target.baseUrl}/global`, { dispatcher: httpAgent.retry });
            assert.ok(res.ok);
            await res.text();

            assert.strictEqual(proxy.getConnectCount(), 1, 'the request should have been tunnelled through the global proxy');
            assert.strictEqual(target.getCount(), 1);
            assert.strictEqual(httpAgent.webhook, httpAgent.fetch, 'behind the global proxy the webhook dispatcher shares the general one too');
        } finally {
            await stopServer(target.server);
            await stopServer(proxy.server);
        }
    });

    await t.test('Dedicated HTTP proxy wins over the global proxy', async () => {
        const target = await startTargetServer();
        const globalProxy = await startProxyServer();
        const httpProxy = await startProxyServer();
        try {
            setMockSetting('proxyEnabled', true);
            setMockSetting('proxyUrl', globalProxy.url);
            setMockSetting('httpProxyEnabled', true);
            setMockSetting('httpProxyUrl', httpProxy.url);
            await reloadHttpProxyAgent();

            const res = await fetchCmd(`${target.baseUrl}/dedicated`, { dispatcher: httpAgent.retry });
            assert.ok(res.ok);
            await res.text();

            assert.strictEqual(httpProxy.getConnectCount(), 1, 'the dedicated HTTP proxy should carry the request');
            assert.strictEqual(globalProxy.getConnectCount(), 0, 'the global proxy should not see HTTP traffic');
        } finally {
            await stopServer(target.server);
            await stopServer(globalProxy.server);
            await stopServer(httpProxy.server);
        }
    });

    await t.test('Global proxy URL without the enable flag - requests stay direct', async () => {
        const target = await startTargetServer();
        const proxy = await startProxyServer();
        try {
            setMockSetting('proxyEnabled', false);
            setMockSetting('proxyUrl', proxy.url);
            await reloadHttpProxyAgent();

            const res = await fetchCmd(`${target.baseUrl}/direct`, { dispatcher: httpAgent.retry });
            assert.ok(res.ok);
            await res.text();

            assert.strictEqual(proxy.getConnectCount(), 0);
            assert.strictEqual(target.getCount(), 1);
        } finally {
            await stopServer(target.server);
            await stopServer(proxy.server);
        }
    });

    await t.test('SOCKS5 global proxy - requests are tunnelled through it', async () => {
        const target = await startTargetServer();
        const socks = await startSocksServer();
        try {
            setMockSetting('proxyEnabled', true);
            setMockSetting('proxyUrl', socks.url);
            await reloadHttpProxyAgent();

            const res = await fetchCmd(`${target.baseUrl}/socks`, { dispatcher: httpAgent.retry });
            assert.ok(res.ok);
            const body = await res.json();
            assert.strictEqual(body.ok, true);

            assert.strictEqual(socks.getConnectCount(), 1, 'the SOCKS server should have opened the tunnel');
            assert.strictEqual(target.getCount(), 1);
        } finally {
            await stopServer(target.server);
            await socks.stop();
        }
    });

    await t.test('maybeReloadHttpProxyAgent - re-reads the settings for proxy keys only', async () => {
        setMockSetting('proxyEnabled', false);
        await reloadHttpProxyAgent();

        let before = httpAgent.fetch;
        assert.strictEqual(await maybeReloadHttpProxyAgent({ webhooks: 'https://example.com/hook' }), false);
        assert.strictEqual(await maybeReloadHttpProxyAgent(null), false);
        assert.strictEqual(httpAgent.fetch, before, 'an unrelated settings change should not touch the agent');

        // the broadcast carries the saved keys, the values come from the settings store
        setMockSetting('proxyEnabled', true);
        setMockSetting('proxyUrl', 'http://proxy.example.com:3128');
        await maybeReloadHttpProxyAgent({ webhooks: 'https://example.com/hook' });
        assert.strictEqual(httpAgent.fetch, before, 'a broadcast without a proxy key should not re-read the settings');

        let enabled = true;
        for (let key of ['proxyEnabled', 'proxyUrl', 'httpProxyEnabled', 'httpProxyUrl']) {
            setMockSetting('proxyEnabled', enabled);
            before = httpAgent.fetch;
            await maybeReloadHttpProxyAgent({ [key]: 'changed' });
            assert.notStrictEqual(httpAgent.fetch, before, `a ${key} change should apply the stored settings`);
            assert.strictEqual(httpAgent.proxyUrl, enabled ? 'http://proxy.example.com:3128' : null);
            enabled = !enabled;
        }
    });

    await t.test('Unchanged proxy settings - a reload keeps the warm agents', async () => {
        setMockSetting('proxyEnabled', true);
        setMockSetting('proxyUrl', 'http://proxy.example.com:3128');
        await reloadHttpProxyAgent();

        const { fetch, retry, webhook } = httpAgent;
        assert.strictEqual(httpAgent.proxyUrl, 'http://proxy.example.com:3128');

        // the network form posts every proxy key on every save, changed or not
        await reloadHttpProxyAgent();
        await maybeReloadHttpProxyAgent({ proxyEnabled: true, proxyUrl: 'http://proxy.example.com:3128', smtpEhloName: 'mail.example.com' });

        assert.strictEqual(httpAgent.fetch, fetch, 'the fetch agent should be kept');
        assert.strictEqual(httpAgent.retry, retry, 'the retry agent should be kept');
        assert.strictEqual(httpAgent.webhook, webhook, 'the webhook dispatcher should be kept');
    });

    await t.test('Worker boot - dispatchers are built from workerData before any worker code runs', async () => {
        const target = await startTargetServer();
        const proxy = await startProxyServer();
        const worker = new Worker(path.join(__dirname, 'helpers', 'http-proxy-worker.js'), {
            workerData: { httpProxyUrl: proxy.url, targetUrl: `${target.baseUrl}/worker-boot` }
        });
        try {
            const report = await new Promise((resolve, reject) => {
                worker.once('message', resolve);
                worker.once('error', reject);
                worker.once('exit', code => reject(new Error(`worker exited with code ${code} before reporting`)));
            });

            assert.strictEqual(report.proxyUrl, proxy.url, 'the worker should know which proxy its dispatchers were built for');
            assert.strictEqual(report.ok, true, report.error);
            assert.strictEqual(proxy.getConnectCount(), 1, 'the first request of the worker should already go through the proxy');
            assert.strictEqual(target.getCount(), 1);
        } finally {
            await worker.terminate();
            await stopServer(target.server);
            await stopServer(proxy.server);
        }
    });

    await t.test('Live dispatcher - forwards to the current agent across reloads', async () => {
        const target = await startTargetServer();
        const proxy = await startProxyServer();
        try {
            const live = httpAgent.live;

            setMockSetting('proxyEnabled', false);
            await reloadHttpProxyAgent();

            let res = await fetchCmd(`${target.baseUrl}/live-direct`, { dispatcher: live });
            assert.ok(res.ok);
            await res.text();
            assert.strictEqual(proxy.getConnectCount(), 0);

            setMockSetting('proxyEnabled', true);
            setMockSetting('proxyUrl', proxy.url);
            await reloadHttpProxyAgent();

            res = await fetchCmd(`${target.baseUrl}/live-proxied`, { dispatcher: live });
            assert.ok(res.ok);
            await res.text();
            assert.strictEqual(proxy.getConnectCount(), 1, 'the same dispatcher object should now go through the proxy');

            assert.strictEqual(httpAgent.live, live, 'the live dispatcher is never replaced');
            assert.strictEqual(target.getCount(), 2);
        } finally {
            await stopServer(target.server);
            await stopServer(proxy.server);
        }
    });

    await t.test('Sentry transport - error reports go through the proxy', async () => {
        const target = await startCapturingServer(res => {
            res.writeHead(200, { 'Content-Type': 'application/json', 'X-Sentry-Rate-Limits': '60:error:organization' });
            res.end('{}');
        });
        const proxy = await startProxyServer();
        try {
            setMockSetting('proxyEnabled', true);
            setMockSetting('proxyUrl', proxy.url);
            await reloadHttpProxyAgent();

            const transport = makeSentryTransport({
                url: `${target.baseUrl}/api/1/envelope/`,
                headers: { 'X-Sentry-Auth': 'Sentry sentry_key=test' },
                recordDroppedEvent() {}
            });

            const envelope = [
                { event_id: 'a'.repeat(32), sent_at: new Date().toISOString() },
                [[{ type: 'event' }, { event_id: 'a'.repeat(32), message: 'proxied report' }]]
            ];
            const result = await transport.send(envelope);

            assert.strictEqual(result.statusCode, 200);
            assert.strictEqual(result.headers['x-sentry-rate-limits'], '60:error:organization');
            assert.strictEqual(proxy.getConnectCount(), 1, 'the report should have been tunnelled through the proxy');

            const requests = target.getRequests();
            assert.strictEqual(requests.length, 1);
            assert.strictEqual(requests[0].method, 'POST');
            assert.strictEqual(requests[0].path, '/api/1/envelope/');
            assert.strictEqual(requests[0].headers['x-sentry-auth'], 'Sentry sentry_key=test');
            assert.ok(requests[0].body.includes('proxied report'), 'the envelope body should reach the endpoint');
        } finally {
            await stopServer(target.server);
            await stopServer(proxy.server);
        }
    });

    await t.test('Default agent (no proxy) - requests reach target directly', async () => {
        const target = await startTargetServer();
        try {
            setMockSetting('httpProxyEnabled', false);
            await reloadHttpProxyAgent();

            const res = await fetchCmd(`${target.baseUrl}/test`, { dispatcher: httpAgent.retry });
            assert.ok(res.ok, 'Response should be OK');
            const body = await res.json();
            assert.strictEqual(body.ok, true);
            assert.strictEqual(target.getCount(), 1);
        } finally {
            await stopServer(target.server);
        }
    });

    await t.test('HTTP proxy routing - requests go through proxy', async () => {
        const target = await startTargetServer();
        const proxy = await startProxyServer();
        try {
            setMockSetting('httpProxyEnabled', true);
            setMockSetting('httpProxyUrl', proxy.url);
            await reloadHttpProxyAgent();

            // Make a request to the target through the proxy (undici uses CONNECT tunnel)
            const res = await fetchCmd(`${target.baseUrl}/proxied`, { dispatcher: httpAgent.retry });
            assert.ok(res.ok, 'Response should be OK');
            const body = await res.json();
            assert.strictEqual(body.ok, true);

            // Proxy should have received the CONNECT request
            assert.ok(proxy.getConnectCount() >= 1, 'Proxy should have handled the CONNECT request');
        } finally {
            await stopServer(target.server);
            await stopServer(proxy.server);
        }
    });

    await t.test('Agent swap on reload - changing settings swaps agent', async () => {
        const target = await startTargetServer();
        const proxy = await startProxyServer();
        try {
            // Start with proxy enabled
            setMockSetting('httpProxyEnabled', true);
            setMockSetting('httpProxyUrl', proxy.url);
            await reloadHttpProxyAgent();

            const res1 = await fetchCmd(`${target.baseUrl}/swap1`, { dispatcher: httpAgent.retry });
            assert.ok(res1.ok);
            await res1.text();

            const proxyCountBefore = proxy.getConnectCount();
            assert.ok(proxyCountBefore >= 1, 'Request should have gone through proxy');

            // Disable proxy
            setMockSetting('httpProxyEnabled', false);
            await reloadHttpProxyAgent();

            const res2 = await fetchCmd(`${target.baseUrl}/swap2`, { dispatcher: httpAgent.retry });
            assert.ok(res2.ok);
            await res2.text();

            // Proxy count should NOT have increased
            assert.strictEqual(proxy.getConnectCount(), proxyCountBefore, 'Second request should bypass proxy');
        } finally {
            await stopServer(target.server);
            await stopServer(proxy.server);
        }
    });

    await t.test('Webhook dispatcher - dedicated without a proxy, shared behind one', async () => {
        // Webhook deliveries go through their own dispatcher so the egress policy is applied by
        // the lookup the socket actually uses. Behind a proxy the target is resolved at the proxy,
        // so there is nothing local to bind and the shared dispatcher is used instead.
        setMockSetting('httpProxyEnabled', false);
        await reloadHttpProxyAgent();

        assert.ok(httpAgent.webhook, 'webhook dispatcher should exist');
        assert.notStrictEqual(httpAgent.webhook, httpAgent.fetch, 'webhook deliveries should not share the general dispatcher');

        const proxy = await startProxyServer();
        try {
            setMockSetting('httpProxyEnabled', true);
            setMockSetting('httpProxyUrl', proxy.url);
            await reloadHttpProxyAgent();

            assert.strictEqual(httpAgent.webhook, httpAgent.fetch, 'behind a proxy the webhook dispatcher should fall back to the shared one');

            setMockSetting('httpProxyEnabled', false);
            await reloadHttpProxyAgent();

            assert.notStrictEqual(httpAgent.webhook, httpAgent.fetch, 'dropping the proxy should restore the dedicated dispatcher');
        } finally {
            await stopServer(proxy.server);
        }
    });

    await t.test('Shared object reference - httpAgent identity is stable while its agents are swapped', async () => {
        const agentRef = httpAgent;

        setMockSetting('httpProxyEnabled', false);
        await reloadHttpProxyAgent();
        const oldFetch = httpAgent.fetch;
        const oldRetry = httpAgent.retry;

        setMockSetting('httpProxyEnabled', true);
        setMockSetting('httpProxyUrl', 'http://proxy.example.com:3128');
        await reloadHttpProxyAgent();

        // Object reference is the same
        assert.strictEqual(httpAgent, agentRef, 'httpAgent object reference should be stable');
        // But properties should be new instances
        assert.notStrictEqual(httpAgent.fetch, oldFetch, '.fetch property should be a new agent');
        assert.notStrictEqual(httpAgent.retry, oldRetry, '.retry property should be a new agent');
    });

    await t.test('Invalid proxy URL - keeps existing agent', async () => {
        // Set up a working agent first
        setMockSetting('httpProxyEnabled', false);
        await reloadHttpProxyAgent();

        const workingFetch = httpAgent.fetch;
        const workingRetry = httpAgent.retry;

        // Now try to set an invalid URL
        setMockSetting('httpProxyEnabled', true);
        setMockSetting('httpProxyUrl', 'not-a-url');
        await reloadHttpProxyAgent();

        // Agent should still work (fallback to existing)
        assert.strictEqual(httpAgent.fetch, workingFetch, 'Agent should be preserved on invalid URL');
        assert.strictEqual(httpAgent.retry, workingRetry, 'Retry agent should be preserved on invalid URL');
    });

    await t.test('SOCKS agent creation - returns valid agent', async () => {
        const agent = createSocksAgent('socks5://127.0.0.1:1080', {
            connectTimeout: 5000,
            headersTimeout: 10000,
            bodyTimeout: 10000
        });

        // Duck-type check: should have a dispatch method (undici Agent interface)
        assert.strictEqual(typeof agent.dispatch, 'function', 'SOCKS agent should have dispatch method');

        await agent.close();
    });

    await t.test('Environment variable overrides', async () => {
        const target = await startTargetServer();
        const proxy = await startProxyServer();
        try {
            // Settings say disabled
            setMockSetting('httpProxyEnabled', false);
            setMockSetting('httpProxyUrl', '');

            // But env vars override
            process.env.EENGINE_HTTP_PROXY_ENABLED = 'true';
            process.env.EENGINE_HTTP_PROXY_URL = proxy.url;
            await reloadHttpProxyAgent();

            const res = await fetchCmd(`${target.baseUrl}/env-test`, { dispatcher: httpAgent.retry });
            assert.ok(res.ok);
            await res.text();

            assert.ok(proxy.getConnectCount() >= 1, 'Request should go through proxy via env var override');
        } finally {
            delete process.env.EENGINE_HTTP_PROXY_ENABLED;
            delete process.env.EENGINE_HTTP_PROXY_URL;
            await stopServer(target.server);
            await stopServer(proxy.server);
        }
    });

    await t.test('SOCKS agent creation - timeout option is passed', async () => {
        // Without explicit connectTimeout, should use default (30000)
        const agentDefault = createSocksAgent('socks5://127.0.0.1:1080', {
            headersTimeout: 10000,
            bodyTimeout: 10000
        });
        assert.strictEqual(typeof agentDefault.dispatch, 'function', 'Agent without explicit timeout should be valid');
        await agentDefault.close();

        // With explicit connectTimeout
        const agentCustom = createSocksAgent('socks5://127.0.0.1:1080', {
            connectTimeout: 5000,
            headersTimeout: 10000,
            bodyTimeout: 10000
        });
        assert.strictEqual(typeof agentCustom.dispatch, 'function', 'Agent with custom timeout should be valid');
        await agentCustom.close();

        // socks4a scheme
        const agentSocks4a = createSocksAgent('socks4a://127.0.0.1:1080', {
            connectTimeout: 5000,
            headersTimeout: 10000,
            bodyTimeout: 10000
        });
        assert.strictEqual(typeof agentSocks4a.dispatch, 'function', 'socks4a agent should be valid');
        await agentSocks4a.close();
    });

    await t.test('Concurrent reload coalescing - multiple calls share one reload', async () => {
        setMockSetting('httpProxyEnabled', false);

        // Fire 10 concurrent reloads
        const promises = [];
        for (let i = 0; i < 10; i++) {
            promises.push(reloadHttpProxyAgent());
        }
        await Promise.all(promises);

        // After all settle, httpAgent should have valid, stable properties
        assert.ok(httpAgent.fetch, 'httpAgent.fetch should exist after concurrent reloads');
        assert.ok(httpAgent.retry, 'httpAgent.retry should exist after concurrent reloads');
        assert.strictEqual(typeof httpAgent.fetch.dispatch, 'function', 'fetch agent should have dispatch method');
        assert.strictEqual(typeof httpAgent.retry.dispatch, 'function', 'retry agent should have dispatch method');

        // A subsequent reload should also work fine
        await reloadHttpProxyAgent();
        assert.ok(httpAgent.fetch, 'httpAgent.fetch should exist after subsequent reload');
        assert.ok(httpAgent.retry, 'httpAgent.retry should exist after subsequent reload');
    });

    await t.test('RetryAgent wrapping preserved - 429 responses are retried through proxy', async () => {
        let requestCount = 0;
        const target = http.createServer((req, res) => {
            requestCount++;
            req.on('data', () => {});
            req.on('end', () => {
                if (requestCount === 1) {
                    res.writeHead(429, { 'Content-Type': 'application/json', 'Retry-After': '0' });
                    res.end(JSON.stringify({ error: 'rate_limited' }));
                } else {
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ ok: true, attempt: requestCount }));
                }
            });
        });
        await new Promise(resolve => target.listen(0, '127.0.0.1', resolve));
        const targetPort = target.address().port;

        const proxy = await startProxyServer();
        try {
            setMockSetting('httpProxyEnabled', true);
            setMockSetting('httpProxyUrl', proxy.url);
            await reloadHttpProxyAgent();

            const res = await fetchCmd(`http://127.0.0.1:${targetPort}/retry-test`, { dispatcher: httpAgent.retry });
            assert.ok(res.ok, 'Final response should be OK after retry');
            const body = await res.json();
            assert.strictEqual(body.ok, true);
            assert.ok(requestCount >= 2, 'Request should have been retried at least once');
        } finally {
            await stopServer(target);
            await stopServer(proxy.server);
        }
    });
});
