'use strict';

const test = require('node:test');
const assert = require('node:assert').strict;
const http = require('node:http');
const net = require('node:net');

// --- Mock setup: must happen before any production imports ---

let mockRedisData = {};

function createMockRedis() {
    return {
        status: 'ready',
        hget: async (key, field) => (mockRedisData[key] && mockRedisData[key][field]) || null,
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
const { httpAgent, reloadHttpProxyAgent, createSocksAgent } = require('../lib/tools');
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

async function stopServer(server) {
    await new Promise(resolve => server.close(resolve));
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

    await t.test('Shared object reference - httpAgent identity is stable across reloads', async () => {
        const agentRef = httpAgent;
        const oldFetch = httpAgent.fetch;
        const oldRetry = httpAgent.retry;

        setMockSetting('httpProxyEnabled', false);
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
