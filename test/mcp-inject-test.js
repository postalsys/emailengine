'use strict';

// lib/mcp/inject.js: the single dispatch path of MCP tool calls and resource reads. What is under
// test is the mirroring rule: every attribute a token restriction reads (credential, client IP,
// Referer) is copied onto the inner request, and the inner request carries the mcpInternal marker.
// The server is a stub that records what it was asked to inject. Pure, no Redis.

const test = require('node:test');
const assert = require('node:assert').strict;

const { apiInject } = require('../lib/mcp/inject');

function recordingServer() {
    const injected = [];
    return {
        injected,
        async inject(opts) {
            injected.push(opts);
            return { statusCode: 200 };
        }
    };
}

function outerRequest(overrides) {
    return Object.assign(
        {
            auth: { credentials: { token: 'a'.repeat(64) } },
            headers: {},
            app: { ip: '198.51.100.7', licenseInfo: { active: true } }
        },
        overrides
    );
}

test('apiInject', async t => {
    await t.test('mirrors the credential as a bearer token, whichever way it arrived', async () => {
        const server = recordingServer();
        await apiInject({ server, request: outerRequest(), method: 'get', url: '/v1/accounts' });
        assert.equal(server.injected[0].headers.authorization, `Bearer ${'a'.repeat(64)}`);
        assert.equal(server.injected[0].method, 'get');
        assert.equal(server.injected[0].url, '/v1/accounts');
    });

    await t.test('sends no credential for the preauth caller', async () => {
        const server = recordingServer();
        await apiInject({ server, request: outerRequest({ auth: { credentials: {} } }), method: 'get', url: '/v1/accounts' });
        assert.equal(server.injected[0].headers.authorization, undefined);

        await apiInject({ server, request: outerRequest({ auth: undefined }), method: 'get', url: '/v1/accounts' });
        assert.equal(server.injected[1].headers.authorization, undefined);
    });

    await t.test('mirrors the resolved client address, not the loopback of the dispatch', async () => {
        const server = recordingServer();
        await apiInject({ server, request: outerRequest(), method: 'get', url: '/v1/accounts' });
        assert.equal(server.injected[0].remoteAddress, '198.51.100.7');

        await apiInject({ server, request: outerRequest({ app: {} }), method: 'get', url: '/v1/accounts' });
        assert.equal(server.injected[1].remoteAddress, undefined, 'left to the default rather than invented');
    });

    await t.test('mirrors the Referer and the timeout header, and nothing else from the outer request', async () => {
        const server = recordingServer();
        await apiInject({
            server,
            request: outerRequest({
                headers: { referer: 'https://app.example.com/page', 'x-ee-timeout': '5000', cookie: 'session=1', 'x-forwarded-for': '203.0.113.1' }
            }),
            method: 'get',
            url: '/v1/accounts'
        });
        const headers = server.injected[0].headers;
        assert.equal(headers.referer, 'https://app.example.com/page');
        assert.equal(headers['x-ee-timeout'], '5000');
        assert.equal(headers.cookie, undefined);
        assert.equal(headers['x-forwarded-for'], undefined);
    });

    await t.test('marks the inner request as MCP-dispatched and carries the license info', async () => {
        const server = recordingServer();
        await apiInject({ server, request: outerRequest(), method: 'get', url: '/v1/accounts' });
        assert.deepEqual(server.injected[0].app, { mcpInternal: true, licenseInfo: { active: true } });
    });

    await t.test('sends a JSON payload with its content type, and none without one', async () => {
        const server = recordingServer();
        await apiInject({ server, request: outerRequest(), method: 'post', url: '/v1/x', payload: { a: 1 } });
        assert.equal(server.injected[0].headers['content-type'], 'application/json');
        assert.deepEqual(server.injected[0].payload, { a: 1 });

        await apiInject({ server, request: outerRequest(), method: 'get', url: '/v1/x' });
        assert.equal(server.injected[1].headers['content-type'], undefined);
    });
});
