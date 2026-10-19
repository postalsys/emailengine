'use strict';

// lib/hapi-request-logger.js replaced the hapi-pino plugin and has to write the records hapi-pino
// did, because operators parse them. The server is real (bound to a loopback port) so the records
// carry what a production request carries, and the logger is configured the way workers/api.js
// configures it.

const test = require('node:test');
const assert = require('node:assert').strict;
const http = require('http');
const { Writable } = require('stream');

const Hapi = require('@hapi/hapi');
const pino = require('pino');

const requestLogger = require('../lib/hapi-request-logger');
const { REDACTED_LOG_KEYS } = require('../lib/consts');

async function startServer(routes) {
    const records = [];
    const stream = new Writable({
        write(chunk, encoding, callback) {
            records.push(JSON.parse(chunk));
            callback();
        }
    });
    const base = pino({ redact: REDACTED_LOG_KEYS, level: 'trace' }, stream);

    const server = Hapi.server({ port: 0, host: '127.0.0.1' });
    await server.register({ plugin: requestLogger, options: { logger: base.child({ component: 'api' }, { redact: REDACTED_LOG_KEYS }) } });
    server.route(routes);
    await server.start();

    return { server, records, url: server.info.uri };
}

// The response event fires after the response is written, so a client can see the reply first
async function waitFor(records, predicate) {
    for (let i = 0; i < 100; i++) {
        const record = records.find(predicate);
        if (record) {
            return record;
        }
        await new Promise(resolve => setTimeout(resolve, 10));
    }
    throw new Error('record was not written');
}

const isResponse = path => record => typeof record.msg === 'string' && record.msg.startsWith('[response] ') && record.req && record.req.url === path;

test('request logger', async t => {
    const { server, records, url } = await startServer([
        {
            method: 'GET',
            path: '/ok/{id}',
            handler: request => {
                request.logger.debug({ msg: 'inside the handler', step: 1 });
                return { ok: true };
            }
        },
        {
            method: 'GET',
            path: '/boom',
            handler: () => {
                throw new Error('kaboom');
            }
        },
        {
            method: 'POST',
            path: '/events',
            handler: request => {
                request.log(['warn', 'custom'], 'request event');
                request.log(['custom'], { detail: 1 });
                server.log(['error', 'debug'], { server: 'event' });
                server.log(['info'], new Error('server error event'));
                return 'x';
            }
        },
        {
            method: 'GET',
            path: '/slow',
            handler: async () => {
                await new Promise(resolve => setTimeout(resolve, 200));
                return 'late';
            }
        }
    ]);

    t.after(() => server.stop());

    await t.test('logs server start with server.info', () => {
        const record = records.find(r => r.msg === 'server started');
        assert.ok(record);
        assert.strictEqual(record.level, 30);
        assert.strictEqual(record.component, 'api');
        assert.strictEqual(record.port, server.info.port);
        assert.strictEqual(record.protocol, 'http');
    });

    await t.test('decorates the server with the logger', () => {
        assert.strictEqual(typeof server.logger.info, 'function');
        assert.strictEqual(typeof server.logger.child, 'function');
    });

    await t.test('binds the serialized request to request.logger and redacts credentials', async () => {
        await fetch(`${url}/ok/5?access_token=secret-token&a=b`, { headers: { authorization: 'Bearer secret-token', cookie: 'ee=secret-cookie' } });

        const inside = await waitFor(records, r => r.msg === 'inside the handler');
        assert.strictEqual(inside.level, 20);
        assert.strictEqual(inside.step, 1);
        assert.strictEqual(inside.component, 'api');
        assert.strictEqual(inside.req.method, 'get');
        assert.strictEqual(inside.req.url, '/ok/5');
        assert.ok(inside.req.id);
        assert.strictEqual(inside.req.remoteAddress, '127.0.0.1');
        assert.strictEqual(typeof inside.req.remotePort, 'number');
        assert.deepStrictEqual(inside.req.query, { access_token: '[Redacted]', a: 'b' });
        assert.strictEqual(inside.req.headers.authorization, '[Redacted]');
        assert.strictEqual(inside.req.headers.cookie, '[Redacted]');

        const serialized = JSON.stringify(records);
        assert.ok(!serialized.includes('secret-token'));
        assert.ok(!serialized.includes('secret-cookie'));
    });

    await t.test('logs each response with status, timing and the same request id', async () => {
        const record = await waitFor(records, isResponse('/ok/5'));
        const inside = records.find(r => r.msg === 'inside the handler');

        assert.strictEqual(record.level, 30);
        assert.match(record.msg, /^\[response\] get \/ok\/5 200 \(\d+ms\)$/);
        assert.strictEqual(record.res.statusCode, 200);
        assert.strictEqual(record.res.headers['content-type'], 'application/json; charset=utf-8');
        assert.strictEqual(typeof record.responseTime, 'number');
        assert.ok(record.responseTime >= 0);
        assert.strictEqual(record.req.id, inside.req.id);
    });

    await t.test('logs responses to unrouted paths', async () => {
        await fetch(`${url}/missing`);
        const record = await waitFor(records, isResponse('/missing'));
        assert.match(record.msg, /^\[response\] get \/missing 404 \(\d+ms\)$/);
    });

    await t.test('logs a request error at error level with the error and its tags', async () => {
        await fetch(`${url}/boom`);
        const error = await waitFor(records, r => r.msg === 'kaboom');
        assert.strictEqual(error.level, 50);
        assert.deepStrictEqual(error.tags, ['internal', 'error']);
        assert.strictEqual(error.err.type, 'Error');
        assert.strictEqual(error.err.message, 'kaboom');
        assert.ok(error.err.stack);
        assert.strictEqual(error.req.url, '/boom');

        const response = await waitFor(records, isResponse('/boom'));
        assert.match(response.msg, / 500 \(\d+ms\)$/);
    });

    await t.test('bridges request.log() and server.log() events at the most severe level in their tags', async () => {
        await fetch(`${url}/events`, { method: 'POST' });
        await waitFor(records, isResponse('/events'));

        const requestEvent = records.find(r => r.data === 'request event');
        assert.strictEqual(requestEvent.level, 40);
        assert.deepStrictEqual(requestEvent.tags, ['warn', 'custom']);
        assert.strictEqual(requestEvent.req.url, '/events');

        const untagged = records.find(r => r.data && r.data.detail === 1);
        assert.strictEqual(untagged.level, 30);

        const serverEvent = records.find(r => r.data && r.data.server === 'event');
        assert.strictEqual(serverEvent.level, 50);
        assert.strictEqual(serverEvent.req, undefined);

        const serverError = records.find(r => r.err && r.err.message === 'server error event');
        assert.strictEqual(serverError.level, 50);
        assert.deepStrictEqual(serverError.tags, ['info']);
    });

    await t.test('logs "-" as the status when the client left before the response', async () => {
        await new Promise(resolve => {
            const req = http.get(`${url}/slow`);
            req.on('error', () => resolve());
            setTimeout(() => {
                req.destroy();
                resolve();
            }, 50);
        });

        const record = await waitFor(records, isResponse('/slow'));
        assert.match(record.msg, /^\[response\] get \/slow - \(\d+ms\)$/);
    });

    await t.test('logs server stop', async () => {
        await server.stop();
        const record = records.find(r => r.msg === 'server stopped');
        assert.ok(record);
        assert.strictEqual(record.level, 30);
    });
});
