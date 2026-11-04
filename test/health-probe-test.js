'use strict';

// The Docker HEALTHCHECK probe (lib/health-probe.js): the target follows the API's own port, bind
// address and TLS switch, and the probe speaks HTTPS to a TLS listener. Local listeners only.

const test = require('node:test');
const assert = require('node:assert').strict;
const http = require('http');
const https = require('https');

const { probeTarget, probe, PROBE_PATH } = require('../lib/health-probe');
const { createSelfSignedCertificate } = require('../lib/tls/self-signed');

const ENV_KEYS = ['EENGINE_PORT', 'PORT', 'EENGINE_HOST', 'EENGINE_API_TLS'];

function withEnv(values, fn) {
    const saved = {};
    for (const key of ENV_KEYS) {
        for (const name of [key, `${key}_FILE`]) {
            saved[name] = process.env[name];
            delete process.env[name];
        }
    }
    Object.assign(process.env, values);
    try {
        return fn();
    } finally {
        for (const [name, value] of Object.entries(saved)) {
            if (typeof value === 'undefined') {
                delete process.env[name];
            } else {
                process.env[name] = value;
            }
        }
    }
}

function listen(server) {
    return new Promise(resolve => server.listen(0, '127.0.0.1', () => resolve(server.address().port)));
}

function liveHandler(req, res) {
    res.writeHead(req.url === PROBE_PATH ? 200 : 404, { 'Content-Type': 'application/json' });
    res.end('{"success":true}');
}

test('probeTarget follows the configuration file when the environment says nothing', () => {
    withEnv({}, () => {
        assert.deepEqual(probeTarget({ port: 4100, host: '0.0.0.0' }), { protocol: 'http', host: '127.0.0.1', port: 4100 });
        assert.equal(probeTarget({ port: 3000, tls: { certPath: '/x' } }).protocol, 'https');
    });
});

test('probeTarget uses https when EENGINE_API_TLS is on, whatever the config file says', () => {
    withEnv({ EENGINE_API_TLS: 'true' }, () => assert.equal(probeTarget({ port: 3000 }).protocol, 'https'));
    withEnv({ EENGINE_API_TLS: 'false' }, () => assert.equal(probeTarget({ port: 3000, tls: {} }).protocol, 'http'));
});

test('probeTarget takes EENGINE_PORT over PORT over the config file', () => {
    withEnv({ EENGINE_PORT: '4200', PORT: '4300' }, () => assert.equal(probeTarget({ port: 4100 }).port, 4200));
    withEnv({ PORT: '4300' }, () => assert.equal(probeTarget({ port: 4100 }).port, 4300));
});

test('probeTarget probes a specific bind address directly and a wildcard over loopback', () => {
    withEnv({ EENGINE_HOST: '10.0.0.5' }, () => assert.equal(probeTarget({ host: '127.0.0.1' }).host, '10.0.0.5'));
    withEnv({ EENGINE_HOST: '::' }, () => assert.equal(probeTarget({}).host, '127.0.0.1'));
    withEnv({ EENGINE_HOST: '[::1]' }, () => assert.equal(probeTarget({}).host, '::1'));
});

test('probe reports a plain HTTP listener as live', async () => {
    const server = http.createServer(liveHandler);
    const port = await listen(server);
    try {
        assert.deepEqual(await probe({ protocol: 'http', host: '127.0.0.1', port }), { ok: true, statusCode: 200 });
    } finally {
        server.close();
    }
});

test('probe speaks HTTPS to a TLS listener, self-signed certificate included', async () => {
    const { cert, privateKey } = await createSelfSignedCertificate({ hostnames: ['emailengine.example.com'] });
    const server = https.createServer({ cert, key: privateKey }, liveHandler);
    const port = await listen(server);
    try {
        assert.deepEqual(await probe({ protocol: 'https', host: '127.0.0.1', port }), { ok: true, statusCode: 200 });

        // What the 2.86.0 image did: a plain request to the TLS socket never gets an answer
        const plain = await probe({ protocol: 'http', host: '127.0.0.1', port }, { timeout: 2000 });
        assert.equal(plain.ok, false);
    } finally {
        server.close();
    }
});

test('probe fails on a non-200 answer and on a closed port', async () => {
    const server = http.createServer((req, res) => {
        res.writeHead(503);
        res.end();
    });
    const port = await listen(server);
    try {
        assert.deepEqual(await probe({ protocol: 'http', host: '127.0.0.1', port }), { ok: false, statusCode: 503 });
    } finally {
        server.close();
    }
    const closed = await probe({ protocol: 'http', host: '127.0.0.1', port });
    assert.equal(closed.ok, false);
    assert.ok(closed.error);
});
