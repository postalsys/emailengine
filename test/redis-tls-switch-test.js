'use strict';

// EENGINE_REDIS_TLS_REJECT_UNAUTHORIZED relaxes certificate checks for the Redis connection alone.
// The Heroku manifest used to set NODE_TLS_REJECT_UNAUTHORIZED=0 instead, which turned verification
// off for every outbound connection of the instance (OAuth2 refreshes carrying the client secret,
// webhooks, IMAP and SMTP).

const test = require('node:test');
const assert = require('node:assert').strict;
const pathlib = require('path');
const { execFileSync } = require('child_process');

const ROOT = pathlib.join(__dirname, '..');

// lib/db.js connects as soon as it loads, so the probe reads the resolved options and exits before
// any connection attempt matters. Port 1 is never a Redis server.
function redisTls(env) {
    const stdout = execFileSync(
        process.execPath,
        [
            '-e',
            "const { REDIS_CONF } = require('./lib/db'); process.stdout.write('\\n@@' + JSON.stringify(REDIS_CONF.tls === undefined ? null : REDIS_CONF.tls) + '\\n'); process.exit(0);"
        ],
        {
            cwd: ROOT,
            encoding: 'utf-8',
            stdio: ['ignore', 'pipe', 'pipe'],
            env: Object.assign({ PATH: process.env.PATH, HOME: process.env.HOME, NODE_ENV: 'test', EE_ENV_LOADED: 'true', EENGINE_LOG_LEVEL: 'fatal' }, env)
        }
    );
    const line = stdout.split('\n').find(line => line.startsWith('@@'));
    return JSON.parse(line.slice(2));
}

test('a rediss:// connection verifies the server certificate by default', () => {
    assert.deepEqual(redisTls({ EENGINE_REDIS: 'rediss://127.0.0.1:1/0' }), {});
});

test('EENGINE_REDIS_TLS_REJECT_UNAUTHORIZED=false relaxes the Redis connection only', () => {
    for (const value of ['false', 'off', 'no', '0']) {
        assert.deepEqual(
            redisTls({ EENGINE_REDIS: 'rediss://127.0.0.1:1/0', EENGINE_REDIS_TLS_REJECT_UNAUTHORIZED: value }),
            { rejectUnauthorized: false },
            value
        );
    }
});

test('the switch does nothing for a plain redis:// connection or another value', () => {
    assert.equal(redisTls({ EENGINE_REDIS: 'redis://127.0.0.1:1/0', EENGINE_REDIS_TLS_REJECT_UNAUTHORIZED: 'false' }), null);
    assert.deepEqual(redisTls({ EENGINE_REDIS: 'rediss://127.0.0.1:1/0', EENGINE_REDIS_TLS_REJECT_UNAUTHORIZED: 'true' }), {});
});

test('the Heroku manifest no longer turns off certificate checks for the whole process', () => {
    const manifest = require('../app.json');
    assert.equal('NODE_TLS_REJECT_UNAUTHORIZED' in manifest.env, false);
    assert.equal(manifest.env.EENGINE_REDIS_TLS_REJECT_UNAUTHORIZED.value, 'false');
});

test('emailengine scan builds its Redis connection with the same switch', () => {
    const { applyRedisTlsSwitch } = require('../lib/redis-url');
    const saved = process.env.EENGINE_REDIS_TLS_REJECT_UNAUTHORIZED;
    process.env.EENGINE_REDIS_TLS_REJECT_UNAUTHORIZED = 'false';
    try {
        assert.deepEqual(applyRedisTlsSwitch({ tls: {} }), { tls: { rejectUnauthorized: false } });
        assert.deepEqual(applyRedisTlsSwitch({}), {});
    } finally {
        if (saved === undefined) {
            delete process.env.EENGINE_REDIS_TLS_REJECT_UNAUTHORIZED;
        } else {
            process.env.EENGINE_REDIS_TLS_REJECT_UNAUTHORIZED = saved;
        }
    }
    assert.match(require('fs').readFileSync(require('path').join(ROOT, 'scan.js'), 'utf-8'), /applyRedisTlsSwitch\(REDIS_CONF\)/);
});
