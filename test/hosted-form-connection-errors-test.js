'use strict';

// POST /accounts/new/imap/test, the hosted form's connection check: the error codes of the IMAP and
// SMTP checks are translated into messages the person at the form can act on. Driven through the
// real route handler with verifyAccountInfo stood in, so every code reaches the translation without
// a real server. The integration tier only covers the signature gate and a refused connection.

process.env.EENGINE_SECRET = process.env.EENGINE_SECRET || 'hosted-form-connection-errors-test-secret';

const test = require('node:test');
const assert = require('node:assert').strict;
const crypto = require('node:crypto');

const tools = require('../lib/tools');
const { redis } = require('../lib/db');
const { REDIS_PREFIX, NONCE_BYTES } = require('../lib/consts');
const registerRedisTeardown = require('./helpers/redis-teardown');

const RUN = crypto.randomBytes(6).toString('hex');
const SECRET = 'hosted-form-connection-errors-test-service-secret';

registerRedisTeardown(redis, async () => {
    let cursor = '0';
    do {
        let [next, keys] = await redis.scan(cursor, 'MATCH', `${REDIS_PREFIX}*${RUN}*`, 'COUNT', 1000);
        cursor = next;
        if (keys.length) {
            await redis.del(...keys);
        }
    } while (cursor !== '0');
});

// The route module reads verifyAccountInfo off lib/tools when it loads, so the stand-in has to be
// in place first; each test sets what it answers
let verifyAnswer = null;
const verifyCalls = [];
tools.verifyAccountInfo = async (redisClient, accountData) => {
    verifyCalls.push(accountData);
    return typeof verifyAnswer === 'function' ? verifyAnswer() : verifyAnswer;
};
tools.getServiceSecret = async () => SECRET;

const logger = { trace() {}, debug() {}, info() {}, warn() {}, error() {}, child: () => logger };

const routes = [];
const server = new Proxy(
    { route: cfg => routes.push(...[].concat(cfg)), auth: { settings: { default: 'session' }, default() {} } },
    { get: (target, prop) => (prop in target ? target[prop] : () => {}) }
);
require('../lib/ui-routes/account-routes')({ server, call: async () => ({}) });
const route = routes.find(cfg => cfg.path === '/accounts/new/imap/test' && [].concat(cfg.method).includes('POST'));

// Marks every translated string, so a message that was not passed through gettext shows
const gt = { gettext: text => `T(${text})` };

function makeRequest(payload) {
    const n = crypto.randomBytes(NONCE_BYTES).toString('base64url') + RUN;
    const { data, signature } = tools.getSignedFormDataSync(SECRET, { n, t: Date.now() }, true);
    return {
        payload: Object.assign({ data, sig: signature }, payload),
        headers: {},
        logger,
        app: { gt, ip: '198.51.100.23' }
    };
}

const check = async (imap, smtp) => {
    verifyAnswer = { imap, smtp };
    return await route.handler(makeRequest({ imap_host: 'imap.example.com', smtp_host: 'smtp.example.com' }));
};

const IMAP_CASES = {
    ENOTFOUND: 'T(Server hostname was not found)',
    EAI_AGAIN: 'T(Server hostname was not found)',
    AUTHENTICATIONFAILED: 'T(Invalid username or password)',
    ETIMEDOUT: 'T(Connection timed out)',
    ETIMEOUT: 'T(Connection timed out)',
    GREETING_TIMEOUT: 'T(Connection timed out)',
    ECONNREFUSED: 'T(Could not connect to server)',
    ECONNRESET: 'T(Could not connect to server)',
    EHOSTUNREACH: 'T(Could not connect to server)',
    ENETUNREACH: 'T(Could not connect to server)',
    ClosedAfterConnectTLS: 'T(The server unexpectedly closed the connection.)',
    ClosedAfterConnectText:
        'T(The server unexpectedly closed the connection. This usually happens when attempting to connect to a TLS port without TLS enabled.)',
    EPROTO: 'T(TLS protocol error)',
    ERR_TLS_CERT_ALTNAME_INVALID: 'T(TLS protocol error)',
    ERR_SSL_WRONG_VERSION_NUMBER: 'T(TLS protocol error)',
    CERT_HAS_EXPIRED: 'T(TLS protocol error)',
    DEPTH_ZERO_SELF_SIGNED_CERT: 'T(TLS protocol error)',
    SELF_SIGNED_CERT_IN_CHAIN: 'T(TLS protocol error)',
    UNABLE_TO_VERIFY_LEAF_SIGNATURE: 'T(TLS protocol error)'
};

const SMTP_CASES = {
    EDNS: 'T(Server hostname was not found)',
    EAUTH: 'T(Invalid username or password)',
    ENOAUTH: 'T(Authentication credentials were not provided)',
    EOAUTH2: 'T(OAuth2 authentication failed)',
    ETLS: 'T(TLS protocol error)',
    ETIMEDOUT: 'T(Connection timed out)',
    ECONNECTION: 'T(Could not connect to server)',
    EPROTOCOL: 'T(Unexpected server response)'
};

test('hosted form connection check: error translations', async t => {
    assert.ok(route, 'POST /accounts/new/imap/test is registered');

    for (const [code, message] of Object.entries(IMAP_CASES)) {
        await t.test(`IMAP ${code}`, async () => {
            const res = await check({ success: false, error: 'raw socket text', code }, { success: true });
            assert.equal(res.imap.error, message);
            assert.equal(res.imap.code, code);
            assert.deepEqual(res.smtp, { success: true });
        });
    }

    for (const [code, message] of Object.entries(SMTP_CASES)) {
        await t.test(`SMTP ${code}`, async () => {
            const res = await check({ success: true }, { success: false, error: 'raw smtp text', code });
            assert.equal(res.smtp.error, message);
            assert.equal(res.smtp.code, code);
            assert.deepEqual(res.imap, { success: true });
        });
    }

    await t.test('an unknown IMAP code keeps its text unless it reads as an OpenSSL error', async () => {
        assert.equal((await check({ error: 'Something odd', code: 'EWHATEVER' })).imap.error, 'Something odd');
        assert.equal((await check({ error: 'error:0A00010B:SSL routines::wrong version number', code: 'EWHATEVER' })).imap.error, 'T(TLS protocol error)');
        assert.equal((await check({ error: 'OpenSSL failure', code: 'EWHATEVER' })).imap.error, 'T(TLS protocol error)');
    });

    await t.test('an SMTP socket error is translated only when it names OpenSSL, case-sensitively', async () => {
        assert.equal((await check(null, { error: 'routines:openssl:bad', code: 'ESOCKET' })).smtp.error, 'T(TLS protocol error)');
        assert.equal((await check(null, { error: 'OpenSSL failure', code: 'ESOCKET' })).smtp.error, 'OpenSSL failure');
        assert.equal((await check(null, { error: 'Socket closed', code: 'ESOCKET' })).smtp.error, 'Socket closed');
    });

    await t.test('an unknown SMTP code and the IMAP-only codes keep their text on SMTP', async () => {
        assert.equal((await check(null, { error: 'raw', code: 'EWHATEVER' })).smtp.error, 'raw');
        assert.equal((await check(null, { error: 'raw', code: 'ENOTFOUND' })).smtp.error, 'raw');
        assert.equal((await check(null, { error: 'error:0A00010B:SSL routines', code: 'ECONNREFUSED' })).smtp.error, 'error:0A00010B:SSL routines');
    });

    await t.test('the SMTP-only codes keep their text on IMAP', async () => {
        assert.equal((await check({ error: 'raw', code: 'EAUTH' })).imap.error, 'raw');
        assert.equal((await check({ error: 'raw', code: 'EDNS' })).imap.error, 'raw');
    });

    await t.test('nothing is translated without both an error and a code', async () => {
        assert.deepEqual(await check({ error: 'raw' }, { error: 'raw' }), { imap: { error: 'raw' }, smtp: { error: 'raw' } });
        assert.deepEqual(await check({ code: 'ENOTFOUND' }, { code: 'EDNS' }), { imap: { code: 'ENOTFOUND' }, smtp: { code: 'EDNS' } });
        assert.deepEqual(await check({ error: '', code: 'ENOTFOUND' }, { error: '', code: 'EDNS' }), {
            imap: { error: '', code: 'ENOTFOUND' },
            smtp: { error: '', code: 'EDNS' }
        });
    });

    await t.test('an empty verify result is returned as is', async () => {
        verifyAnswer = null;
        assert.equal(await route.handler(makeRequest({})), null);
        verifyAnswer = false;
        assert.equal(await route.handler(makeRequest({})), false);
    });

    await t.test('both sides are translated in one answer', async () => {
        const res = await check({ error: 'x', code: 'AUTHENTICATIONFAILED' }, { error: 'y', code: 'EAUTH' });
        assert.equal(res.imap.error, 'T(Invalid username or password)');
        assert.equal(res.smtp.error, 'T(Invalid username or password)');
    });

    await t.test('the signature gate runs before any connection is attempted', async () => {
        verifyCalls.length = 0;
        verifyAnswer = { imap: { success: true } };
        await assert.rejects(
            route.handler({ payload: { data: 'x', sig: 'bad', imap_host: 'imap.example.com' }, headers: {}, logger, app: { gt, ip: '198.51.100.23' } }),
            err => err.isBoom && err.output.statusCode === 403
        );
        assert.equal(verifyCalls.length, 0);
    });

    await t.test('the payload reaches the connection check field for field', async () => {
        verifyCalls.length = 0;
        verifyAnswer = { imap: { success: true } };
        await route.handler(
            makeRequest({
                imap_host: 'imap.example.com',
                imap_port: 993,
                imap_secure: true,
                imap_disabled: false,
                imap_auth_user: 'iu',
                imap_auth_pass: 'ip',
                smtp_host: 'smtp.example.com',
                smtp_port: 465,
                smtp_secure: true,
                smtp_auth_user: 'su',
                smtp_auth_pass: 'sp'
            })
        );
        assert.deepEqual(verifyCalls, [
            {
                imap: { host: 'imap.example.com', port: 993, secure: true, disabled: false, auth: { user: 'iu', pass: 'ip' } },
                smtp: { host: 'smtp.example.com', port: 465, secure: true, auth: { user: 'su', pass: 'sp' } }
            }
        ]);
    });

    await t.test('a failure of the check itself becomes a Boom error carrying its code', async () => {
        verifyAnswer = () => {
            throw Object.assign(new Error('boom'), { code: 'EFAIL', statusCode: 502 });
        };
        await assert.rejects(route.handler(makeRequest({})), err => {
            assert.equal(err.output.statusCode, 502);
            assert.equal(err.output.payload.code, 'EFAIL');
            return true;
        });
    });
});
