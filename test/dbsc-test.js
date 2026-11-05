'use strict';

// Device-bound admin sessions (lib/dbsc), driven the way Chrome drives them, against a real hapi
// server: the real cookie plugin and session strategy, the real bound cookie (iron-sealed through
// server.state), the real routes and extensions, Redis for the bindings and challenges, and ES256 /
// RS256 keys generated here standing in for the browser's hardware key. The header spellings are
// the ones Chrome 156 sends (bare values where the spec says quoted strings), observed 2026-11-05.
//
// Only the surroundings workers/api.js provides are stand-ins: the onRequest step that decides
// request.app.dbscEnabled and request.flash, a login route that mints a session the way
// setAdminSession() does, a page rendered through @hapi/vision, and an api-token-like scheme that
// marks its request as carrying the message browser's session token.

const test = require('node:test');
const assert = require('node:assert').strict;
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const pathlib = require('path');

const Hapi = require('@hapi/hapi');
const Cookie = require('@hapi/cookie');
const Vision = require('@hapi/vision');

const { redis } = require('../lib/db');
const { ADMIN_SESSION_MAX_AGE } = require('../lib/consts');
const { setupDbsc, registerDbscExtensions, endDeviceBinding } = require('../lib/dbsc');
const { createDbscStore, bindingKey, offerKey, failureKey, MAX_REFRESH_FAILURES } = require('../lib/dbsc/store');
const { BOUND_COOKIE, boundCookieSpec, boundCookieValid, readSfString } = require('../lib/dbsc/protocol');
const dbscRoutes = require('../lib/ui-routes/dbsc-routes');
const registerRedisTeardown = require('./helpers/redis-teardown');
const { createMockLogger } = require('./helpers/mock-logger');
const { browserKey, signProof } = require('./helpers/dbsc-keys');
const exitWhenStandalone = require('./helpers/exit-standalone');

const PASSWORD = crypto.randomBytes(32).toString('hex');
const sids = new Set();

let server;
let dbscEnabled = true;
let templates;
const logger = createMockLogger();

registerRedisTeardown(redis, async () => {
    if (server) {
        await server.stop();
    }
    for (const sid of sids) {
        await redis.del(bindingKey(sid), offerKey(sid), failureKey(sid));
    }
    if (templates) {
        fs.rmSync(templates, { recursive: true, force: true });
    }
});

// --- the browser side ---------------------------------------------------------------------------

// A minimal cookie jar: name -> value, updated from each response
function jar(initial = {}) {
    const cookies = Object.assign({}, initial);
    return {
        cookies,
        header: () =>
            Object.entries(cookies)
                .map(([name, value]) => `${name}=${value}`)
                .join('; '),
        take(res) {
            for (const line of [].concat(res.headers['set-cookie'] || [])) {
                const [pair] = line.split(';');
                const name = pair.slice(0, pair.indexOf('='));
                const value = pair.slice(pair.indexOf('=') + 1);
                if (!value || /max-age=0/i.test(line)) {
                    delete cookies[name];
                } else {
                    cookies[name] = value;
                }
            }
            return res;
        }
    };
}

async function inject(browser, method, url, headers = {}) {
    return browser.take(await server.inject({ method, url, headers: Object.assign({ cookie: browser.header() }, headers) }));
}

async function signIn(extra = {}) {
    const browser = jar();
    const sid = crypto.randomBytes(32).toString('hex');
    sids.add(sid);
    await inject(browser, 'POST', `/test/login?sid=${sid}&totp=${extra.requireTotp ? 1 : 0}`);
    return { browser, sid };
}

const registrationChallenge = res => {
    const header = res.headers['secure-session-registration'];
    assert.ok(header, 'the page offers registration');
    return header.match(/challenge="([^"]+)"/)[1];
};

// Signs in, loads a page, and registers with the challenge it was offered
async function boundSession(alg = 'ES256') {
    const session = await signIn();
    const key = browserKey(alg);
    const challenge = registrationChallenge(await inject(session.browser, 'GET', '/admin'));
    const res = await inject(session.browser, 'POST', '/admin/dbsc/start', { 'secure-session-response': signProof(key, challenge, { registration: true }) });
    assert.equal(res.statusCode, 200, res.payload);
    return Object.assign(session, { key, id: res.result.session_identifier, registration: res });
}

async function refresh(session, headers) {
    return await inject(session.browser, 'POST', '/admin/dbsc/refresh', Object.assign({ 'sec-secure-session-id': session.id }, headers));
}

// --- the server ---------------------------------------------------------------------------------

test.before(async () => {
    templates = fs.mkdtempSync(pathlib.join(os.tmpdir(), 'ee-dbsc-views-'));
    fs.writeFileSync(pathlib.join(templates, 'page.html'), '<html>page</html>');

    server = Hapi.server();
    await server.register([Cookie, Vision]);
    server.views({ engines: { html: { compile: source => () => source } }, path: templates });

    server.auth.strategy('session', 'cookie', {
        cookie: { name: 'ee', password: PASSWORD, isSecure: false, path: '/', isSameSite: 'Lax' },
        validate: async (request, session) => ({ isValid: !session.ended, credentials: { user: 'admin' } })
    });
    server.auth.default('session');

    // Stands in for the api-token strategy accepting the message browser's session token
    server.auth.scheme('session-token', () => ({
        authenticate: (request, h) => {
            request.app.sessionToken = true;
            return h.authenticated({ credentials: {} });
        }
    }));
    server.auth.strategy('session-token', 'session-token');

    server.ext('onRequest', (request, h) => {
        request.app.dbscEnabled = dbscEnabled;
        request.app.ip = '127.0.0.1';
        request.flash = async () => {};
        return h.continue;
    });

    setupDbsc(server, { redis, logger, secure: false, password: PASSWORD });
    dbscRoutes({ server });
    registerDbscExtensions(server);

    server.route([
        {
            method: 'POST',
            path: '/test/login',
            options: { auth: false },
            handler(request, h) {
                request.cookieAuth.set({ sid: request.query.sid, user: 'admin', issuedAt: Date.now(), requireTotp: request.query.totp === '1' });
                return h.response('ok');
            }
        },
        { method: 'GET', path: '/admin', handler: (request, h) => h.view('page') },
        { method: 'GET', path: '/admin/data', handler: () => ({ ok: true }) },
        {
            method: 'GET',
            path: '/admin/logout',
            async handler(request, h) {
                await endDeviceBinding(request, h);
                request.cookieAuth.clear();
                return h.response('bye');
            }
        },
        { method: 'GET', path: '/v1/account/test/messages', options: { auth: 'session-token' }, handler: () => ({ messages: [] }) }
    ]);

    await server.initialize();
});

test.beforeEach(() => {
    dbscEnabled = true;
});

test('registration', async t => {
    await t.test('a signed-in page offers registration, at most once a minute', async () => {
        const { browser } = await signIn();
        const first = await inject(browser, 'GET', '/admin');
        assert.match(first.headers['secure-session-registration'], /^\(ES256 RS256\);path="\/admin\/dbsc\/start";challenge="[A-Za-z0-9_-]+"$/);

        const second = await inject(browser, 'GET', '/admin');
        assert.equal(second.headers['secure-session-registration'], undefined, 'a browser that did not register is not asked on every page');
    });

    await t.test('nothing is offered with the feature off, to a session owing its second factor, or outside a page', async () => {
        dbscEnabled = false;
        const off = await signIn();
        assert.equal((await inject(off.browser, 'GET', '/admin')).headers['secure-session-registration'], undefined);

        dbscEnabled = true;
        const totp = await signIn({ requireTotp: true });
        assert.equal((await inject(totp.browser, 'GET', '/admin')).headers['secure-session-registration'], undefined);

        const json = await signIn();
        assert.equal((await inject(json.browser, 'GET', '/admin/data')).headers['secure-session-registration'], undefined);
    });

    for (const alg of ['ES256', 'RS256']) {
        await t.test(`an ${alg} proof over the offered challenge binds the session`, async () => {
            const session = await boundSession(alg);
            const res = session.registration;

            assert.match(session.id, /^[0-9a-f]{32}$/);
            assert.equal(res.result.scope.include_site, false);
            assert.equal(res.result.scope.origin, undefined, 'the scope defaults to the origin the browser registered on');
            assert.equal(res.result.refresh_url, '/admin/dbsc/refresh');
            assert.ok(session.browser.cookies[BOUND_COOKIE], 'the response sets the bound cookie');

            // The browser only accepts the session when the cookie it is sent matches the attributes
            // it registered, so the two have to come from one place
            const [credential] = res.result.credentials;
            assert.deepEqual(credential, { type: 'cookie', name: BOUND_COOKIE, attributes: 'Path=/; HttpOnly; SameSite=Lax' });
            const setCookie = [].concat(res.headers['set-cookie']).find(line => line.startsWith(`${BOUND_COOKIE}=`));
            for (const attribute of credential.attributes.split('; ')) {
                assert.ok(setCookie.includes(attribute), `${attribute} is on the cookie: ${setCookie}`);
            }
            assert.ok(!/Domain=/i.test(setCookie), 'host-only, like the session cookie');

            const stored = JSON.parse(await redis.get(bindingKey(session.sid)));
            assert.equal(stored.alg, alg);
            assert.equal(stored.id, session.id);
            assert.equal(stored.jwk.d, undefined);
            const ttl = await redis.ttl(bindingKey(session.sid));
            assert.ok(ttl > 0 && ttl <= ADMIN_SESSION_MAX_AGE / 1000, 'the binding lives as long as the session can');
        });
    }

    await t.test('a spent, foreign or missing challenge is refused', async () => {
        const session = await signIn();
        const key = browserKey();
        const challenge = registrationChallenge(await inject(session.browser, 'GET', '/admin'));

        const other = await signIn();
        const foreign = await inject(other.browser, 'POST', '/admin/dbsc/start', {
            'secure-session-response': signProof(key, challenge, { registration: true })
        });
        assert.equal(foreign.statusCode, 400, 'a challenge minted for another session');

        // The foreign attempt spent it
        const spent = await inject(session.browser, 'POST', '/admin/dbsc/start', {
            'secure-session-response': signProof(key, challenge, { registration: true })
        });
        assert.equal(spent.statusCode, 400);

        const missing = await inject(session.browser, 'POST', '/admin/dbsc/start');
        assert.equal(missing.statusCode, 400);
        assert.equal(await redis.exists(bindingKey(session.sid)), 0);
    });

    await t.test('a session is bound once: a second key cannot replace the first', async () => {
        const session = await boundSession();
        // A bound browser is not offered again, and a copied cookie used elsewhere is refused before
        // it gets that far, so the second attempt here uses a challenge minted directly
        const challenge = await createDbscStore(redis).mintChallenge(session.sid, 'register');
        const res = await inject(session.browser, 'POST', '/admin/dbsc/start', {
            'secure-session-response': signProof(browserKey(), challenge, { registration: true })
        });
        assert.equal(res.statusCode, 409);
        assert.equal(JSON.parse(await redis.get(bindingKey(session.sid))).id, session.id);
    });

    await t.test('a quoted header value is read like the bare one Chrome sends', async () => {
        const session = await signIn();
        const key = browserKey();
        const challenge = registrationChallenge(await inject(session.browser, 'GET', '/admin'));
        const res = await inject(session.browser, 'POST', '/admin/dbsc/start', {
            'secure-session-response': `"${signProof(key, challenge, { registration: true })}"`
        });
        assert.equal(res.statusCode, 200);
    });

    await t.test('registration needs the feature and a signed-in session', async () => {
        dbscEnabled = false;
        const session = await signIn();
        assert.equal((await inject(session.browser, 'POST', '/admin/dbsc/start')).statusCode, 404);

        dbscEnabled = true;
        assert.equal((await server.inject({ method: 'POST', url: '/admin/dbsc/start' })).statusCode, 401);
    });
});

test('enforcement', async t => {
    await t.test('a bound session without its bound cookie is signed out', async () => {
        const session = await boundSession();
        assert.equal((await inject(session.browser, 'GET', '/admin')).statusCode, 200, 'with it, pages load');

        const copied = jar({ ee: session.browser.cookies.ee });
        const res = await inject(copied, 'GET', '/admin?x=1');
        assert.equal(res.statusCode, 302);
        assert.equal(res.headers.location, `/admin/login?next=${encodeURIComponent('/admin?x=1')}`);
        assert.equal(copied.cookies.ee, undefined, 'the session cookie is cleared');
        assert.ok(logger.entries.some(entry => entry.msg === 'Refused a device-bound admin session without its bound credential'));

        // The binding stays, so the same cookie keeps being refused wherever it is replayed
        assert.equal(await redis.exists(bindingKey(session.sid)), 1);
        assert.equal((await inject(jar({ ee: session.browser.cookies.ee }), 'GET', '/admin')).statusCode, 302);
    });

    await t.test("the message browser's session token is held to the same rule", async () => {
        const session = await boundSession();
        assert.equal((await inject(session.browser, 'GET', '/v1/account/test/messages')).statusCode, 200);
        assert.equal((await inject(jar({ ee: session.browser.cookies.ee }), 'GET', '/v1/account/test/messages')).statusCode, 401);
    });

    await t.test('a bound cookie of another session does not count', async () => {
        const first = await boundSession();
        const second = await boundSession();
        const mixed = jar({ ee: second.browser.cookies.ee, [BOUND_COOKIE]: first.browser.cookies[BOUND_COOKIE] });
        assert.equal((await inject(mixed, 'GET', '/admin')).statusCode, 302);
    });

    await t.test('an unbound session, and every session with the feature off, works as before', async () => {
        const unbound = await signIn();
        assert.equal((await inject(unbound.browser, 'GET', '/admin/data')).statusCode, 200);

        const session = await boundSession();
        dbscEnabled = false;
        assert.equal((await inject(jar({ ee: session.browser.cookies.ee }), 'GET', '/admin/data')).statusCode, 200, 'switching it off locks nobody out');
    });

    await t.test('logout ends the session everywhere, and the binding stays to say so', async () => {
        const session = await boundSession();
        const copied = session.browser.cookies.ee;
        const ttlBefore = await redis.ttl(bindingKey(session.sid));

        await inject(session.browser, 'GET', '/admin/logout');
        assert.equal(session.browser.cookies[BOUND_COOKIE], undefined);

        // Deleting the binding would let a copy of the session cookie pass as an unbound session
        // after the owner signed out, and let its holder bind a key of their own
        const stored = JSON.parse(await redis.get(bindingKey(session.sid)));
        assert.ok(stored.ended, 'the binding is marked ended');
        assert.ok((await redis.ttl(bindingKey(session.sid))) > ttlBefore - 5, 'and keeps its lifetime');

        const thief = jar({ ee: copied });
        assert.equal((await inject(thief, 'GET', '/admin/data')).statusCode, 302, 'a copied cookie is still refused');
        assert.equal((await inject(jar({ ee: copied }), 'GET', '/v1/account/test/messages')).statusCode, 401);

        const challenge = await createDbscStore(redis).mintChallenge(session.sid, 'register');
        const rebind = await inject(jar({ ee: copied }), 'POST', '/admin/dbsc/start', {
            'secure-session-response': signProof(browserKey(), challenge, { registration: true })
        });
        assert.notEqual(rebind.statusCode, 200, 'no key can be bound to the ended session');
        assert.ok(JSON.parse(await redis.get(bindingKey(session.sid))).ended);
    });

    await t.test('the refresh of an ended session is told to stop', async () => {
        const session = await boundSession();
        await createDbscStore(redis).endBinding(session.sid);
        assert.deepEqual((await refresh(session)).result, { continue: false });
    });
});

test('refresh', async t => {
    await t.test('a challenge, then a proof over it, renews the bound cookie', async () => {
        const session = await boundSession();
        delete session.browser.cookies[BOUND_COOKIE];

        const challenged = await refresh(session);
        assert.equal(challenged.statusCode, 403);
        const [, challenge, id] = challenged.headers['secure-session-challenge'].match(/^"([^"]+)";id="([^"]+)"$/);
        assert.equal(id, session.id, 'the challenge names the session, or the browser does not cache it');

        const renewed = await refresh(session, { 'secure-session-response': signProof(session.key, challenge) });
        assert.equal(renewed.statusCode, 200);
        assert.equal(renewed.payload, '', 'an empty answer keeps the session as registered');
        assert.ok(session.browser.cookies[BOUND_COOKIE]);
        assert.equal((await inject(session.browser, 'GET', '/admin')).statusCode, 200);
    });

    await t.test('a reused challenge is answered with a fresh one, as Chrome expects', async () => {
        const session = await boundSession();
        const [, challenge] = (await refresh(session)).headers['secure-session-challenge'].match(/^"([^"]+)"/);
        assert.equal((await refresh(session, { 'secure-session-response': signProof(session.key, challenge) })).statusCode, 200);

        // Chrome signs its proactive refreshes over the challenge it cached
        const again = await refresh(session, { 'secure-session-response': signProof(session.key, challenge) });
        assert.equal(again.statusCode, 403);
        assert.ok(again.headers['secure-session-challenge']);
    });

    await t.test('a proof from another key is refused, and after a few the browser is told to stop', async () => {
        const session = await boundSession();
        const stranger = browserKey();
        let res;
        for (let i = 0; i <= MAX_REFRESH_FAILURES; i++) {
            const [, challenge] = (await refresh(session)).headers['secure-session-challenge'].match(/^"([^"]+)"/);
            res = await refresh(session, { 'secure-session-response': signProof(stranger, challenge, { registration: true }) });
            if (i < MAX_REFRESH_FAILURES) {
                assert.equal(res.statusCode, 403, `attempt ${i + 1} gets another chance`);
            }
        }
        assert.equal(res.statusCode, 401, 'a 4xx other than 403 ends the session in the browser');
    });

    await t.test('an ended, unknown or switched-off session is told to stop in a body the browser reads', async () => {
        const session = await boundSession();
        const stop = { continue: false };

        assert.deepEqual((await refresh(session, { 'sec-secure-session-id': 'not-this-one' })).result, stop);
        assert.deepEqual((await inject(jar(), 'POST', '/admin/dbsc/refresh', { 'sec-secure-session-id': session.id })).result, stop, 'no session cookie');

        dbscEnabled = false;
        const off = await refresh(session);
        assert.equal(off.statusCode, 200);
        assert.deepEqual(off.result, stop);
    });

    await t.test('the refresh route itself is never refused for a missing bound cookie', async () => {
        const session = await boundSession();
        delete session.browser.cookies[BOUND_COOKIE];
        assert.equal((await refresh(session)).statusCode, 403, 'a challenge, not a redirect to the login page');
    });
});

test('the bound cookie settings', () => {
    const plain = boundCookieSpec({ secure: false, password: PASSWORD });
    const secure = boundCookieSpec({ secure: true, password: PASSWORD });
    assert.equal(plain.attributes, 'Path=/; HttpOnly; SameSite=Lax');
    assert.equal(secure.attributes, 'Path=/; HttpOnly; SameSite=Lax; Secure');
    assert.equal(secure.state.isSecure, true);
    assert.equal(secure.state.encoding, 'iron', 'sealed, so a bound cookie cannot be written by hand');
    assert.ok(secure.state.ttl <= 10 * 60 * 1000);
});

test('reading the protocol values', async t => {
    await t.test('a bound cookie counts only for its own session and only until it runs out', () => {
        const now = Date.now();
        assert.equal(boundCookieValid({ sid: 's1', exp: now + 1000 }, 's1', now), true);
        assert.equal(boundCookieValid({ sid: 's1', exp: now - 1 }, 's1', now), false, 'a copy outlives its cookie lifetime on disk, not here');
        assert.equal(boundCookieValid({ sid: 's2', exp: now + 1000 }, 's1', now), false);
        assert.equal(boundCookieValid(undefined, 's1', now), false);
        assert.equal(boundCookieValid({ sid: 's1', exp: now + 1000 }, undefined, now), false);
    });

    await t.test('header strings, quoted or bare', () => {
        assert.equal(readSfString('abc.def-_'), 'abc.def-_');
        assert.equal(readSfString('"abc"'), 'abc');
        assert.equal(readSfString('  "abc"  '), 'abc');
        for (const value of [undefined, '', '""', '"', 'has space', 'a"b', 'semi;colon', '"abc";x=1']) {
            assert.equal(readSfString(value), null, String(value));
        }
    });
});

exitWhenStandalone();
