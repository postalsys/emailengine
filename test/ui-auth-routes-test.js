'use strict';

// The admin sign-in routes of lib/ui-routes/auth-routes.js, driven through their real handlers
// with a fake request and toolkit: the second-factor step (failure budgets, the session ended
// after repeated failures, single-use codes), the password change (every session and every
// passkey ends with the old password) and passkey registration (the password is demanded again
// at the step that stores the credential). Settings and passkey storage are stubbed; the rate
// limit counters and the used-code markers are real Redis keys, each under a user name unique to
// the run and removed afterwards.

const test = require('node:test');
const assert = require('node:assert').strict;
const crypto = require('node:crypto');

const pbkdf2 = require('../lib/pbkdf2-phc');
const settings = require('../lib/settings');
const passkeys = require('../lib/passkeys');
const { isEndedSession } = require('../lib/tools');
const { redis } = require('../lib/db');
const { REDIS_PREFIX, PDKDF2_ITERATIONS } = require('../lib/consts');
const registerRedisTeardown = require('./helpers/redis-teardown');
const authRoutes = require('../lib/ui-routes/auth-routes');

const RUN = crypto.randomBytes(6).toString('hex');

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

function captureAuthRoutes({ defaultAuth = 'session' } = {}) {
    const routes = [];
    const server = {
        route: cfg => routes.push(...[].concat(cfg)),
        auth: { settings: { default: defaultAuth }, default() {} },
        decorate() {},
        ext() {}
    };
    authRoutes({ server });
    return (method, path) => routes.find(cfg => cfg.path === path && [].concat(cfg.method).includes(method));
}

const route = captureAuthRoutes();

const logger = { trace() {}, debug() {}, info() {}, warn() {}, error() {} };

function makeToolkit() {
    const answers = { views: [], redirects: [], responses: [] };
    return {
        answers,
        async checkRateLimit() {
            return { success: true };
        },
        view(template, context) {
            answers.views.push({ template, context });
            return { template, context };
        },
        redirect(url) {
            answers.redirects.push(url);
            return { redirect: url };
        },
        response(body) {
            const res = { body, statusCode: 200 };
            res.code = code => {
                res.statusCode = code;
                return res;
            };
            answers.responses.push(res);
            return res;
        }
    };
}

function makeRequest({ user, sid, payload, artifacts } = {}) {
    const flashes = [];
    const cookie = { cleared: [], set: [] };
    return {
        flashes,
        cookie,
        auth: {
            isAuthenticated: true,
            credentials: { user },
            artifacts: Object.assign({ requireTotp: true, sid }, artifacts)
        },
        payload,
        logger,
        app: { ip: '192.0.2.1' },
        async flash(message) {
            flashes.push(message);
        },
        cookieAuth: {
            clear(key) {
                cookie.cleared.push(key === undefined ? '*' : key);
            },
            set(key, value) {
                cookie.set.push([key, value]);
            },
            ttl() {}
        }
    };
}

// The current RFC 6238 code for a seed (SHA-1, six digits, 30 second step), as lib/totp.js
// computes it
function currentCode(seed, offset = 0) {
    const counter = Buffer.alloc(8);
    counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000) + offset));
    const digest = crypto.createHmac('sha1', Buffer.from(seed)).update(counter).digest();
    const pos = digest[digest.length - 1] & 0x0f;
    return ((digest.readUInt32BE(pos) & 0x7fffffff) % 1e6).toString().padStart(6, '0');
}

// A code that does not verify: one far outside the accepted window
const wrongCode = seed => {
    const valid = new Set([-1, 0, 1].map(offset => currentCode(seed, offset)));
    for (let i = 0; ; i++) {
        const code = String(i).padStart(6, '0');
        if (!valid.has(code)) {
            return code;
        }
    }
};

test('admin sign-in routes', async t => {
    const originalGet = settings.get;
    const originalSet = settings.set;
    const seed = 'abcDEF123ghiJKL456mn';
    let stored = {};
    const written = [];

    t.beforeEach(() => {
        stored = { totpSeed: seed };
        written.length = 0;
        settings.get = async key => stored[key];
        settings.set = async (key, value) => {
            written.push([key, value]);
            stored[key] = value;
            return 1;
        };
    });

    t.afterEach(() => {
        settings.get = originalGet;
        settings.set = originalSet;
    });

    const totpPost = route('POST', '/admin/totp');

    await t.test('a valid code signs in once and cannot be replayed', async () => {
        const user = `totp-reuse-${RUN}`;
        const code = currentCode(seed);

        const h1 = makeToolkit();
        const r1 = makeRequest({ user, sid: `s1-${RUN}`, payload: { type: 'totp', code } });
        await totpPost.handler(r1, h1);
        assert.deepEqual(h1.answers.redirects, ['/admin']);
        assert.deepEqual(r1.cookie.cleared, ['requireTotp']);

        // The same code again, from another password-stage session: the marker is per user and
        // code, and it outlives any bucket boundary
        const h2 = makeToolkit();
        const r2 = makeRequest({ user, sid: `s2-${RUN}`, payload: { type: 'totp', code } });
        await totpPost.handler(r2, h2);
        assert.deepEqual(h2.answers.redirects, []);
        assert.equal(h2.answers.views[0].template, 'account/totp');
        assert.match(r2.flashes[0].message, /already been used|already used/);
        assert.deepEqual(r2.cookie.cleared, [], 'the second factor was not cleared');

        const ttl = await redis.ttl(`${REDIS_PREFIX}totp:used:${user}:${code}`);
        assert.ok(ttl > 0 && ttl <= 720, `single-use marker with a TTL, saw ${ttl}`);
    });

    await t.test('repeated failed codes end the password-stage session', async () => {
        const user = `totp-session-${RUN}`;
        const sid = `sess-${RUN}`;
        const bad = wrongCode(seed);

        for (let i = 1; i <= 4; i++) {
            const h = makeToolkit();
            const request = makeRequest({ user, sid, payload: { type: 'totp', code: bad } });
            await totpPost.handler(request, h);
            assert.equal(h.answers.views.length, 1, `failure ${i} re-renders the form`);
            assert.deepEqual(request.cookie.cleared, []);
        }

        const h = makeToolkit();
        const request = makeRequest({ user, sid, payload: { type: 'totp', code: bad, next: '/admin/accounts' } });
        await totpPost.handler(request, h);
        assert.deepEqual(request.cookie.cleared, ['*'], 'the whole session cookie is cleared');
        assert.deepEqual(h.answers.redirects, ['/admin/login?next=%2Fadmin%2Faccounts']);
    });

    await t.test('the hourly failure budget locks the second factor, even for a valid code', async () => {
        const user = `totp-budget-${RUN}`;
        const bad = wrongCode(seed);

        // A fresh session for every guess, so only the per-user budget is in play
        for (let i = 0; i < 20; i++) {
            const request = makeRequest({ user, sid: `b${i}-${RUN}`, payload: { type: 'totp', code: bad } });
            await totpPost.handler(request, makeToolkit());
        }

        const h = makeToolkit();
        const request = makeRequest({ user, sid: `bfinal-${RUN}`, payload: { type: 'totp', code: currentCode(seed) } });
        await totpPost.handler(request, h);
        assert.deepEqual(h.answers.redirects, [], 'not signed in');
        assert.match(request.flashes[0].message, /Too many failed codes/);
        assert.deepEqual(request.cookie.cleared, []);

        // Another user is unaffected
        const other = makeToolkit();
        await totpPost.handler(makeRequest({ user: `totp-other-${RUN}`, sid: `o-${RUN}`, payload: { type: 'totp', code: currentCode(seed) } }), other);
        assert.deepEqual(other.answers.redirects, ['/admin']);
    });

    await t.test('a password change ends every other session and removes every passkey', async () => {
        const originalDelete = passkeys.deleteAllCredentials;
        const deleted = [];
        passkeys.deleteAllCredentials = async user => {
            deleted.push(user);
            return 2;
        };
        try {
            stored.authData = { user: 'admin', password: await pbkdf2.hash('old-password', { iterations: 1000 }), passwordVersion: 1 };

            const h = makeToolkit();
            const request = makeRequest({
                user: 'admin',
                sid: `pw-${RUN}`,
                payload: { password0: 'old-password', password: 'new-password-123', password2: 'new-password-123' },
                artifacts: { requireTotp: false, passwordVersion: 1 }
            });
            await route('POST', '/admin/account/password').handler(request, h);

            const saved = written.find(([key]) => key === 'authData')[1];
            assert.notEqual(saved.passwordVersion, 1, 'the password version moved');
            assert.ok(await pbkdf2.verify(saved.password, 'new-password-123'));
            assert.equal(isEndedSession(saved.passwordVersion, { passwordVersion: 1 }), true, 'a session stamped with the old version is over');
            assert.deepEqual(request.cookie.set, [['passwordVersion', saved.passwordVersion]], 'the session making the change survives');
            assert.deepEqual(deleted, ['admin']);
            assert.match(request.flashes[0].message, /2 registered passkeys removed/);
        } finally {
            passkeys.deleteAllCredentials = originalDelete;
        }
    });

    await t.test('a password change with the wrong current password changes nothing', async () => {
        const originalDelete = passkeys.deleteAllCredentials;
        let deleted = false;
        passkeys.deleteAllCredentials = async () => {
            deleted = true;
            return 0;
        };
        try {
            stored.authData = { user: 'admin', password: await pbkdf2.hash('old-password', { iterations: 1000 }), passwordVersion: 1 };
            const request = makeRequest({ user: 'admin', payload: { password0: 'wrong', password: 'new-password-123' }, artifacts: { requireTotp: false } });
            await route('POST', '/admin/account/password').handler(request, makeToolkit());
            assert.equal(
                written.some(([key]) => key === 'authData'),
                false
            );
            assert.equal(deleted, false);
        } finally {
            passkeys.deleteAllCredentials = originalDelete;
        }
    });

    await t.test('wrong passwords spend the sign-in budget of an account name, successful sign-ins do not', async () => {
        // Counted on failure only, under its own key: the bucket used to count every attempt, so
        // ten sign-ins a minute by the admin locked the admin out, and a username of
        // `ip:<address>` landed on the per-address counter
        const user = `login-budget-${RUN}`;
        stored.authData = { user, password: await pbkdf2.hash('the-password', { iterations: 1000 }), passwordVersion: 1 };
        const login = route('POST', '/admin/login');

        const attempt = async password => {
            const h = makeToolkit();
            const req = makeRequest({ user, payload: { username: user, password } });
            await login.handler(req, h);
            return { h, req };
        };

        for (let i = 0; i < 10; i++) {
            const { h } = await attempt('wrong-password');
            assert.equal(h.answers.views.length, 1, `attempt ${i + 1} renders the login form again`);
            assert.ok(h.answers.views[0].context.errors.password, 'a wrong password is reported as such');
        }

        // the budget is spent: the right password is refused as rate limited now
        const refused = await attempt('the-password');
        assert.equal(refused.h.answers.redirects.length, 0);
        assert.match(refused.req.flashes[0].message, /Rate limited/);

        // a fresh account name with a clean budget: twelve successful sign-ins in a row pass,
        // since each gives its reservation back (the old attempt counter refused the eleventh)
        const quiet = `login-quiet-${RUN}`;
        stored.authData = { user: quiet, password: await pbkdf2.hash('the-password', { iterations: PDKDF2_ITERATIONS }), passwordVersion: 1 };
        for (let i = 0; i < 12; i++) {
            const h = makeToolkit();
            await login.handler(makeRequest({ user: quiet, payload: { username: quiet, password: 'the-password' } }), h);
            assert.deepEqual(h.answers.redirects, ['/admin'], `sign-in ${i + 1} succeeds`);
        }
    });

    await t.test('a successful sign-in upgrades a hash written with weaker parameters', async () => {
        // The one moment the password is known is the one moment the stored hash can be rewritten
        const user = `login-rehash-${RUN}`;
        const legacy = await pbkdf2.hash('the-password', { digest: 'sha1', iterations: 1000 });
        stored.authData = { user, password: legacy, passwordVersion: 7 };
        const login = route('POST', '/admin/login');

        const h = makeToolkit();
        const req = makeRequest({ user, payload: { username: user, password: 'the-password' } });
        await login.handler(req, h);
        assert.deepEqual(h.answers.redirects, ['/admin']);

        const saved = written.find(([key]) => key === 'authData');
        assert.ok(saved, 'the upgraded hash is stored');
        assert.notEqual(saved[1].password, legacy);
        assert.match(saved[1].password, /^\$pbkdf2-sha256\$i=600000\$/);
        assert.equal(saved[1].passwordVersion, 7, 'not a password change: other sessions stay signed in');
        assert.equal(await pbkdf2.verify(saved[1].password, 'the-password'), true);

        // and the session carries the time it was issued, which is what ages it out
        const session = req.cookie.set[0][0];
        assert.ok(session.issuedAt > Date.now() - 5000);
        assert.ok(session.sid);

        // a hash already at the current parameters is left alone
        written.length = 0;
        const current = await pbkdf2.hash('the-password');
        stored.authData = { user, password: current, passwordVersion: 7 };
        await login.handler(makeRequest({ user, payload: { username: user, password: 'the-password' } }), makeToolkit());
        assert.equal(
            written.find(([key]) => key === 'authData'),
            undefined
        );
    });

    await t.test('enabling the second factor demands the password', async () => {
        // Switching TOTP on bumps the password version, which ends every other session: a
        // hijacked session could lock the real admin out, so it is a step that asks for the
        // password again like the step down does
        stored.authData = { user: 'admin', password: await pbkdf2.hash('the-password', { iterations: 1000 }), passwordVersion: 1 };
        const enable = route('POST', '/admin/account/tfa/enable');

        for (const password of [undefined, '', 'wrong-password']) {
            written.length = 0;
            const h = makeToolkit();
            const req = makeRequest({ user: 'admin', payload: { type: 'totp', code: currentCode(seed), password }, artifacts: { requireTotp: false } });
            await enable.handler(req, h);
            assert.deepEqual(h.answers.redirects, ['/admin/account/security']);
            assert.equal(req.flashes[0].message, 'Invalid password', `password ${JSON.stringify(password)} is refused`);
            assert.equal(
                written.find(([key]) => key === 'totpEnabled'),
                undefined,
                'nothing is switched on'
            );
        }

        written.length = 0;
        const h = makeToolkit();
        const req = makeRequest({
            user: 'admin',
            payload: { type: 'totp', code: currentCode(seed), password: 'the-password' },
            artifacts: { requireTotp: false }
        });
        await enable.handler(req, h);
        assert.equal(req.flashes[0].message, 'Two-factor auth enabled');
        assert.deepEqual(
            written.find(([key]) => key === 'totpEnabled'),
            ['totpEnabled', true]
        );
    });

    await t.test('passkey registration demands the password at the step that stores the credential', async () => {
        const originalRp = passkeys.getRpConfig;
        const originalConsume = passkeys.consumeChallenge;
        const consumed = [];
        passkeys.getRpConfig = async () => ({ rpId: 'localhost', origin: 'http://localhost:3000' });
        passkeys.consumeChallenge = async (...args) => {
            consumed.push(args);
            return null;
        };
        try {
            stored.authData = { user: 'admin', password: await pbkdf2.hash('the-password', { iterations: 1000 }), passwordVersion: 1 };
            const verify = route('POST', '/admin/account/passkeys/register/verify');

            for (const password of [undefined, '', 'wrong-password']) {
                const h = makeToolkit();
                const res = await verify.handler(
                    makeRequest({ user: 'admin', payload: { password, challengeId: 'c', credential: {}, name: 'key' }, artifacts: { requireTotp: false } }),
                    h
                );
                assert.equal(res.statusCode, 403, `password ${JSON.stringify(password)} is refused`);
            }
            assert.equal(consumed.length, 0, 'the challenge is not consumed by a refused attempt');

            // The right password gets as far as the challenge
            const res = await verify.handler(
                makeRequest({
                    user: 'admin',
                    payload: { password: 'the-password', challengeId: 'c', credential: {}, name: 'key' },
                    artifacts: { requireTotp: false }
                }),
                makeToolkit()
            );
            assert.equal(res.statusCode, 400);
            assert.equal(consumed.length, 1);
        } finally {
            passkeys.getRpConfig = originalRp;
            passkeys.consumeChallenge = originalConsume;
        }
    });
});
