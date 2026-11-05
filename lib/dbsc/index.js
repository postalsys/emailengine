'use strict';

// Device-bound admin sessions (DBSC, https://w3c.github.io/webappsec-dbsc/). An opt-in hardening of
// the admin session cookie: a browser that supports it creates a key pair it cannot export (the TPM
// on Windows, the Secure Enclave on macOS) and from then on proves possession of the key every few
// minutes to renew a short-lived second cookie. A session cookie copied off the machine stops
// working within BOUND_COOKIE_TTL, because nothing but the key can renew the second one.
//
// Opportunistic by design: a browser that does not support it never registers, and its session
// works exactly as before. Once a session HAS registered, the binding lives in Redis (store.js) and
// every request carrying that session's cookie must carry a valid bound cookie too - the session
// cookie says nothing about being bound, so it cannot be stripped of it.
//
// The pieces:
//   offer()       onPreResponse: asks an authenticated admin page's browser to register
//   register()    POST /admin/dbsc/start (lib/ui-routes/dbsc-routes.js)
//   refresh()     POST /admin/dbsc/refresh
//   mustRefuse()  onPostAuth: a bound session's request without the bound cookie is refused
//   end()         logout: marks the binding ended, which refuses the session cookie everywhere
//
// Verified end to end against Chrome 156 on macOS (Secure Enclave keys) on 2026-11-05. Chrome only
// registers on a trusted https origin: not on http, not on localhost, not with a certificate error.

const crypto = require('crypto');
const Boom = require('@hapi/boom');

const { ADMIN_SESSION_MAX_AGE } = require('../consts');
const { createDbscStore } = require('./store');
const { verifyRegistrationProof, verifyRefreshProof } = require('./jwt');
const {
    BOUND_COOKIE,
    BOUND_COOKIE_TTL,
    readSfString,
    registrationHeader,
    challengeHeader,
    registrationAnswer,
    boundCookieValid,
    boundCookieSpec
} = require('./protocol');

const RESPONSE_HEADER = 'secure-session-response';

// The admin session cookie's sid, which keys everything DBSC stores
const sidOf = request => (request.state && request.state.ee && request.state.ee.sid) || null;
const SESSION_ID_HEADER = 'sec-secure-session-id';
const SKIPPED_HEADER = 'secure-session-skipped';

/**
 * @param {Object} deps
 * @param {Object} deps.store - createDbscStore()
 * @param {Object} deps.logger
 * @param {string} deps.attributes - the bound cookie's attributes string (boundCookieSpec())
 */
function createDbsc({ store, logger, attributes }) {
    const issueBoundCookie = (h, sid, id) => h.state(BOUND_COOKIE, { sid, id, exp: Date.now() + BOUND_COOKIE_TTL });

    // Seconds the admin session behind this cookie can still live, which bounds its binding
    const sessionTtl = session => (Number(session.issuedAt) + ADMIN_SESSION_MAX_AGE - Date.now()) / 1000;

    return {
        async offer(request, h) {
            const response = request.response;
            if (!request.app.dbscEnabled || request.method !== 'get' || !request.auth.isAuthenticated || request.auth.strategy !== 'session') {
                return h.continue;
            }
            if (response.isBoom || response.variety !== 'view' || response.statusCode !== 200) {
                return h.continue;
            }
            const session = request.auth.artifacts || {};
            if (!session.sid || session.requireTotp || boundCookieValid(request.state[BOUND_COOKIE], session.sid)) {
                return h.continue;
            }
            try {
                // The throttle first: on a browser that never binds, that is the only round trip
                if (!(await store.claimOffer(session.sid)) || (!request.app.dbscUnbound && (await store.getBinding(session.sid)))) {
                    return h.continue;
                }
                response.header('Secure-Session-Registration', registrationHeader(await store.mintChallenge(session.sid, 'register')));
            } catch (err) {
                // An offer is an invitation, never a reason to fail the page
                logger.warn({ msg: 'Failed to offer a device-bound session', err });
            }
            return h.continue;
        },

        async register(request, h) {
            const session = request.auth.artifacts || {};
            if (!request.app.dbscEnabled || !session.sid) {
                return h.response().code(404);
            }

            const refuse = reason => {
                logger.info({ msg: 'Refused a device-bound session registration', reason, remoteAddress: request.app.ip });
                return h.response().code(400);
            };

            let proof;
            try {
                proof = verifyRegistrationProof(readSfString(request.headers[RESPONSE_HEADER]));
            } catch (err) {
                return refuse(err.message);
            }
            if (!(await store.consumeChallenge(proof.jti, session.sid, 'register'))) {
                return refuse('unknown or spent challenge');
            }

            const id = crypto.randomBytes(16).toString('hex');
            if (!(await store.bind(session.sid, { id, alg: proof.alg, jwk: proof.jwk }, sessionTtl(session)))) {
                // Bound already. A second registration would let whoever holds the session cookie
                // replace the key, which is the one thing the binding exists to prevent
                return h.response().code(409);
            }

            logger.info({
                msg: 'Admin session bound to a device key',
                user: request.auth.credentials && request.auth.credentials.user,
                alg: proof.alg,
                remoteAddress: request.app.ip
            });
            issueBoundCookie(h, session.sid, id);
            return h.response(registrationAnswer({ sessionId: id, attributes })).type('application/json');
        },

        async refresh(request, h) {
            // A 4xx other than 403 ends the session in the browser, a 3xx is ignored by it, so the
            // answers here are chosen by what the browser does with them
            const stop = () => h.response({ continue: false }).type('application/json');

            const session = request.auth.isAuthenticated ? request.auth.artifacts || {} : null;
            if (!request.app.dbscEnabled || !session || !session.sid) {
                return stop();
            }
            const binding = await store.getBinding(session.sid);
            if (!binding || binding.ended || binding.id !== readSfString(request.headers[SESSION_ID_HEADER])) {
                // A session the browser still holds from an earlier sign-in
                return stop();
            }

            const challengeAgain = async () =>
                h
                    .response()
                    .code(403)
                    .header('Secure-Session-Challenge', challengeHeader(await store.mintChallenge(session.sid, 'refresh'), binding.id));

            const token = readSfString(request.headers[RESPONSE_HEADER]);
            if (!token) {
                return await challengeAgain();
            }

            let jti;
            try {
                ({ jti } = verifyRefreshProof(token, binding));
            } catch (err) {
                // counted as a failed proof below
            }
            // Chrome signs proactive refreshes over the challenge it has cached, which this server
            // has already spent: that is answered with a fresh one, and the browser retries
            if (!jti || !(await store.consumeChallenge(jti, session.sid, 'refresh'))) {
                if (await store.recordRefreshFailure(session.sid)) {
                    return await challengeAgain();
                }
                logger.warn({ msg: 'Ended a device-bound session after repeated bad proofs', remoteAddress: request.app.ip });
                return h.response().code(401);
            }

            await store.clearRefreshFailures(session.sid);
            issueBoundCookie(h, session.sid, binding.id);
            return h.response().code(200);
        },

        /**
         * @returns {Promise<boolean>} true when the request carries a bound session without its
         *   bound cookie and has to be refused
         */
        async mustRefuse(request) {
            // The refresh route opts out: it is where a missing bound cookie gets renewed
            const routeOptions = request.route.settings.plugins.dbsc;
            if (!request.app.dbscEnabled || (routeOptions && routeOptions.enforce === false)) {
                return false;
            }
            // Both credentials the session cookie carries: the admin session, and the message
            // browser's session token on /v1 (lib/api-token-auth.js), which reads the same cookie
            const viaSession = request.auth.isAuthenticated && request.auth.strategy === 'session';
            if (!viaSession && !request.app.sessionToken) {
                return false;
            }
            const sid = sidOf(request);
            if (!sid || boundCookieValid(request.state[BOUND_COOKIE], sid)) {
                return false;
            }
            if (!(await store.getBinding(sid))) {
                // Known unbound for the rest of this request, so the offer need not ask again
                request.app.dbscUnbound = true;
                return false;
            }
            // A binding and no valid bound cookie: the session cookie is being used without the device
            // that holds the key. An ended binding (logout) is refused the same way; a bound cookie
            // issued before the logout still passes until it runs out, which is the price of not
            // reading Redis on every request that carries one

            logger.warn({
                msg: 'Refused a device-bound admin session without its bound credential',
                path: request.path,
                skipped: request.headers[SKIPPED_HEADER],
                remoteAddress: request.app.ip
            });
            return true;
        },

        /**
         * Whether the session making this request is bound to a device key, for the Security
         * page's "this browser" line
         * @returns {Promise<boolean>}
         */
        async isBound(request) {
            const sid = sidOf(request);
            if (!sid) {
                return false;
            }
            const binding = await store.getBinding(sid);
            return !!binding && !binding.ended;
        },

        async end(sid) {
            await store.endBinding(sid);
        }
    };
}

/**
 * Registers the bound cookie and publishes the DBSC instance on server.app, where the routes and
 * the logout handlers find it. Called with the session strategy, from the same cookie settings
 * @param {Object} server - hapi server
 * @param {Object} opts
 * @param {Object} opts.redis
 * @param {Object} opts.logger
 * @param {boolean} opts.secure - whether the admin cookies are Secure
 * @param {string} opts.password - cookiePassword
 */
function setupDbsc(server, { redis, logger, secure, password }) {
    const spec = boundCookieSpec({ secure, password });
    server.state(BOUND_COOKIE, spec.state);
    server.app.dbsc = createDbsc({ store: createDbscStore(redis), logger, attributes: spec.attributes });
}

/**
 * The offer (onPreResponse) and the enforcement (onPostAuth). Registered after the TOTP step, so a
 * session still owing its second factor is sent there first, and after the error-page extension,
 * so an offer is only ever attached to a page that is actually rendered
 * @param {Object} server - hapi server, after setupDbsc()
 */
function registerDbscExtensions(server) {
    const dbsc = server.app.dbsc;

    server.ext('onPostAuth', async (request, h) => {
        if (!(await dbsc.mustRefuse(request))) {
            return h.continue;
        }
        // The session is over on this browser. Its binding stays: deleting it would let the same
        // session cookie, wherever it was copied to, pass as an unbound session
        h.unstate('ee');
        h.unstate(BOUND_COOKIE);
        if (request.app.sessionToken) {
            throw Boom.unauthorized('Session could not be confirmed on this device');
        }
        await request.flash({
            type: 'warning',
            message: 'You were signed out because this browser could not confirm it is the device you signed in on. Sign in again to continue.'
        });
        const next = request.method === 'get' ? `?next=${encodeURIComponent(request.url.pathname + request.url.search)}` : '';
        return h.redirect(`/admin/login${next}`).takeover();
    });

    server.ext('onPreResponse', (request, h) => dbsc.offer(request, h));
}

/**
 * Ends the binding of the session a logout ends. A no-op where DBSC was never set up
 * @param {Object} request
 * @param {Object} h
 */
async function endDeviceBinding(request, h) {
    const dbsc = request.server.app.dbsc;
    const sid = sidOf(request);
    if (!dbsc || !sid) {
        return;
    }
    h.unstate(BOUND_COOKIE);
    await dbsc.end(sid);
}

module.exports = { setupDbsc, registerDbscExtensions, endDeviceBinding };
