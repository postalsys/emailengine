'use strict';

// The wire format of device-bound admin sessions (DBSC): the headers EmailEngine sends and reads,
// the short-lived cookie that carries the binding, and the registration answer. Pure.
//
// Chrome sends `Secure-Session-Response` and `Sec-Secure-Session-Id` as bare values although the
// spec declares them structured-field strings (quoted); both spellings are read. The challenge
// header carries the `id` parameter the spec requires, without which the browser does not cache
// the challenge and signs the next proof with a stale one.

const { ALGORITHMS } = require('./jwt');

// The paths the registration header and the registration answer name
const REGISTRATION_PATH = '/admin/dbsc/start';
const REFRESH_PATH = '/admin/dbsc/refresh';

// The cookie that proves a request came from the browser holding the session key. Short-lived on
// purpose: a stolen copy is useless once it runs out, and only the key can mint the next one
const BOUND_COOKIE = 'eeb';
const BOUND_COOKIE_TTL = 10 * 60 * 1000;

// Challenges are base64url, which is safe inside a structured-field string without escaping
const SF_TOKEN = /^[A-Za-z0-9_.~+/=-]+$/;

/**
 * Reads a header the spec declares a structured-field string, accepting the bare form Chrome sends
 * @param {string|undefined} value
 * @returns {string|null} the string, or null when the header is absent or malformed
 */
function readSfString(value) {
    if (typeof value !== 'string') {
        return null;
    }
    let text = value.trim();
    if (text.length >= 2 && text.startsWith('"') && text.endsWith('"')) {
        text = text.slice(1, -1);
    }
    return text && SF_TOKEN.test(text) ? text : null;
}

/**
 * @param {string} challenge
 * @returns {string} the Secure-Session-Registration value offering the algorithms jwt.js verifies
 */
function registrationHeader(challenge) {
    return `(${ALGORITHMS.join(' ')});path="${REGISTRATION_PATH}";challenge="${challenge}"`;
}

/**
 * @param {string} challenge
 * @param {string} sessionId - the session_identifier the browser registered under
 * @returns {string} the Secure-Session-Challenge value
 */
function challengeHeader(challenge, sessionId) {
    return `"${challenge}";id="${sessionId}"`;
}

/**
 * The bound cookie's settings, as hapi's server.state() takes them and as the attributes string the
 * registration answer names. One source for both, because the browser compares the cookie it is
 * sent against the attributes it registered (Domain, Path, Secure, HttpOnly, SameSite) and ignores
 * a refresh that sets anything else
 * @param {Object} opts
 * @param {boolean} opts.secure - whether the admin cookies are marked Secure (an https serviceUrl)
 * @param {string} opts.password - the iron sealing password (cookiePassword)
 * @returns {{ state: Object, attributes: string }}
 */
function boundCookieSpec({ secure, password }) {
    return {
        state: {
            ttl: BOUND_COOKIE_TTL,
            encoding: 'iron',
            password,
            path: '/',
            isSecure: !!secure,
            isHttpOnly: true,
            isSameSite: 'Lax',
            clearInvalid: true,
            ignoreErrors: true
        },
        attributes: ['Path=/', 'HttpOnly', 'SameSite=Lax'].concat(secure ? ['Secure'] : []).join('; ')
    };
}

/**
 * The JSON answer to a registration. The scope names no origin, so it defaults to the origin the
 * browser registered on: an operator reaching the admin UI on a name other than the Service URL's
 * would otherwise be told about a different site and the browser would drop the session
 * @param {Object} opts
 * @param {string} opts.sessionId
 * @param {string} opts.attributes - from boundCookieSpec()
 * @returns {Object}
 */
function registrationAnswer({ sessionId, attributes }) {
    return {
        session_identifier: sessionId,
        refresh_url: REFRESH_PATH,
        scope: {
            include_site: false,
            // Nothing under these carries the session, so there is nothing to refresh for
            scope_specification: [
                { type: 'exclude', domain: '*', path: '/static' },
                { type: 'exclude', domain: '*', path: '/.well-known' }
            ]
        },
        credentials: [{ type: 'cookie', name: BOUND_COOKIE, attributes }]
    };
}

/**
 * Whether a decoded bound cookie vouches for this session right now
 * @param {Object|undefined} cookie - request.state.eeb
 * @param {string} sid - the admin session's sid
 * @param {number} [now]
 * @returns {boolean}
 */
function boundCookieValid(cookie, sid, now = Date.now()) {
    return !!(cookie && sid && cookie.sid === sid && Number(cookie.exp) > now);
}

module.exports = {
    REGISTRATION_PATH,
    REFRESH_PATH,
    BOUND_COOKIE,
    BOUND_COOKIE_TTL,
    readSfString,
    registrationHeader,
    challengeHeader,
    boundCookieSpec,
    registrationAnswer,
    boundCookieValid
};
