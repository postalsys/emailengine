'use strict';

// Response headers every HTTP surface sends. Applied from an onPreResponse extension registered
// AFTER the error-rendering one in workers/api.js, so the rebuilt error page, a redirect and a
// rendered view all carry them - a header set only on the success path would be missing from
// exactly the responses an attacker can provoke.
//
// The framing headers are limited to the admin surface. The public pages (hosted authentication
// form, unsubscribe, redirect) are meant to be opened from an operator's own application, and
// nothing in the contract says they must not be embedded there, so they are left frameable.
//
// Header names are lowercase because that is how hapi stores them on a response; the wire does
// not care about the case.

// Refuses MIME sniffing everywhere. An attachment or export served as application/octet-stream
// must not be rendered as HTML because the bytes happen to look like it.
const COMMON_HEADERS = Object.freeze({
    'x-content-type-options': 'nosniff',
    // Cross-origin requests carry the origin only. The hosted form and the message browser open
    // with signed tokens in the query string, and browsers that predate this default would send
    // the whole URL to any https target linked from the page
    'referrer-policy': 'strict-origin-when-cross-origin'
});

// The admin session cookie is SameSite=Lax and every form posts a crumb, but neither stops a page
// from being framed - and a framed admin page carries a valid crumb, so a click inside the frame
// is a real action. `frame-ancestors` is the standard, X-Frame-Options is for the browsers that
// only read the legacy header.
const ADMIN_HEADERS = Object.freeze(
    Object.assign({}, COMMON_HEADERS, {
        'x-frame-options': 'SAMEORIGIN',
        'content-security-policy': "frame-ancestors 'self'"
    })
);

/**
 * Tells whether a path belongs to the admin surface.
 *
 * Exact `/admin` plus everything under it. `/admin-something` is not admin, and `/v1/...` is the
 * machine-facing API where a framing header changes nothing. Also what the admin address
 * whitelist in workers/api.js keys on, so the two agree on what "the admin surface" is.
 *
 * @param {string} path - Request path
 * @returns {boolean}
 */
function isAdminPath(path) {
    return path === '/admin' || (typeof path === 'string' && path.startsWith('/admin/'));
}

/**
 * Resolves the security headers a response on the given path carries.
 *
 * @param {string} path - Request path
 * @returns {Object} Header name to value, frozen
 */
function securityHeadersFor(path) {
    return isAdminPath(path) ? ADMIN_HEADERS : COMMON_HEADERS;
}

/**
 * Hapi onPreResponse extension that stamps the headers onto the outgoing response.
 *
 * Works on both response shapes: a Boom error keeps its headers under `output.headers`, a regular
 * response under `headers`. An earlier extension may already have replaced the original response
 * (the admin error page, the JSON API error), and `request.response` is whatever is current.
 * The values are set unconditionally: no handler has a reason to weaken them.
 *
 * @param {Object} request - Hapi request
 * @param {Object} h - Hapi response toolkit
 * @returns {Symbol} h.continue
 */
function applySecurityHeaders(request, h) {
    const response = request.response;
    Object.assign(response.isBoom ? response.output.headers : response.headers, securityHeadersFor(request.path));
    return h.continue;
}

module.exports = { applySecurityHeaders, securityHeadersFor, isAdminPath };
