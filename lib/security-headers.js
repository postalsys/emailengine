'use strict';

// Response headers every HTTP surface sends. Applied from an onPreResponse extension registered
// AFTER the error-rendering one in workers/api.js, so the rebuilt error page, a redirect and a
// rendered view all carry them - a header set only on the success path would be missing from
// exactly the responses an attacker can provoke.
//
// Which headers a response gets is decided by its profile, picked from the request path and the
// route tags:
//
//   static    - /static and the other inert routes. The common set only: a Content-Security-Policy
//               on a script file governs nothing, except when the file is loaded as a worker,
//               and static/js/evaluation-worker.js runs operator code through `new Function`
//               on purpose, so it must not inherit a policy from here.
//   api       - /v1, /mcp, /swagger.json, /metrics: machine-facing JSON that must never be
//               rendered or framed.
//   admin     - the authenticated console. The strict, nonce-based policy: only scripts the
//               server rendered with the request's nonce run, so markup that reaches the page
//               (the message browser renders sanitised email HTML, the error logs show inbound
//               headers) cannot bring code with it.
//   bullBoard - /admin/bull-board, third-party markup this code does not render: no nonce, and
//               the Google Fonts stylesheet its shell links.
//   public    - everything else: the hosted authentication form, unsubscribe, the OAuth landing
//               page, error pages. Operators inject their own HTML into these pages
//               (templateHtmlHead / templateHeader, a documented feature whose own example is
//               an external stylesheet), so the policy allows inline code and https: sources.
//               They also stay frameable: they are meant to be opened from an operator's own
//               application, and nothing in the contract says they must not be embedded there.
//
// The CSP preset additionally follows the layout. A view rendered with the public layout on an
// admin path - the error page, the branding preview - is that same operator-customisable markup
// and gets the public preset, while `frame-ancestors` stays with the path, so an admin error
// page is still not frameable elsewhere.
//
// Header names are lowercase because that is how hapi stores them on a response; the wire does
// not care about the case.

const crypto = require('crypto');
const { BULL_BOARD_BASE_PATH } = require('./consts');

const CSP_HEADER = 'content-security-policy';
const CSP_REPORT_ONLY_HEADER = 'content-security-policy-report-only';

// One year, this host only. `includeSubDomains` is not ours to decide: an operator running
// EmailEngine on a subdomain would be signing up every sibling host. `preload` is a manual
// submission the operator has to make anyway.
const HSTS_VALUE = 'max-age=31536000';

// The browser features no page of this application asks for. Passkeys
// (publickey-credentials-*) and the clipboard are deliberately absent from the list.
const PERMISSIONS_POLICY = 'accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()';

// How the Content-Security-Policy is delivered. `report-only` keeps the framing protection
// enforced and moves the rest of the policy to the report-only header, so an operator can see
// in the browser console what a page would lose without losing it; `off` is the pre-CSP state.
const CSP_MODES = ['enforce', 'report-only', 'off'];

// The layout the operator-customisable pages render with (views/layout/public.hbs)
const PUBLIC_LAYOUT = 'public';

// Route tags of the surfaces no browser page is served from. Shared with the CSRF check in
// workers/api.js, which skips the same routes: a request that carries no browser session has
// no crumb to present, and a response nobody renders needs no page policy.
const MACHINE_TAGS = Object.freeze(['api', 'external', 'scope:metrics', 'static']);

// `nonceScripts` presets get the request's nonce appended to script-src after any route
// override, so an override of that directive keeps the nonce and a missing nonce fails closed
const CSP_PRESETS = Object.freeze({
    admin: Object.freeze({
        nonceScripts: true,
        directives: Object.freeze({
            'default-src': "'self'",
            'script-src': "'self'",
            // 'unsafe-inline' stays for styles: the ACE editor and the message browser widget
            // append <style> elements, and sanitised email HTML arrives with every rule inlined
            // into style attributes. Script execution is what the nonce guards.
            'style-src': "'self' 'unsafe-inline'",
            // data: for the icon masks in the stylesheets, the TOTP QR code and embedded cid images
            'img-src': "'self' data:",
            'font-src': "'self'",
            'connect-src': "'self'",
            // ACE loads its syntax workers through blob: URLs; the webhook function editor loads
            // evaluation-worker.js from /static
            'worker-src': "'self' blob:",
            'frame-src': "'none'",
            'object-src': "'none'",
            'base-uri': "'none'",
            'form-action': "'self'"
        })
    }),

    bullBoard: Object.freeze({
        directives: Object.freeze({
            'default-src': "'self'",
            'script-src': "'self'",
            'style-src': "'self' 'unsafe-inline' https://fonts.googleapis.com",
            'font-src': "'self' https://fonts.gstatic.com",
            'img-src': "'self' data:",
            'connect-src': "'self'",
            'object-src': "'none'",
            // its shell carries a <base href> for the mount path
            'base-uri': "'self'",
            'form-action': "'self'"
        })
    }),

    api: Object.freeze({
        directives: Object.freeze({
            'default-src': "'none'"
        })
    }),

    public: Object.freeze({
        directives: Object.freeze({
            'default-src': "'self' https: data:",
            'script-src': "'self' https: 'unsafe-inline'",
            'style-src': "'self' https: 'unsafe-inline'",
            'img-src': "'self' https: data: blob:",
            'font-src': "'self' https: data:",
            'connect-src': "'self' https:",
            'object-src': "'none'",
            'base-uri': "'self'",
            // The hosted form answers its POST with a redirect to the provider's authorization
            // page, and Chrome checks the redirect target of a form submission against form-action
            'form-action': "'self' https:"
        })
    })
});

// Refuses MIME sniffing everywhere. An attachment or export served as application/octet-stream
// must not be rendered as HTML because the bytes happen to look like it.
const COMMON_HEADERS = Object.freeze({
    'x-content-type-options': 'nosniff',
    // Cross-origin requests carry the origin only. The hosted form and the message browser open
    // with signed tokens in the query string, and browsers that predate this default would send
    // the whole URL to any https target linked from the page
    'referrer-policy': 'strict-origin-when-cross-origin',
    // Nothing here is meant for Flash or Acrobat cross-domain loading
    'x-permitted-cross-domain-policies': 'none'
});

const PAGE_HEADERS = Object.freeze(
    Object.assign({}, COMMON_HEADERS, {
        'permissions-policy': PERMISSIONS_POLICY
    })
);

// The admin session cookie is SameSite=Lax and every form posts a crumb, but neither stops a page
// from being framed - and a framed admin page carries a valid crumb, so a click inside the frame
// is a real action. `frame-ancestors` is the standard, X-Frame-Options is for the browsers that
// only read the legacy header. The cross-origin policies keep another origin from holding a
// reference to an admin window or embedding an admin response.
const ADMIN_HEADERS = Object.freeze(
    Object.assign({}, PAGE_HEADERS, {
        'x-frame-options': 'SAMEORIGIN',
        'cross-origin-opener-policy': 'same-origin',
        'cross-origin-resource-policy': 'same-origin'
    })
);

const PROFILES = Object.freeze({
    static: Object.freeze({ headers: COMMON_HEADERS, csp: null, frameAncestors: null, cacheControl: null }),
    api: Object.freeze({
        headers: Object.freeze(Object.assign({}, PAGE_HEADERS, { 'x-frame-options': 'DENY' })),
        csp: 'api',
        frameAncestors: "'none'",
        cacheControl: 'no-store'
    }),
    public: Object.freeze({ headers: PAGE_HEADERS, csp: 'public', frameAncestors: null, cacheControl: null }),
    admin: Object.freeze({ headers: ADMIN_HEADERS, csp: 'admin', frameAncestors: "'self'", cacheControl: 'no-store' }),
    bullBoard: Object.freeze({ headers: ADMIN_HEADERS, csp: 'bullBoard', frameAncestors: "'self'", cacheControl: 'no-store' })
});

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
 * Tells whether a route serves machines rather than browser pages, by its tags.
 *
 * @param {string[]} [tags] - Route tags
 * @returns {boolean}
 */
function isMachineRoute(tags = []) {
    return tags.some(tag => MACHINE_TAGS.includes(tag));
}

/**
 * Tells whether the instance declares itself served over https - the same signal that gives the
 * session and CSRF cookies their Secure flag, and the one that decides whether HSTS is sent.
 *
 * @param {string} serviceUrl - The `serviceUrl` setting
 * @returns {boolean}
 */
function isSecureOrigin(serviceUrl) {
    if (!serviceUrl) {
        return false;
    }
    try {
        return new URL(serviceUrl).protocol === 'https:';
    } catch (err) {
        return false;
    }
}

/**
 * Seeds a request with what the headers need later: the nonce its inline scripts carry and
 * whether HSTS applies. Runs at the top of the onRequest extension, before anything can render
 * a view, so the template and the header agree on the nonce.
 *
 * base64url rather than base64: Handlebars escapes `=` in an attribute, and a test comparing
 * the header against the rendered page should not have to know that.
 *
 * @param {Object} request - Hapi request
 * @param {Object} [options]
 * @param {boolean} [options.secureOrigin] - Whether the instance is served over https
 */
function attachSecurityContext(request, { secureOrigin = false } = {}) {
    request.app.cspNonce = crypto.randomBytes(16).toString('base64url');
    request.app.secureOrigin = !!secureOrigin;
}

/**
 * Picks the header profile for a request.
 *
 * @param {string} path - Request path
 * @param {string[]} [tags] - Route tags
 * @returns {string} Profile name, a key of PROFILES
 */
function profileNameFor(path, tags = []) {
    path = typeof path === 'string' ? path : '';

    if (tags.includes('static') || path.startsWith(`${BULL_BOARD_BASE_PATH}/static/`)) {
        return 'static';
    }
    if (path === BULL_BOARD_BASE_PATH || path.startsWith(`${BULL_BOARD_BASE_PATH}/`)) {
        return 'bullBoard';
    }
    if (isAdminPath(path)) {
        return 'admin';
    }
    // The path prefix covers what no tag can: a mistyped API path lands on the untagged catch-all
    if (path.startsWith('/v1/') || path === '/swagger.json' || isMachineRoute(tags)) {
        return 'api';
    }
    return 'public';
}

function serializeCsp(directives) {
    return Object.keys(directives)
        .map(name => `${name} ${directives[name]}`)
        .join('; ');
}

/**
 * Resolves the security headers for one response. Pure, so the whole matrix is testable
 * without a server.
 *
 * @param {Object} options
 * @param {string} options.path - Request path
 * @param {string[]} [options.tags] - Route tags
 * @param {string} [options.layout] - Layout the response's view was rendered with, if it is one
 * @param {Object} [options.override] - The route's `plugins.securityHeaders` block: `directives`
 *     is merged over the preset, a `null` value removes a directive
 * @param {string} [options.nonce] - Request nonce
 * @param {boolean} [options.secureOrigin] - Whether HSTS applies
 * @param {string} [options.cspMode] - One of CSP_MODES; anything else enforces
 * @returns {{headers: Object, cacheControl: (string|null)}}
 */
function policyFor({ path, tags = [], layout, override, nonce, secureOrigin = false, cspMode = 'enforce' }) {
    const profile = PROFILES[profileNameFor(path, tags)];
    const headers = Object.assign({}, profile.headers);

    if (secureOrigin) {
        headers['strict-transport-security'] = HSTS_VALUE;
    }

    if (profile.csp) {
        const preset = CSP_PRESETS[layout === PUBLIC_LAYOUT ? 'public' : profile.csp];
        const directives = Object.assign({}, preset.directives);

        const overrides = (override && override.directives) || {};
        for (const directive of Object.keys(overrides)) {
            if (overrides[directive] === null) {
                delete directives[directive];
            } else {
                directives[directive] = overrides[directive];
            }
        }

        if (preset.nonceScripts && nonce && directives['script-src']) {
            directives['script-src'] += ` 'nonce-${nonce}'`;
        }

        if (profile.frameAncestors) {
            directives['frame-ancestors'] = profile.frameAncestors;
        }

        const framingOnly = profile.frameAncestors ? `frame-ancestors ${profile.frameAncestors}` : null;

        if (cspMode === 'off' || cspMode === 'report-only') {
            if (framingOnly) {
                headers[CSP_HEADER] = framingOnly;
            }
            if (cspMode === 'report-only') {
                headers[CSP_REPORT_ONLY_HEADER] = serializeCsp(directives);
            }
        } else {
            headers[CSP_HEADER] = serializeCsp(directives);
        }
    }

    return { headers, cacheControl: profile.cacheControl };
}

// Boom keeps its headers under the author's casing (`Retry-After`, `WWW-Authenticate`), a
// regular response lowercases them
function hasHeader(headers, name) {
    return Object.keys(headers).some(key => key.toLowerCase() === name);
}

/**
 * Builds the hapi onPreResponse extension that stamps the headers onto the outgoing response.
 *
 * Works on both response shapes: a Boom error keeps its headers under `output.headers`, a regular
 * response under `headers`. An earlier extension may already have replaced the original response
 * (the admin error page, the JSON API error), and `request.response` is whatever is current.
 * The profile's own headers are set unconditionally - no handler has a reason to weaken them -
 * while Cache-Control is only filled in where the handler set none, so a stream that asked for
 * `no-cache` (the change feed) or a download keeps what it chose.
 *
 * @param {Object} [options]
 * @param {string} [options.cspMode] - One of CSP_MODES
 * @returns {Function} Extension handler
 */
function securityHeadersExt({ cspMode = 'enforce' } = {}) {
    return function applySecurityHeaders(request, h) {
        const response = request.response;
        const target = response.isBoom ? response.output.headers : response.headers;
        const settings = (request.route && request.route.settings) || {};

        // `source.options` is what h.view() was called with; a view rendered through the
        // default layout has no layout option
        const layout = !response.isBoom && response.variety === 'view' && response.source.options ? response.source.options.layout : undefined;

        const policy = policyFor({
            path: request.path,
            tags: settings.tags || [],
            layout,
            override: settings.plugins && settings.plugins.securityHeaders,
            nonce: request.app.cspNonce,
            secureOrigin: request.app.secureOrigin,
            cspMode
        });

        Object.assign(target, policy.headers);

        if (policy.cacheControl && !hasHeader(target, 'cache-control')) {
            target['cache-control'] = policy.cacheControl;
        }

        return h.continue;
    };
}

module.exports = {
    securityHeadersExt,
    attachSecurityContext,
    policyFor,
    profileNameFor,
    isAdminPath,
    isMachineRoute,
    isSecureOrigin,
    CSP_MODES,
    CSP_HEADER,
    CSP_REPORT_ONLY_HEADER
};
