'use strict';

// fetch() with every redirect hop vetted by an egress policy.
//
// undici follows redirects on its own and offers no hook to look at the intermediate hops, so a
// permitted destination can hand a request on to one the policy refuses: a domain whose
// autoconfig answers 302 to http://169.254.169.254/ gets the metadata service fetched on its
// behalf. Webhook deliveries solve this by not following at all (lib/webhook-request.js), because
// there is an operator to publish the final URL. Autodiscovery has neither: the destination is
// derived from whatever email address a caller typed, and a domain's autoconfig commonly lives
// behind a redirect or two. So here redirects are followed by hand, and each hop goes through the
// same check the first request did.
//
// No dependency on lib/tools.js on purpose: that module opens Redis on require, and this one has
// to stay testable as a pure helper.

// A domain's autoconfig commonly sits behind one or two hops (http to https, apex to www); five
// is generous for that and small enough that a redirect loop costs nothing worth mentioning
const MAX_REDIRECTS = 5;

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

// The only schemes a redirect may lead to. A Location of `file:` or `ftp:` is not a web hop, and
// undici would refuse it anyway - refusing it here names the reason
const ALLOWED_PROTOCOLS = new Set(['http:', 'https:']);

// Headers that describe a request body. Dropped when a redirect turns the request into a GET,
// which is what fetch() does too (a Content-Length for a body that is no longer sent breaks the
// request outright)
const BODY_HEADERS = new Set(['content-type', 'content-length', 'content-encoding', 'content-language', 'content-location']);

function redirectError(message, code) {
    let err = new Error(message);
    err.code = code;
    return err;
}

/**
 * Resolves the Location header of a redirect against the URL that answered it.
 *
 * @param {string} location - Raw Location header
 * @param {string} base - URL of the response carrying it
 * @returns {string} Absolute URL of the next hop
 * @throws {Error} EREDIRECTINVALID for an unparseable target, EREDIRECTSCHEME for a non-web one
 */
function resolveRedirect(location, base) {
    let next;
    try {
        next = new URL(location, base);
    } catch (err) {
        throw redirectError(`Redirect from ${base} points at an invalid URL`, 'EREDIRECTINVALID');
    }

    if (!ALLOWED_PROTOCOLS.has(next.protocol)) {
        throw redirectError(`Redirect from ${base} points at an unsupported scheme (${next.protocol})`, 'EREDIRECTSCHEME');
    }

    return next.toString();
}

/**
 * Drops body-describing headers from a plain header object (the only shape the callers pass).
 *
 * @param {Object} [headers] - Header name to value
 * @returns {Object|undefined} Filtered copy
 */
function withoutBodyHeaders(headers) {
    return headers && Object.fromEntries(Object.entries(headers).filter(([name]) => !BODY_HEADERS.has(name.toLowerCase())));
}

/**
 * Performs a fetch, following redirects one vetted hop at a time.
 *
 * `validateTarget(url)` runs before the first request and before every hop; whatever it throws
 * ends the fetch. Redirect semantics match fetch(): 303 always becomes a bodyless GET, 301 and 302
 * do so for anything but GET and HEAD, 307 and 308 replay the request unchanged. A 3xx without a
 * Location is returned as it is, since it is not a redirect anyone can follow.
 *
 * @param {Function} fetchImpl - fetch implementation (undici fetch)
 * @param {string} url - Destination URL
 * @param {Object} [options] - fetch options (method, body, headers, dispatcher, signal) plus
 *   `validateTarget` (async url => void)
 * @returns {Promise<Response>} The final response, with its body unread
 * @throws {Error} EMAXREDIRECTS when the hop budget is spent, EREDIRECTINVALID / EREDIRECTSCHEME
 *   for a redirect that cannot be taken, or whatever validateTarget throws for a refused hop
 */
async function fetchWithVettedRedirects(fetchImpl, url, options) {
    let { validateTarget, ...fetchOptions } = options || {};

    let method = (fetchOptions.method || 'GET').toUpperCase();
    let body = fetchOptions.body;
    let headers = fetchOptions.headers;
    let current = url;

    for (let hop = 0; ; hop++) {
        if (validateTarget) {
            await validateTarget(current);
        }

        // redirect:'manual' makes undici return the 3xx itself, headers included, rather than
        // the opaque response the browser spec prescribes
        const res = await fetchImpl(current, Object.assign({}, fetchOptions, { method, body, headers, redirect: 'manual' }));

        if (!REDIRECT_STATUSES.has(res.status)) {
            return res;
        }

        const location = res.headers.get('location');
        if (!location) {
            return res;
        }

        // The hop is not taken, so its body is never read by the caller. Drain it here so the
        // keep-alive socket goes back to the pool instead of staying pinned
        await res.text().catch(() => false);

        if (hop >= MAX_REDIRECTS) {
            throw redirectError(`Too many redirects, gave up at ${current}`, 'EMAXREDIRECTS');
        }

        const next = resolveRedirect(location, current);

        if (res.status === 303 || ((res.status === 301 || res.status === 302) && method !== 'GET' && method !== 'HEAD')) {
            method = 'GET';
            body = undefined;
            headers = withoutBodyHeaders(headers);
        }

        current = next;
    }
}

module.exports = { fetchWithVettedRedirects, MAX_REDIRECTS };
