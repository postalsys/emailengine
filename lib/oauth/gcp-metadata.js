'use strict';

// The Google Cloud metadata server: the credentials of the service account attached to the
// Compute Engine VM, GKE pod (Workload Identity) or Cloud Run service EmailEngine runs on. Used by
// the `metadataServer` authentication method of a Cloud Pub/Sub app, which stores no secret at all.
//
// The host is fixed in code and can only be moved from the environment. It is deliberately not an
// application or settings field: these requests bypass the HTTP proxy and the webhook egress policy
// (the metadata server is reachable only from this host, and 169.254.169.254 is exactly what the
// default egress policy blocks), and the verify report echoes what came back. A host that an API
// token with `oauth2` or `settings` write could choose would turn that into a probe of the
// instance's own network. The environment belongs to whoever deployed the instance, who already
// holds the encryption secret and the Redis URL. Only the host moves: the paths, the
// `Metadata-Flavor` header and the http scheme are fixed, so this never becomes a general fetcher.
//
// No dependency on lib/tools.js on purpose: that module opens Redis on require, and this one has
// to stay testable as a pure helper. lib/read-env-value.js is the leaf it splits out for that.

const timers = require('timers/promises');
const { fetch: undiciFetch, Agent } = require('undici');
const packageData = require('../../package.json');
const { makeError } = require('./external-account-config');
const { readEnvValue } = require('../read-env-value');

// Google recommends the DNS name over 169.254.169.254, and it fails safer: it resolves only on
// Google Cloud, so on any other host the request ends at once with ENOTFOUND, instead of waiting
// out a connect timeout or reaching another cloud's instance metadata service at the same address
const DEFAULT_METADATA_HOST = 'metadata.google.internal';

// EmailEngine's own name first; GCE_METADATA_HOST is what every Google client library reads, so an
// existing emulator or metadata proxy setup keeps working without a second variable
const METADATA_HOST_ENV_KEYS = ['EENGINE_GCP_METADATA_HOST', 'GCE_METADATA_HOST'];

const TOKEN_PATH = '/computeMetadata/v1/instance/service-accounts/default/token';
const EMAIL_PATH = '/computeMetadata/v1/instance/service-accounts/default/email';
const PROJECT_ID_PATH = '/computeMetadata/v1/project/project-id';

// Required on every request, and sent back by the metadata server on its answers. Checking the
// answer is what tells the Google metadata server from something else listening at the address
const FLAVOR_HEADER = 'Metadata-Flavor';
const FLAVOR_VALUE = 'Google';

const REQUEST_TIMEOUT = 10 * 1000;

// Google documents sub-second 503 answers during host maintenance, so one quick retry covers them
const MAINTENANCE_RETRY_DELAY = 500;

// Upper bound on response text kept on an error, which the verify report can surface
const MAX_RESPONSE_TEXT = 512;

const USER_AGENT = `${packageData.name}/${packageData.version} (+${packageData.homepage})`;

// Never the shared proxy dispatcher: a proxy cannot reach the metadata server, and the request
// would hand it the access token that comes back
const metadataAgent = new Agent({
    connectTimeout: 3 * 1000,
    headersTimeout: REQUEST_TIMEOUT,
    bodyTimeout: REQUEST_TIMEOUT
});

/**
 * Resolves the origin the metadata server is reached at.
 *
 * An override takes `host`, `host:port` or `http://host[:port]`. Anything else (https, a path, a
 * query, credentials) is refused rather than replaced by the default: an override that is quietly
 * ignored sends a test setup to the real metadata server, which is the worse way to fail.
 *
 * @param {Object} [env] - environment to read (tests); the process environment, through readEnvValue(), when omitted
 * @returns {string} the origin, e.g. `http://metadata.google.internal`
 */
function resolveMetadataOrigin(env) {
    for (let key of METADATA_HOST_ENV_KEYS) {
        // readEnvValue() so the <KEY>_FILE form works here as it does for every other value
        let raw = ((env ? env[key] : readEnvValue(key)) || '').toString().trim();
        if (!raw) {
            continue;
        }

        let candidate = /^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? raw : `http://${raw}`;
        let url;
        try {
            url = new URL(candidate);
        } catch (err) {
            url = null;
        }

        if (!url || url.protocol !== 'http:' || !url.hostname || url.username || url.password || url.pathname !== '/' || url.search || url.hash) {
            throw makeError(`${key} must be a host name or host:port of the metadata server, got ${JSON.stringify(raw)}`, 'EMetadataConfig');
        }

        return url.origin;
    }

    return `http://${DEFAULT_METADATA_HOST}`;
}

function isTimeoutError(err) {
    return !!err && (err.name === 'TimeoutError' || err.name === 'AbortError');
}

function describeNetworkError(err) {
    let cause = (err && err.cause) || err;
    if (isTimeoutError(cause)) {
        return `no answer within ${Math.round(REQUEST_TIMEOUT / 1000)}s`;
    }
    return (cause && (cause.code || cause.message)) || 'connection failed';
}

// Network failures that say the metadata server was there but slow or interrupted, as opposed to
// absent (ENOTFOUND off Google Cloud) or refusing (ECONNREFUSED at a wrong override). Deliberately
// not consts.TRANSIENT_NETWORK_CODES, which counts both of those as transient
const METADATA_TRANSIENT_CODES = new Set([
    'ECONNRESET',
    'ETIMEDOUT',
    'EPIPE',
    'UND_ERR_CONNECT_TIMEOUT',
    'UND_ERR_HEADERS_TIMEOUT',
    'UND_ERR_BODY_TIMEOUT',
    'UND_ERR_SOCKET'
]);

/**
 * Whether a failure from this module is worth retrying as is: the metadata server answered 5xx past
 * the maintenance retry, or the request timed out or was cut off. Everything else (no metadata server,
 * no service account, a wrong override, a refused request) needs the operator. Decided where the error
 * is thrown, which is where the underlying failure is in hand.
 *
 * @param {Error} err - an error thrown by fetchAccessToken() and friends
 * @returns {boolean}
 */
function isTransientMetadataError(err) {
    return !!(err && err.transient);
}

/**
 * GETs one metadata path and returns the response text.
 *
 * @param {string} path - one of the fixed metadata paths
 * @param {Object} [opts]
 * @param {Object} [opts.env] - environment to resolve the host from (tests)
 * @param {Function} [opts.fetchImpl] - fetch implementation (tests)
 * @returns {Promise<string>}
 */
async function metadataRequest(path, opts) {
    opts = opts || {};
    const fetchImpl = opts.fetchImpl || undiciFetch;

    let origin = resolveMetadataOrigin(opts.env);

    for (let attempt = 0; ; attempt++) {
        let res;
        let body;
        try {
            res = await fetchImpl(origin + path, {
                method: 'GET',
                headers: { [FLAVOR_HEADER]: FLAVOR_VALUE, 'User-Agent': USER_AGENT },
                redirect: 'error',
                dispatcher: metadataAgent,
                signal: AbortSignal.timeout(REQUEST_TIMEOUT)
            });
            body = await res.text();
        } catch (err) {
            let cause = err.cause || err;
            throw makeError(`The metadata server at ${origin} could not be reached (${describeNetworkError(err)})`, 'EMetadataUnreachable', null, {
                cause: err,
                transient: isTimeoutError(cause) || METADATA_TRANSIENT_CODES.has(cause.code)
            });
        }

        if (res.status === 503 && attempt === 0) {
            await timers.setTimeout(MAINTENANCE_RETRY_DELAY);
            continue;
        }

        // Before the status: the metadata server flavors its error answers too, and a 404 from a
        // parking host or a cluster's search domain must read as "not the metadata server", not as
        // "no service account attached"
        if (res.headers.get(FLAVOR_HEADER) !== FLAVOR_VALUE) {
            throw makeError(
                `The server at ${origin} is not a Google Cloud metadata server (no "${FLAVOR_HEADER}: ${FLAVOR_VALUE}" header)`,
                'EMetadataServer',
                null,
                {
                    wrongFlavor: true
                }
            );
        }

        if (!res.ok) {
            throw makeError(`The metadata server at ${origin} returned HTTP ${res.status} for ${path}`, 'EMetadataServer', res.status, {
                responseText: body.slice(0, MAX_RESPONSE_TEXT),
                transient: res.status >= 500
            });
        }

        return body;
    }
}

/**
 * Fetches an access token for the attached service account.
 *
 * The metadata server caches the token itself and hands out the same one until five minutes before
 * it expires, so asking again is cheap; the caller still caches it like any other service token.
 *
 * @param {Object} [opts] - see metadataRequest()
 * @returns {Promise<{ access_token: string, expires_in: number, token_type: string }>}
 */
async function fetchAccessToken(opts) {
    let body = await metadataRequest(TOKEN_PATH, opts);

    let data;
    try {
        data = JSON.parse(body);
    } catch (err) {
        data = null;
    }

    if (!data || typeof data.access_token !== 'string' || !data.access_token) {
        throw makeError('The metadata server answered without an access token', 'EMetadataResponse');
    }

    let expiresIn = Number(data.expires_in);

    return {
        access_token: data.access_token,
        expires_in: Number.isFinite(expiresIn) && expiresIn > 0 ? expiresIn : undefined,
        token_type: data.token_type || 'Bearer'
    };
}

/**
 * Reads the attached service account's email address.
 *
 * @param {Object} [opts] - see metadataRequest()
 * @returns {Promise<string>}
 */
async function fetchServiceAccountEmail(opts) {
    return (await metadataRequest(EMAIL_PATH, opts)).trim();
}

/**
 * Reads the attached service account's email address and the project id.
 *
 * @param {Object} [opts] - see metadataRequest()
 * @returns {Promise<{ serviceAccountEmail: string, projectId: string }>}
 */
async function describeAttachedIdentity(opts) {
    let [serviceAccountEmail, projectId] = await Promise.all([fetchServiceAccountEmail(opts), metadataRequest(PROJECT_ID_PATH, opts)]);
    return { serviceAccountEmail, projectId: projectId.trim() };
}

module.exports = {
    resolveMetadataOrigin,
    isTransientMetadataError,
    fetchAccessToken,
    fetchServiceAccountEmail,
    describeAttachedIdentity
};
