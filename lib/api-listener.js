'use strict';

// Where and how the API listens, resolved from the environment and the config file. One copy for
// every process that needs the answer: the main thread and the API worker build the listener from
// it, the certificate reconciler asks whether it serves TLS, and the Docker health check
// (lib/health-probe.js) probes it. Kept to leaf modules so the health check can load it without
// reaching Redis, which lib/tools.js and lib/settings.js do as they load.

const config = require('@zone-eu/wild-config');
const { readEnvValue, hasEnvValue } = require('./read-env-value');
const { getBoolean } = require('./get-boolean');

/**
 * @param {Object} [api] - The `[api]` section of the configuration
 * @returns {number|undefined} EENGINE_PORT, then PORT, then `[api] port`
 */
function apiPort(api = config.api || {}) {
    return (hasEnvValue('EENGINE_PORT') && Number(readEnvValue('EENGINE_PORT'))) || (hasEnvValue('PORT') && Number(readEnvValue('PORT'))) || api.port;
}

/**
 * @param {Object} [api] - The `[api]` section of the configuration
 * @returns {string|undefined} EENGINE_HOST, then `[api] host`
 */
function apiHost(api = config.api || {}) {
    return readEnvValue('EENGINE_HOST') || api.host;
}

/**
 * Whether, and how, the API listener serves TLS: EENGINE_API_TLS and `[api.tls]`.
 *
 * @param {Object} [api] - The `[api]` section of the configuration
 * @returns {Object|false} The `[api.tls]` options to build the listener from, or false when the
 *                         API serves plain HTTP
 */
function apiTlsConfig(api = config.api || {}) {
    return hasEnvValue('EENGINE_API_TLS') ? getBoolean(readEnvValue('EENGINE_API_TLS')) && (api.tls || {}) : api.tls || false;
}

module.exports = { apiPort, apiHost, apiTlsConfig };
