'use strict';

// The Docker image's HEALTHCHECK, run by bin/healthcheck.js. The image's first health check was a
// BusyBox wget against http://127.0.0.1:${EENGINE_PORT}, which failed every time on an instance
// serving the API over HTTPS: the probe reached a TLS socket with a plain request, Swarm marked
// the task unhealthy, sent it no traffic and replaced it every few minutes. The probe therefore
// asks lib/api-listener.js, the same resolver the API listener is built from.

const http = require('http');
const https = require('https');
const { apiPort, apiHost, apiTlsConfig } = require('./api-listener');

const PROBE_TIMEOUT = 5000;
const PROBE_PATH = '/health/live';

// A listener bound to every address answers on loopback; a specific address is probed directly
const WILDCARD_HOSTS = new Set(['', '0.0.0.0', '::']);

/**
 * Where the API listener of this instance can be reached from inside its own container.
 *
 * @param {Object} api - The `[api]` section of the configuration
 * @returns {{ protocol: string, host: string, port: number }}
 */
function probeTarget(api) {
    const host = (apiHost(api) || '')
        .toString()
        .trim()
        .replace(/^\[(.*)\]$/, '$1');

    return {
        protocol: apiTlsConfig(api) ? 'https' : 'http',
        host: WILDCARD_HOSTS.has(host) ? '127.0.0.1' : host,
        port: Number(apiPort(api))
    };
}

/**
 * Asks the liveness endpoint once.
 *
 * @param {{ protocol: string, host: string, port: number }} target
 * @param {Object} [opts]
 * @param {number} [opts.timeout] - Milliseconds before the probe gives up
 * @returns {Promise<{ ok: boolean, statusCode?: number, error?: string }>}
 */
function probe(target, { timeout = PROBE_TIMEOUT } = {}) {
    const client = target.protocol === 'https' ? https : http;

    return new Promise(resolve => {
        const req = client.get(
            {
                host: target.host,
                port: target.port,
                path: PROBE_PATH,
                timeout,
                // The probe only asks whether this process answers. The certificate is whatever the
                // operator serves for a public name (or the self-signed fallback), never one issued
                // for the loopback address, and judging it is not the liveness check's business.
                rejectUnauthorized: false
            },
            res => {
                res.resume();
                resolve({ ok: res.statusCode === 200, statusCode: res.statusCode });
            }
        );
        req.on('timeout', () => req.destroy(new Error(`No response in ${timeout}ms`)));
        req.on('error', err => resolve({ ok: false, error: err.message }));
    });
}

module.exports = { probeTarget, probe, PROBE_PATH };
