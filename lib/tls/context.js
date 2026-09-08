'use strict';

// Turns the sources in lib/tls/store.js into something a TLS listener can be handed, and lets a
// listener swap what it serves without being restarted.
//
// Both problems are the same problem. A listener used to bake `cert` and `key` into its options at
// startup, so a renewed certificate only reached clients when the worker was terminated and
// respawned - every SMTP submission and every IMAP session in flight was cut for a certificate that
// had another thirty days on it. A secure context built here can be replaced in place, and the
// SNI callback reads whatever the latest refresh produced.
//
// The same callback is what serves more than one hostname. EmailEngine's admin URL and its mail
// hostname are usually different names, and a client connecting to smtp.example.com has to be
// offered a certificate for smtp.example.com, not for the admin UI's.
//
// Everything a handshake needs is computed in refresh(): the certificates are parsed once there,
// not per connection. The SNI callback is on the accept path of the SMTP server, the IMAP proxy
// and the API's HTTPS listener, so anything it does is done once per client.

const tls = require('tls');

const settings = require('../settings');
const { getCertificateHostnames, getManualCertificate, getSelfSignedCertificate, getAcmeCertificate, parseCertificate, coversHostname } = require('./store');

/**
 * The certificate plus whatever chain came with it, which is what a TLS context wants.
 *
 * @param {Object} material Resolved material
 * @returns {string} PEM bundle, leaf first
 */
function fullChain(material) {
    return material.ca && material.ca.length ? [material.cert].concat(material.ca).join('\n') : material.cert;
}

// Which stored sources the operator's choice admits. The setting is the certificate SOURCE, so it
// has to decide what is served and not only whether an order is placed: picking "self-signed only"
// while a Let's Encrypt certificate was still being served is the same class of bug this rework
// exists to remove - the UI describing behaviour the code does not have.
//
// Material from the environment is admitted by every mode. It is not a source EmailEngine chose.
const MODE_SOURCES = {
    acme: { manual: true, acme: true },
    manual: { manual: true, acme: false },
    'self-signed': { manual: false, acme: false }
};

function sourcesFor(mode) {
    return MODE_SOURCES[mode] || MODE_SOURCES.acme;
}

/**
 * Material for one name, in the precedence order lib/tls/store.js documents. The self-signed
 * fallback is not here: it covers every configured name at once and is resolved by the caller when
 * nothing else answered.
 *
 * @param {Object} opts
 * @param {Object} [opts.certs] @postalsys/certs handler, or null to skip the ACME source
 * @param {string} opts.hostname Name being resolved
 * @param {Object} [opts.sources] Which stored sources the configured mode admits
 * @param {Object} [opts.env] Material from the environment or config file
 * @param {Object} [opts.envX509] That certificate, parsed once
 * @param {Object} [opts.manual] Pre-loaded uploaded certificate, so one lookup serves every name
 * @param {Object} [opts.manualX509] That certificate, parsed once
 * @returns {Promise<Object|false>} Material, or false when only the fallback is left
 */
async function resolveHostname(opts) {
    const { certs, hostname, env, envX509, manual, manualX509 } = opts;
    const sources = opts.sources || sourcesFor('acme');

    // An explicit instruction from the operator, and the only source not stored in Redis. Applied
    // per name like every other source: a listener told to serve one certificate should still
    // offer a second configured hostname the certificate that actually covers it.
    if (env && coversHostname(envX509, hostname)) {
        return env;
    }

    if (sources.manual && manual && coversHostname(manualX509, hostname)) {
        return manual;
    }

    if (sources.acme) {
        return (await getAcmeCertificate(certs, hostname)) || false;
    }

    return false;
}

/**
 * Builds a listener's TLS material and keeps it refreshable.
 *
 * @param {Object} opts
 * @param {Object} [opts.certs] @postalsys/certs handler
 * @param {Object} opts.logger Worker logger
 * @param {Object} [opts.envMaterial] Options already populated from the environment or config file
 * @returns {Promise<Object>} `{ options, active, source, refresh() }`
 */
async function createTlsContext(opts) {
    const { certs, logger, envMaterial } = opts || {};

    // The state the SNI callback reads. Replaced wholesale by refresh(), so a handshake either sees
    // the previous set or the new one, never a half-built one.
    let state = { hostnames: [], entries: [], fallback: null, options: {} };

    const buildEntry = (hostname, material) => {
        try {
            return {
                hostname,
                material,
                x509: parseCertificate(material.cert),
                context: tls.createSecureContext({ cert: fullChain(material), key: material.privateKey })
            };
        } catch (err) {
            if (logger) {
                logger.error({ msg: 'Failed to build a TLS context', hostname, source: material.source, err });
            }
            return null;
        }
    };

    // Stable across refreshes, so the options object handed to a listener stays valid while the
    // material behind it is replaced.
    const contextFor = servername => {
        const name = (servername || '').toString().toLowerCase().trim();

        if (name) {
            const match = state.entries.find(entry => coversHostname(entry.x509, name));
            if (match) {
                return match.context;
            }
        }

        return state.fallback && state.fallback.context;
    };

    const sniCallback = (servername, cb) => {
        const context = contextFor(servername);
        return typeof cb === 'function' ? cb(null, context) : context;
    };

    const refresh = async () => {
        const env =
            envMaterial && envMaterial.cert && envMaterial.key
                ? {
                      source: 'env',
                      cert: envMaterial.cert,
                      ca: [].concat(envMaterial.ca || []).filter(entry => entry),
                      privateKey: envMaterial.key
                  }
                : null;
        const envX509 = env ? parseCertificate(env.cert) : null;

        const [hostnames, mode, manual] = await Promise.all([getCertificateHostnames(), settings.get('tlsProvisioning'), env ? false : getManualCertificate()]);

        const sources = sourcesFor(mode);
        const manualX509 = manual ? parseCertificate(manual.cert) : null;

        // Resolved concurrently: each hostname is an independent pair of Redis reads and a key
        // decrypt, and this runs before the listener binds its port in every worker that serves
        // TLS. Order is preserved, which is what makes entries[0] the primary name.
        const resolved = await Promise.all(hostnames.map(hostname => resolveHostname({ certs, hostname, sources, env, envX509, manual, manualX509 })));

        const entries = [];
        for (let i = 0; i < hostnames.length; i++) {
            if (!resolved[i]) {
                continue;
            }
            const entry = buildEntry(hostnames[i], resolved[i]);
            if (entry) {
                entries.push(entry);
            }
        }

        // The default context answers a client that sent no SNI, and every name nothing else covers.
        // In order: the certificate for the primary name; then material the operator supplied, even
        // when it covers none of the configured names, because they configured this listener with
        // it on purpose; then any certificate at all; then the self-signed fallback, because a
        // listener that has been switched on has to start.
        let fallback = entries.find(entry => coversHostname(entry.x509, hostnames[0])) || null;

        if (!fallback && env) {
            fallback = buildEntry(hostnames[0] || null, env);
        }

        if (!fallback) {
            fallback = entries[0] || buildEntry(hostnames[0] || null, await getSelfSignedCertificate(hostnames, logger));
        }

        state = {
            hostnames,
            entries,
            fallback,
            // Built here rather than per read: `cert` and `key` are still set because both mail
            // server libraries assert on them before a handshake happens, and a client that sends
            // no SNI never reaches the callback.
            options: fallback ? { cert: fullChain(fallback.material), key: fallback.material.privateKey, SNICallback: sniCallback } : {}
        };

        return state;
    };

    await refresh();

    return {
        refresh,

        get options() {
            return state.options;
        },

        get source() {
            return (state.fallback && state.fallback.material.source) || null;
        },

        // What the listener is serving, for the admin UI's listener table and the state payload.
        get active() {
            if (!state.fallback) {
                return null;
            }

            const { material, x509 } = state.fallback;
            return {
                source: material.source,
                subject: x509 && x509.subject,
                issuer: x509 && x509.issuer,
                fingerprint: x509 && x509.fingerprint,
                validTo: x509 && new Date(x509.validTo)
            };
        }
    };
}

/**
 * Installs whatever the context now resolves to on a running listener.
 *
 * Every TLS listener does the same four things on a reload - refresh, check there is something to
 * serve, hand it over, say what happened - and the last time each of them carried its own copy of a
 * certificate step, the renewal path reloaded the SMTP server and forgot the IMAP proxy for months.
 *
 * @param {Object} opts
 * @param {Object} opts.context Result of createTlsContext(); null when the listener serves no TLS
 * @param {Function} opts.apply Receives `{ cert, key, SNICallback }` and installs it
 * @param {Object} opts.logger Worker logger
 * @returns {Promise<Object>} `{ updated, tls }`
 */
async function applyTlsContext(opts) {
    const { context, apply, logger } = opts;

    if (!context) {
        return { updated: false, tls: null };
    }

    await context.refresh();

    const options = context.options;
    if (!options.cert || !options.key) {
        logger.error({ msg: 'Refusing to reload TLS certificates, nothing to serve' });
        return { updated: false, tls: null };
    }

    apply({ cert: options.cert, key: options.key, SNICallback: options.SNICallback });

    const active = context.active;
    logger.info({ msg: 'Reloaded TLS certificates', source: active && active.source, fingerprint: active && active.fingerprint });

    return { updated: true, tls: active };
}

module.exports = { createTlsContext, applyTlsContext, resolveHostname, sourcesFor, fullChain };
