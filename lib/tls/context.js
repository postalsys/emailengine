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
const {
    getCertificateHostnames,
    getManualCertificate,
    getSelfSignedCertificate,
    getAcmeCertificate,
    parseCertificate,
    coversHostname,
    describeX509,
    normalizeHostname
} = require('./store');

/**
 * The certificate plus whatever chain came with it, which is what a TLS context wants.
 *
 * @param {Object} material Resolved material
 * @returns {string} PEM bundle, leaf first
 */
function fullChain(material) {
    return material.ca && material.ca.length ? [material.cert].concat(material.ca).join('\n') : material.cert;
}

// How a listener negotiates, as opposed to what it serves. These belong to the listener rather
// than to any one certificate, and they travel with the resolved options because installing a
// context replaces it whole: tls.Server.setSecureContext() reverts everything absent from its
// argument to Node's default, so a reload carrying nothing but a certificate and a key dropped an
// operator's mTLS `ca` and version bounds at the first renewal. Every context built here is built
// from the same set, so what a listener installs and what the SNI callback hands back cannot drift.
//
// The names are the tls.createSecureContext() ones, which is what lib/tools.js loadTlsConfig()
// fills in from EENGINE_{API,SMTP,IMAPPROXY}_TLS_* and [api.tls]. `requestCert` and
// `rejectUnauthorized` are deliberately absent: they are listener options, not context options.
const HANDSHAKE_KEYS = ['ca', 'ciphers', 'ecdhCurve', 'dhparam', 'minVersion', 'maxVersion', 'honorCipherOrder', 'secureOptions', 'sigalgs', 'crl'];

/**
 * Picks the handshake settings out of a listener's TLS options.
 *
 * @param {Object} [source] Listener TLS options
 * @returns {Object} Just the settings a secure context understands
 */
function handshakeOptionsFrom(source) {
    const options = {};

    for (const key of HANDSHAKE_KEYS) {
        if (source && typeof source[key] !== 'undefined' && source[key] !== null) {
            options[key] = source[key];
        }
    }

    return options;
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
 * @param {Object} [opts.logger] Logger for a stored certificate that could not be read
 * @returns {Promise<Object|false>} Material, or false when only the fallback is left
 */
async function resolveHostname(opts) {
    const { certs, hostname, env, envX509, manual, manualX509, logger } = opts;
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
        return (await getAcmeCertificate(certs, hostname, logger)) || false;
    }

    return false;
}

/**
 * Builds a listener's TLS material and keeps it refreshable.
 *
 * @param {Object} opts
 * @param {Object} [opts.certs] @postalsys/certs handler
 * @param {Object} opts.logger Worker logger
 * @param {Object} [opts.listenerOptions] The listener's own TLS options: its handshake settings, and
 *                                        the material the environment or config file supplied
 * @param {Object} [opts.envMaterial] That material stated explicitly, when it is not on the listener
 *                                    options: `{ cert, key, ca, passphrase }`
 * @returns {Promise<Object>} `{ options, active, source, refresh() }`
 */
async function createTlsContext(opts) {
    const { certs, logger } = opts || {};
    const listenerOptions = (opts && opts.listenerOptions) || null;

    // Both snapshotted here rather than read per refresh: a listener writes the resolved options
    // back into the same object it passed in, so re-reading it later would mean reading this
    // module's own output back as if the operator had configured it.
    const handshake = handshakeOptionsFrom(listenerOptions);
    const envMaterial =
        (opts && opts.envMaterial) ||
        (listenerOptions ? { cert: listenerOptions.cert, key: listenerOptions.key, ca: listenerOptions.ca, passphrase: listenerOptions.passphrase } : null);

    // The state the SNI callback reads. Replaced wholesale by refresh(), so a handshake either sees
    // the previous set or the new one, never a half-built one.
    let state = { hostnames: [], entries: [], fallback: null, options: {} };

    // What one certificate is served with. The passphrase only ever comes from the environment:
    // everything EmailEngine stores is decrypted before it reaches here, and an operator's
    // encrypted key without it fails to load, which used to leave the listener quietly serving the
    // self-signed fallback instead of the certificate it was configured with. It is always set,
    // even when there is none - tls.createSecureContext() treats undefined as absent, and merging
    // this into a listener's own options has to clear a passphrase belonging to material it no
    // longer serves.
    const secureContextOptions = material =>
        Object.assign({}, handshake, { cert: fullChain(material), key: material.privateKey, passphrase: material.passphrase });

    const buildEntry = (hostname, material) => {
        try {
            return {
                hostname,
                material,
                x509: parseCertificate(material.cert),
                context: tls.createSecureContext(secureContextOptions(material))
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
        const name = normalizeHostname(servername);

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
                      privateKey: envMaterial.key,
                      passphrase: envMaterial.passphrase
                  }
                : null;
        const envX509 = env ? parseCertificate(env.cert) : null;

        // The uploaded certificate is loaded whether or not the environment supplied one: both are
        // applied per name, so a listener pinned to one certificate still has to offer a second
        // configured hostname the uploaded certificate that covers it.
        const [hostnames, mode, manual] = await Promise.all([getCertificateHostnames(), settings.get('tlsProvisioning'), getManualCertificate()]);

        const sources = sourcesFor(mode);
        const manualX509 = manual ? parseCertificate(manual.cert) : null;

        // Resolved concurrently: each hostname is an independent pair of Redis reads and a key
        // decrypt, and this runs before the listener binds its port in every worker that serves
        // TLS. Order is preserved, which is what makes entries[0] the primary name.
        const resolved = await Promise.all(hostnames.map(hostname => resolveHostname({ certs, hostname, sources, env, envX509, manual, manualX509, logger })));

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
            // no SNI never reaches the callback. The handshake settings come along because a
            // listener installing this replaces its context whole.
            options: fallback ? Object.assign(secureContextOptions(fallback.material), { SNICallback: sniCallback }) : {}
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

            // The store's own shape rather than a hand-picked subset of it: the page that renders
            // this reports a certificate that is not valid yet and lists the names it covers, and
            // neither field was here to report.
            return Object.assign(
                {
                    source: state.fallback.material.source,
                    // Env material is per listener and per process, so the listener is the only
                    // thing that knows which of the configured names it serves from it, and the
                    // TLS page reads that off this report.
                    envHostnames: state.entries.filter(entry => entry.material.source === 'env').map(entry => entry.hostname)
                },
                describeX509(state.fallback.x509) || {}
            );
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
 * @param {Function} opts.apply Receives the full option set (certificate, key and handshake settings) and installs it
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

    // Everything, not just the certificate and key: a listener that installs a context from those
    // two alone drops whatever the operator configured for the handshake.
    apply(options);

    const active = context.active;
    logger.info({ msg: 'Reloaded TLS certificates', source: active && active.source, fingerprint: active && active.fingerprint });

    return { updated: true, tls: active };
}

module.exports = { createTlsContext, applyTlsContext, resolveHostname, sourcesFor };
