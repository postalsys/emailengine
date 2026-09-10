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
// Which certificate answers which name, and which one is the listener's default, is decided by
// lib/tls/catalog.js (listenerView()); this module only turns that view into secure contexts.
//
// Everything a handshake needs is computed in refresh(): the certificates are parsed once there,
// not per connection. The SNI callback is on the accept path of the SMTP server, the IMAP proxy
// and the API's HTTPS listener, so anything it does is done once per client.

const tls = require('tls');
const config = require('@zone-eu/wild-config');

const settings = require('../settings');
const { hasEnvValue, readEnvValue, getBoolean } = require('../tools');
const { hostnamesFrom, getSelfSignedCertificate, parseCertificate, describeX509 } = require('./store');
const { TLS_CERTIFICATE_SETTINGS, SELF_SIGNED_ID, listenerByKey } = require('./listeners');
const { sourcesFor, listCertificates, entryForName, listenerView } = require('./catalog');

/**
 * The certificate plus whatever chain came with it, which is what a TLS context wants.
 *
 * @param {Object} material Resolved material
 * @returns {string} PEM bundle, leaf first
 */
function fullChain(material) {
    return material.ca && material.ca.length ? [material.cert].concat(material.ca).join('\n') : material.cert;
}

/**
 * Whether, and how, the API listener serves TLS: EENGINE_API_TLS and `[api.tls]`.
 *
 * Read from the environment and the config file, which every process shares, so the API worker
 * (which builds its listener from it) and the certificate reconciler (which asks whether any
 * listener would serve a certificate) cannot answer differently.
 *
 * @returns {Object|false} The `[api.tls]` options to build the listener from, or false when the
 *                         API serves plain HTTP
 */
function apiTlsConfig() {
    return hasEnvValue('EENGINE_API_TLS') ? getBoolean(readEnvValue('EENGINE_API_TLS')) && (config.api.tls || {}) : config.api.tls || false;
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

/**
 * Builds a listener's TLS material and keeps it refreshable.
 *
 * @param {Object} opts
 * @param {Object} [opts.certs] @postalsys/certs handler
 * @param {Object} opts.logger Worker logger
 * @param {string} [opts.listener] Which listener this is (`api`, `smtp`, `imapProxy`): whose
 *                                 environment material is its own, and which setting holds the
 *                                 certificate it presents by default
 * @param {Object} [opts.listenerOptions] The listener's own TLS options, for the handshake
 *                                        settings (ciphers, version bounds, a client CA). The
 *                                        certificate material in them is read from the environment
 *                                        by the catalog instead, so every worker sees the same bytes
 * @returns {Promise<Object>} `{ options, active, source, refresh() }`
 */
async function createTlsContext(opts) {
    const { certs, logger } = opts || {};
    const listener = (opts && listenerByKey(opts.listener)) || null;

    // Snapshotted here rather than read per refresh: a listener writes the resolved options back
    // into the same object it passed in, so re-reading it later would mean reading this module's
    // own output back as if the operator had configured it.
    const handshake = handshakeOptionsFrom((opts && opts.listenerOptions) || null);

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

    // A catalog entry with a context built for it. The self-signed entry is listed without
    // material until something needs it, and generated material may be newer than what the
    // catalog peeked, so the material is parsed again here rather than taken off the entry.
    const buildEntry = (entry, material) => {
        try {
            return {
                id: entry.id,
                material,
                x509: parseCertificate(material.cert),
                context: tls.createSecureContext(secureContextOptions(material))
            };
        } catch (err) {
            if (logger) {
                logger.error({ msg: 'Failed to build a TLS context', id: entry.id, source: material.source, err });
            }
            return null;
        }
    };

    // Stable across refreshes, so the options object handed to a listener stays valid while the
    // material behind it is replaced. The rule is entryForName(): the default certificate for
    // every name it covers and for a client that names none, otherwise the certificate resolved
    // for the name, otherwise the default again.
    const contextFor = servername => {
        const entry = entryForName(servername, state);
        return entry ? entry.context : null;
    };

    const sniCallback = (servername, cb) => {
        const context = contextFor(servername);
        return typeof cb === 'function' ? cb(null, context) : context;
    };

    const refresh = async () => {
        const values = await settings.getMulti('serviceUrl', 'tlsHostnames', 'tlsProvisioning', ...TLS_CERTIFICATE_SETTINGS);

        const hostnames = hostnamesFrom(values);

        // Everything the instance holds, with keys: this is the one read of the stores per
        // refresh, and it runs before the listener binds its port
        const catalog = await listCertificates({ certs, hostnames, logger, withPrivateKey: true });

        const view = listenerView({
            catalog,
            hostnames,
            sources: sourcesFor(values.tlsProvisioning),
            listener: listener && listener.key,
            requested: listener ? values[listener.settingKey] : null
        });

        if (view.selection === 'missing' && logger) {
            logger.warn({
                msg: 'The certificate this listener was told to present no longer exists, presenting the automatic choice',
                listener: listener && listener.key,
                requested: view.requested,
                fallback: view.fallback && view.fallback.id
            });
        }

        // Generated only when something needs it - as the default, or for a name nothing else
        // covers: once every name has a certificate of its own there is nothing for it to answer
        // for, and generating it anyway would put a certificate on the page that no listener
        // serves. The store hands back what it holds, or replaces one that no longer covers the
        // configured names.
        let selfSigned = view.needsSelfSigned ? await getSelfSignedCertificate(hostnames, logger) : null;
        const materialOf = entry => (entry.id === SELF_SIGNED_ID ? selfSigned : entry.material);

        const built = new Map();
        const build = entry => {
            if (!entry || !materialOf(entry)) {
                return null;
            }
            if (!built.has(entry.id)) {
                built.set(entry.id, buildEntry(entry, materialOf(entry)));
            }
            return built.get(entry.id);
        };

        let fallback = build(view.fallback);

        // A default whose context cannot be built - an encrypted operator key with no passphrase
        // - has been reported above; the listener still starts, on the fallback, rather than
        // refusing to bind with nothing to serve
        if (!fallback) {
            selfSigned = selfSigned || (await getSelfSignedCertificate(hostnames, logger));
            fallback = build(catalog.find(entry => entry.id === SELF_SIGNED_ID));
        }

        const entries = view.entries.map(build).filter(entry => entry);

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

        // What the listener is serving by default, for the admin UI's listener table and the state
        // payload. The store's own shape rather than a hand-picked subset of it: the page that
        // renders this reports a certificate that is not valid yet and lists the names it covers.
        get active() {
            if (!state.fallback) {
                return null;
            }

            const material = state.fallback.material;
            return Object.assign(
                {
                    id: state.fallback.id,
                    source: material.source,
                    // What the id is made of, so a page can name the certificate without the store
                    listener: material.listener || null,
                    hostname: material.hostname || null
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

module.exports = { createTlsContext, applyTlsContext, apiTlsConfig };
