'use strict';

// Every certificate this instance could present, under one id each (lib/tls/listeners.js), and
// what each listener makes of the list: the certificate it presents by default, and the one that
// answers each configured name.
//
// Until this module existed, material from EENGINE_SMTP_TLS_* and its siblings was not a
// certificate at all as far as the rest of the code was concerned: each listener loaded its own,
// served it ahead of everything else, and the admin page could only describe it second-hand from
// what the listener reported. It could not be chosen, and nothing else could be chosen over it.
// Here it is an entry like the uploaded, issued and self-signed ones, and what a listener presents
// when a client names no host (or a host nothing else covers) is a setting per listener, with the
// environment material as its automatic choice rather than its only possible one.
//
// Nothing here serves anything and nothing here renders anything. lib/tls/context.js turns a
// listener's view into secure contexts, lib/tls/status.js turns every listener's view into the
// page, and both get the view from listenerView() below, so they cannot disagree about it.

const config = require('@zone-eu/wild-config');

const { loadTlsConfig } = require('../tools');
const {
    parseCertificate,
    coversHostname,
    materialFrom,
    normalizeHostname,
    getManualCertificate,
    peekManualCertificate,
    peekSelfSignedCertificate,
    getAcmeCertificate
} = require('./store');
const { LISTENERS, AUTO, MANUAL_ID, SELF_SIGNED_ID, CERTIFICATE_ID_PATTERN, listenerByKey } = require('./listeners');

// The `[api.tls]` section as the operator wrote it, taken before the API worker reads its file
// paths into it and then merges the material it resolved back over it (workers/api.js), which
// would otherwise put whatever that listener ended up serving on the page as "from the
// environment". The file paths are read here once; the environment is applied per read below,
// because a test sets it and because that is cheap.
const API_TLS_FILE = (() => {
    const section = config.api && config.api.tls && typeof config.api.tls === 'object' ? Object.assign({}, config.api.tls) : {};
    loadTlsConfig(section, 'EENGINE_API_TLS_');
    return section;
})();

// Which stored sources a certificate-source setting admits for a name. The setting is the
// certificate SOURCE, so it decides what is served and not only whether an order is placed:
// picking "self-signed only" while a Let's Encrypt certificate was still being served is the
// class of bug the source rework exists to remove - the UI describing behaviour the code does not
// have. Material from the environment is admitted by every mode: it is not a source EmailEngine
// chose. So is a certificate a listener was explicitly told to present.
const MODE_SOURCES = {
    acme: { manual: true, acme: true },
    manual: { manual: true, acme: false },
    'self-signed': { manual: false, acme: false }
};

function sourcesFor(mode) {
    return MODE_SOURCES[mode] || MODE_SOURCES.acme;
}

/**
 * The id a piece of material is listed and stored under.
 *
 * @param {Object} material Material from any store, with its `source`
 * @returns {string|null} The id, or null for material that has none (it is not listed)
 */
function certificateId(material) {
    if (!material) {
        return null;
    }
    switch (material.source) {
        case 'env':
            return material.listener ? `env:${material.listener}` : null;
        case 'manual':
            return MANUAL_ID;
        case 'acme':
            return material.hostname ? `acme:${material.hostname}` : null;
        case 'self-signed':
            return SELF_SIGNED_ID;
        default:
            return null;
    }
}

/**
 * Takes an id apart, so a page can name a certificate that is gone.
 *
 * @param {string} id Certificate id
 * @returns {Object|null} `{ source, listener?, hostname? }`, or null when it is not one
 */
function parseCertificateId(id) {
    const value = (id || '').toString().trim();
    if (!value || value === AUTO || !CERTIFICATE_ID_PATTERN.test(value)) {
        return null;
    }
    if (value === MANUAL_ID) {
        return { source: 'manual' };
    }
    if (value === SELF_SIGNED_ID) {
        return { source: 'self-signed' };
    }
    if (value.startsWith('env:')) {
        return { source: 'env', listener: value.slice(4) };
    }
    return { source: 'acme', hostname: normalizeHostname(value.slice(5)) };
}

/**
 * What a setting holds, folded: nothing and "auto" are the same answer, and so is a value the
 * schema would refuse - a listener does not die on a bad setting, it decides for itself.
 *
 * @param {*} value Stored setting value
 * @returns {string} An id, or "auto"
 */
function requestedCertificate(value) {
    const id = (value || '').toString().trim();
    return id && id !== AUTO && CERTIFICATE_ID_PATTERN.test(id) ? id : AUTO;
}

/**
 * The material a listener's environment prefix, or the config file, supplies.
 *
 * Read from the shared environment rather than from the listener's own options, so every worker
 * sees the same bytes for every listener - which is what lets one listener be told to present
 * another's certificate, and what lets the page list it.
 *
 * @param {string} key Listener key
 * @param {Object} [logger] Logger for material that is set but does not parse
 * @returns {Object|false} `{ source: 'env', listener, cert, ca, privateKey, passphrase, ...metadata }`
 */
function envMaterialFor(key, logger) {
    const listener = listenerByKey(key);
    if (!listener) {
        return false;
    }

    const ref = key === 'api' ? Object.assign({}, API_TLS_FILE) : {};
    loadTlsConfig(ref, listener.envPrefix);

    if (!ref.cert || !ref.key) {
        return false;
    }

    const material = materialFrom('env', {
        listener: key,
        cert: ref.cert,
        ca: [].concat(ref.ca || []).filter(entry => entry),
        privateKey: ref.key,
        passphrase: ref.passphrase || undefined
    });

    // Reported rather than silently dropped, which used to leave the listener quietly serving
    // the fallback instead of what it was configured with
    if (!material && logger) {
        logger.error({ msg: 'The TLS certificate supplied through the environment does not parse', listener: key, prefix: listener.envPrefix });
    }

    return material;
}

/**
 * The words a certificate is listed under.
 *
 * @param {Object} entry `{ source, listener?, hostname? }`
 * @returns {{ label: string, detail: (string|null) }}
 */
function describeEntry(entry) {
    switch (entry.source) {
        case 'env': {
            const listener = listenerByKey(entry.listener);
            return { label: `Environment (${listener ? listener.name : entry.listener})`, detail: listener ? listener.envNote : null };
        }
        case 'manual':
            return { label: 'Uploaded certificate', detail: null };
        case 'acme':
            return { label: `Let's Encrypt for ${entry.hostname}`, detail: null };
        case 'self-signed':
            return { label: 'Self-signed fallback', detail: null };
        default:
            return { label: entry.source, detail: null };
    }
}

/**
 * Whether a listener can be told to present this entry: it has material, or it is the self-signed
 * fallback, which is generated the first time a listener needs it.
 *
 * @param {Object} entry Catalog entry
 * @returns {boolean}
 */
function isSelectable(entry) {
    return !!(entry && (entry.material || entry.id === SELF_SIGNED_ID));
}

function entryFrom(fields, material) {
    return Object.assign(
        { id: certificateId(fields), material: material || false, x509: material ? parseCertificate(material.cert) : false },
        fields,
        describeEntry(fields)
    );
}

/**
 * Every certificate the instance could present, in page order - which is also precedence order
 * for a name: environment material, the upload, the issued certificates in hostname priority,
 * the fallback.
 *
 * The self-signed entry is always listed, generated or not: it is an option a listener may be
 * told to present, and the listener generates it on first use the way it always has. Listing
 * never generates it.
 *
 * @param {Object} opts
 * @param {Object} [opts.certs] @postalsys/certs handler, or null to list no issued certificate
 * @param {string[]} opts.hostnames Configured hostnames, in priority order
 * @param {boolean} [opts.withPrivateKey=false] Whether the uploaded certificate's key is decrypted
 *                                             into its entry. A listener needs it; a page does not.
 *                                             Issued material carries its key either way, which
 *                                             is how the certificate library returns it
 * @param {Object} [opts.logger] Logger for a store that could not be read
 * @returns {Promise<Object[]>} Entries `{ id, source, listener?, hostname?, label, detail, material, x509 }`
 */
async function listCertificates(opts) {
    const { certs, logger } = opts || {};
    const hostnames = [].concat((opts && opts.hostnames) || []);
    const withPrivateKey = !!(opts && opts.withPrivateKey);

    // Independent reads, in one round: this runs before a listener binds its port
    const [manual, issued, selfSigned] = await Promise.all([
        withPrivateKey ? getManualCertificate() : peekManualCertificate(),
        Promise.all(hostnames.map(hostname => getAcmeCertificate(certs, hostname, logger))),
        peekSelfSignedCertificate()
    ]);

    const entries = [];

    for (const listener of LISTENERS) {
        const material = envMaterialFor(listener.key, logger);
        if (material) {
            entries.push(entryFrom({ source: 'env', listener: listener.key }, material));
        }
    }

    if (manual) {
        entries.push(entryFrom({ source: 'manual' }, manual));
    }

    hostnames.forEach((hostname, index) => {
        if (issued[index]) {
            // With the name it was issued for: that is what the certificate's id is made of
            entries.push(entryFrom({ source: 'acme', hostname }, Object.assign({ hostname }, issued[index])));
        }
    });

    entries.push(entryFrom({ source: 'self-signed' }, selfSigned));

    return entries;
}

/**
 * The entries a name may resolve to on a listener, in precedence order: the listener's own
 * environment material, then the upload and the issued certificates as far as the source setting
 * admits them. The fallback is not among them; it is what a caller adds for a name none of these
 * cover.
 *
 * @param {Object[]} catalog What listCertificates() returned
 * @param {Object} opts
 * @param {string|null} [opts.listener] Listener key; null admits no environment material
 * @param {Object} opts.sources What the source setting admits, from sourcesFor()
 * @returns {Object[]} The admitted entries, catalog order
 */
function admittedFor(catalog, opts) {
    const { listener, sources } = opts;

    return catalog.filter(entry => {
        if (!entry.material) {
            return false;
        }
        switch (entry.source) {
            case 'env':
                return !!listener && entry.listener === listener;
            case 'manual':
                return !!sources.manual;
            case 'acme':
                return !!sources.acme;
            default:
                return false;
        }
    });
}

/**
 * The certificate a listener presents by default: to a client that names no host, and for every
 * name the certificate covers.
 *
 * An explicit choice is honored as long as the certificate exists, whatever the source setting
 * admits - it is an instruction, the way environment material always was. Otherwise the automatic
 * choice: the listener's own environment material (an operator who set EENGINE_SMTP_TLS_CERT meant
 * the SMTP server to present it), then whatever answers the primary hostname, then any certificate
 * answering a name at all, then the self-signed fallback, so a listener that has been switched on
 * always starts.
 *
 * @param {Object} opts
 * @param {Object[]} opts.catalog What listCertificates() returned
 * @param {Object[]} opts.entries The entries answering configured names, primary first
 * @param {string} [opts.primary] The primary hostname
 * @param {string|null} [opts.listener] Listener key
 * @param {*} [opts.requested] The listener's setting value
 * @returns {Object} `{ entry, selection, requested }` - `selection` is "selected", "auto", or
 *                   "missing" when the requested certificate no longer exists and the automatic
 *                   choice stands in for it
 */
function resolveDefaultCertificate(opts) {
    const { catalog, entries, primary, listener } = opts;
    const requested = requestedCertificate(opts.requested);

    if (requested !== AUTO) {
        const chosen = catalog.find(entry => entry.id === requested && isSelectable(entry));
        if (chosen) {
            return { entry: chosen, selection: 'selected', requested };
        }
    }

    const selection = requested === AUTO ? 'auto' : 'missing';

    const own = listener ? catalog.find(entry => entry.source === 'env' && entry.listener === listener && entry.material) : null;
    const forPrimary = primary ? entries.find(entry => coversHostname(entry.x509, primary)) : null;
    const entry = own || forPrimary || entries[0] || catalog.find(candidate => candidate.id === SELF_SIGNED_ID);

    return { entry, selection, requested };
}

/**
 * Which entry answers a client asking for a name: the default when it covers the name, otherwise
 * whichever per-hostname entry does, otherwise the default. The one rule the SNI callback and the
 * page both follow.
 *
 * @param {string} servername Name the client sent, or nothing
 * @param {Object} view `{ fallback, entries }`, each entry with a parsed `x509`
 * @returns {Object|null} The entry to serve
 */
function entryForName(servername, view) {
    const { fallback, entries } = view;
    const name = normalizeHostname(servername);

    if (name) {
        if (fallback && coversHostname(fallback.x509, name)) {
            return fallback;
        }
        const match = (entries || []).find(entry => coversHostname(entry.x509, name));
        if (match) {
            return match;
        }
    }

    return fallback || null;
}

/**
 * What one listener makes of the catalog: the entry answering each configured name, the default,
 * and whether the self-signed fallback is needed for any of it.
 *
 * A configured name that neither the default nor any admitted entry covers gets the self-signed
 * fallback, which covers every configured name, rather than a certificate that fails the client's
 * name check just the same and is not what the page says the name has.
 *
 * @param {Object} opts
 * @param {Object[]} opts.catalog What listCertificates() returned
 * @param {string[]} opts.hostnames Configured hostnames, primary first
 * @param {Object} opts.sources What the source setting admits, from sourcesFor()
 * @param {string|null} [opts.listener] Listener key
 * @param {*} [opts.requested] The listener's setting value
 * @returns {Object} `{ fallback, entries, selection, requested, uncovered, needsSelfSigned }` -
 *                   `entries` are the distinct entries answering some configured name, hostname
 *                   order, with the self-signed entry appended when a name needs it;
 *                   `needsSelfSigned` says the fallback material has to exist for this view to
 *                   serve, whether generated or not yet
 */
function listenerView(opts) {
    const { catalog, sources, listener, requested } = opts;
    const hostnames = [].concat(opts.hostnames || []);

    const admitted = admittedFor(catalog, { listener: listener || null, sources });

    // The first admitted entry covering each name, deduplicated in hostname order
    const entries = [];
    for (const hostname of hostnames) {
        const match = admitted.find(entry => coversHostname(entry.x509, hostname));
        if (match && !entries.includes(match)) {
            entries.push(match);
        }
    }

    const choice = resolveDefaultCertificate({ catalog, entries, primary: hostnames[0], listener: listener || null, requested });
    const fallback = choice.entry;

    const uncovered = hostnames.filter(
        hostname => !(fallback && coversHostname(fallback.x509, hostname)) && !entries.some(entry => coversHostname(entry.x509, hostname))
    );

    const selfSigned = catalog.find(entry => entry.id === SELF_SIGNED_ID);
    if (uncovered.length && selfSigned && fallback !== selfSigned && !entries.includes(selfSigned)) {
        entries.push(selfSigned);
    }

    return {
        fallback,
        entries,
        selection: choice.selection,
        requested: choice.requested,
        uncovered,
        needsSelfSigned: !!((fallback && fallback.id === SELF_SIGNED_ID) || uncovered.length)
    };
}

module.exports = {
    sourcesFor,
    certificateId,
    parseCertificateId,
    requestedCertificate,
    envMaterialFor,
    describeEntry,
    isSelectable,
    listCertificates,
    admittedFor,
    resolveDefaultCertificate,
    entryForName,
    listenerView
};
