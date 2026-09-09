'use strict';

// The certificate model the admin UI renders.
//
// Everything here used to be a single badge next to a checkbox whose tooltip carried the
// fingerprint, computed for the service domain and for nothing else. It could not say what a
// listener was actually serving, when the certificate expired, where it came from, or why the last
// order failed - and one of its four states, "Self-signed", described something that did not exist.
//
// Pure apart from the two stores it reads, so the page and the tests see the same model.

const settings = require('../settings');
const { ACME_DIRECTORY_URL, ACME_ENVIRONMENT } = require('../consts');
const {
    hostnamesFrom,
    extraHostnamesFrom,
    acmeEligibleHostnames,
    getManualCertificate,
    peekSelfSignedCertificate,
    parseCertificate,
    coversHostname,
    normalizeHostname
} = require('./store');
const { resolveHostname, sourcesFor } = require('./context');
const { getProvisioningStatus } = require('./provision');
const { worstBy } = require('../utils/severity');

// Below this many days left, a certificate is worth pointing at even though it still works.
const EXPIRY_WARNING_DAYS = 14;

// How the recorded message is rendered, which is not always how the certificate is: a failed order
// sits under a certificate that is still perfectly valid, and a failed renewal under one that is
// still being served. A declined request ("skipped") is an explanation of why nothing happened,
// not a failure. Anything not listed is progress, and reads as information.
const STATUS_VARIANTS = {
    failed: 'error',
    skipped: 'info',
    renewalFailed: 'warning'
};

// The recorded states whose message the page shows as a line under the hostname. A successful
// order also records a message, but the certificate row already says everything it would.
const REASON_STATES = new Set(['failed', 'skipped', 'renewalFailed', 'queued', 'ordering']);

// The header badge when no listener is serving TLS at all.
const TLS_OFF_LABEL = { type: 'neutral', text: 'TLS off', title: 'No listener is serving TLS' };

const SOURCE_LABELS = {
    env: 'Environment',
    manual: 'Uploaded',
    acme: "Let's Encrypt",
    'self-signed': 'Self-signed'
};

// The same sources inside a sentence: "serving mail.example.com from ..."
const SOURCE_PHRASES = {
    env: 'the TLS environment variables',
    manual: 'the uploaded certificate',
    acme: "Let's Encrypt",
    'self-signed': 'the self-signed fallback'
};

function daysUntil(date) {
    if (!date) {
        return null;
    }
    return Math.floor((date.getTime() - Date.now()) / (24 * 3600 * 1000));
}

/**
 * A listener's report, with its dates back as dates.
 *
 * @param {Object} report Certificate description from a listener's state payload
 * @returns {Object} The same description, usable by certificateLabel() and publicView()
 */
function rehydrateReport(report) {
    // The report reaches a page as JSON out of a Redis hash, so every date in it is an ISO string
    return Object.assign({}, report, {
        validFrom: report.validFrom ? new Date(report.validFrom) : null,
        validTo: report.validTo ? new Date(report.validTo) : null
    });
}

/**
 * The certificate a listener is serving for a hostname out of environment or config-file material.
 *
 * That material is per listener and per process, so this module cannot read it, and a hostname
 * served only through EENGINE_SMTP_TLS_CERT used to be described as having no certificate at all
 * while every listener served it perfectly well. The listeners report which configured names they
 * resolved to that material, so the answer is a lookup in that list rather than a second, weaker
 * reimplementation of name matching against the report's own name list.
 *
 * @param {Object[]} reports Certificate descriptions from the listener state payloads
 * @param {string} hostname Name to describe
 * @returns {Object|false} The certificate, or false when no listener reports one for that name
 */
function reportedEnvCertificate(reports, hostname) {
    const name = normalizeHostname(hostname);
    if (!name) {
        return false;
    }

    const report = reports.find(entry => entry.source === 'env' && [].concat(entry.envHostnames || []).includes(name));

    return report ? rehydrateReport(report) : false;
}

/**
 * The countdown text for a certificate inside its warning window. Only reachable for a
 * certificate that has not expired, so the smallest value is today.
 *
 * @param {number} daysRemaining Whole days until expiry, possibly zero
 * @returns {string} Badge text
 */
function expiryText(daysRemaining) {
    if (daysRemaining <= 0) {
        return 'Expires today';
    }
    return daysRemaining === 1 ? 'Expires in 1 day' : `Expires in ${daysRemaining} days`;
}

/**
 * The badge for one certificate: colour, text and the sentence behind it.
 *
 * Severity follows consequence. Red means an order failed or a listener is serving something
 * clients will reject; a name nothing serves yet is neutral, and a self-signed certificate is a
 * warning only while a listener is actually presenting it. "Missing" is not a state: a listener
 * with TLS on always has the self-signed fallback, so a name without a stored certificate is one
 * nobody has needed a certificate for.
 *
 * @param {Object|false} certificate Resolved certificate, or false when there is none
 * @param {Object} [status] Recorded provisioning state for the hostname
 * @param {Object} [opts]
 * @param {boolean} [opts.served=true] Whether a listener with TLS on is presenting this name
 * @param {boolean} [opts.canRequest=false] Whether asking Let's Encrypt for the name would do anything
 * @returns {Object} `{ type, text, title }`
 */
function certificateLabel(certificate, status, opts) {
    const served = !opts || opts.served !== false;
    const canRequest = !!(opts && opts.canRequest);

    // Both states are "an order is happening": the reconciler is asked to run, then it runs. A page
    // rendered between the two used to fall through to whatever the stored certificate said.
    if (status && (status.state === 'ordering' || status.state === 'queued')) {
        return { type: 'info', text: 'Requesting', title: status.message || 'Requesting a certificate' };
    }

    if (!certificate) {
        if (status && status.state === 'failed') {
            return { type: 'error', text: 'Failed', title: status.message || 'Could not get a certificate' };
        }
        if (canRequest) {
            return { type: 'neutral', text: 'Not requested', title: 'No certificate has been requested for this name yet' };
        }
        return {
            type: 'neutral',
            text: 'Self-signed',
            title: 'A self-signed certificate is generated for this name the first time a listener needs one'
        };
    }

    const now = Date.now();

    if (certificate.validFrom && certificate.validFrom.getTime() > now) {
        return { type: 'warning', text: 'Not yet valid', title: `Valid from ${certificate.validFrom.toISOString()}` };
    }

    if (certificate.validTo && certificate.validTo.getTime() < now) {
        return { type: 'error', text: 'Expired', title: `Expired on ${certificate.validTo.toISOString()}` };
    }

    // A renewal that failed while the current certificate is still usable. The certificate itself
    // is fine, so every check below would call it Valid and the operator would never learn that it
    // has stopped being renewed - which is the whole failure mode: the badge stays green until the
    // day the certificate expires.
    if (status && status.state === 'renewalFailed') {
        return { type: 'warning', text: 'Renewal failed', title: status.message || 'The last renewal attempt failed' };
    }

    if (certificate.source === 'self-signed') {
        if (!served) {
            return { type: 'neutral', text: 'Self-signed', title: 'Generated on this instance. Clients can not verify it, and no listener is serving it yet.' };
        }
        return {
            type: 'warning',
            text: 'Self-signed',
            title: 'Clients can not verify this certificate. Pin its fingerprint or install a real one.'
        };
    }

    const daysRemaining = daysUntil(certificate.validTo);

    if (daysRemaining !== null && daysRemaining <= EXPIRY_WARNING_DAYS) {
        return { type: 'warning', text: expiryText(daysRemaining), title: `Expires on ${certificate.validTo.toISOString()}` };
    }

    if (certificate.source === 'env') {
        return { type: 'info', text: 'From environment', title: 'Supplied through the TLS environment variables or the config file' };
    }

    return { type: 'success', text: 'Valid', title: certificate.fingerprint || 'Valid certificate' };
}

/**
 * Strips the private key and normalizes what the views render.
 *
 * @param {Object|false} certificate Resolved certificate
 * @returns {Object|false} View-safe copy
 */
function publicView(certificate) {
    if (!certificate) {
        return false;
    }

    return {
        source: certificate.source,
        sourceLabel: SOURCE_LABELS[certificate.source] || certificate.source,
        sourcePhrase: SOURCE_PHRASES[certificate.source] || certificate.source,
        subject: certificate.subject,
        issuer: certificate.issuer,
        serialNumber: certificate.serialNumber,
        fingerprint: certificate.fingerprint,
        fingerprint256: certificate.fingerprint256,
        altNames: certificate.altNames || [],
        // Which configured names a listener resolved to this material, which only the listener
        // knows for environment material - see reportedEnvCertificate()
        envHostnames: certificate.envHostnames || [],
        validFrom: certificate.validFrom,
        validTo: certificate.validTo,
        // ISO strings as well as the dates: handlebars has no date formatter, and the page
        // localizes these client-side from the machine-readable form (the .local-time and
        // .relative-time handlers in static/js/app.js).
        validFromIso: certificate.validFrom ? certificate.validFrom.toISOString() : null,
        validToIso: certificate.validTo ? certificate.validTo.toISOString() : null,
        selfSigned: !!certificate.selfSigned,
        chainLength: 1 + [].concat(certificate.ca || []).length
    };
}

/**
 * The certificate summary the SMTP and IMAP proxy pages show next to their own TLS checkbox.
 *
 * It takes the provisioning state as well as the certificate, because those pages read a listener's
 * own report rather than the stored model: without the state they could only ever say "Valid",
 * including while a renewal had been failing for weeks.
 *
 * @param {Object} opts
 * @param {Object|null} opts.reported Certificate description from the listener's state payload
 * @param {string|null} opts.hostname Name clients connect to
 * @param {Object} [opts.status] Recorded provisioning state for that name
 * @returns {Object} `{ hostname, certificate, label }`; the last two are null when the listener has
 *                   reported nothing, so a caller has one shape to render either way
 */
function listenerCertificateSummary(opts) {
    const { reported, hostname, status } = opts || {};

    if (!reported) {
        return { hostname: hostname || null, certificate: null, label: null };
    }

    const certificate = rehydrateReport(reported);

    // A listener that reported a certificate is presenting it, so the label reads as served
    return { hostname: hostname || null, certificate: publicView(certificate), label: certificateLabel(certificate, status || null, { served: true }) };
}

/**
 * One badge for several: the worst of the labels given, or the "TLS off" label when there are none.
 * The page header wears it, so the tab an operator lands on agrees with the tiles under it.
 *
 * @param {Array<Object|null>} labels Labels from certificateLabel(); empty entries are skipped
 * @returns {Object} `{ type, text, title }`
 */
function summarizeLabels(labels) {
    const present = [].concat(labels || []).filter(label => label && label.type);

    if (!present.length) {
        return TLS_OFF_LABEL;
    }

    return worstBy(present, label => label.type);
}

/**
 * Whether asking for a certificate is the thing to do for a name: it could be ordered, and what it
 * has now is nothing, the fallback, or a certificate in trouble. A valid one is left alone (the
 * reconciler renews it), and so is one already being ordered.
 *
 * @param {Object} entry `{ canRequest, certificate, label, status }`, the certificate unwrapped
 * @returns {boolean}
 */
function wantsCertificate(entry) {
    if (!entry.canRequest) {
        return false;
    }
    if (entry.status && (entry.status.state === 'ordering' || entry.status.state === 'queued')) {
        return false;
    }
    if (!entry.certificate || entry.certificate.source === 'self-signed') {
        return true;
    }
    return entry.label.type === 'error' || entry.label.type === 'warning';
}

/**
 * Builds the whole certificate model: what is configured, what is installed for each name, where it
 * came from, and what the last provisioning attempt did.
 *
 * @param {Object} opts
 * @param {Object} opts.certs @postalsys/certs handler
 * @param {Object[]|Promise} [opts.reported] Certificates the listeners report serving, for the names
 *                                           no stored source answers for. A promise is accepted, so
 *                                           a page reading the listeners can do it alongside this
 * @returns {Promise<Object>} The model
 */
async function buildCertificateStatus(opts) {
    const { certs } = opts || {};

    // Everything the model needs, in one round of reads rather than five in a row. The hostname
    // list is derived from settings this already has, so it costs no second lookup.
    const [values, manual, selfSigned, provisioning, listenerReports] = await Promise.all([
        settings.getMulti('serviceUrl', 'tlsProvisioning', 'tlsHostnames'),
        getManualCertificate(),
        peekSelfSignedCertificate(),
        getProvisioningStatus(),
        (opts && opts.reported) || []
    ]);

    const reported = [].concat(listenerReports || []).filter(entry => entry);

    const mode = values.tlsProvisioning || 'acme';
    const hostnames = hostnamesFrom(values);
    const eligible = acmeEligibleHostnames(hostnames);

    const sources = sourcesFor(mode);
    const manualX509 = manual ? parseCertificate(manual.cert) : null;
    const selfSignedX509 = selfSigned ? parseCertificate(selfSigned.cert) : null;

    // The same resolver the listeners use, so the page cannot describe a certificate the listener
    // would not serve - which is the confusion this page exists to end. Env material is not passed:
    // it is per listener and per process, and the listeners report it themselves, which is what
    // reportedEnvCertificate() reads below.
    const resolved = await Promise.all(hostnames.map(hostname => resolveHostname({ certs, hostname, sources, manual, manualX509 })));

    // A listener reports a certificate only while it has TLS on, so a report is what says a name is
    // being presented to clients at all. That is what turns the self-signed fallback from a note
    // into a warning.
    const served = reported.length > 0;

    // The names this page adds and removes. Whatever is configured and not among them is the
    // Service URL's own name, which is set on the General page.
    const extraHostnames = extraHostnamesFrom(values);

    const certificates = hostnames.map((hostname, index) => {
        const certificate = resolved[index] || reportedEnvCertificate(reported, hostname) || (coversHostname(selfSignedX509, hostname) ? selfSigned : false);
        const status = provisioning[hostname] || null;
        const acmeEligible = eligible.includes(hostname);
        // Whether asking for a certificate now would do anything at all
        const canRequest = mode === 'acme' && acmeEligible;
        const label = certificateLabel(certificate, status, { served, canRequest });

        return {
            hostname,
            isServiceHostname: !extraHostnames.includes(hostname),
            acmeEligible,
            canRequest,
            wanted: wantsCertificate({ canRequest, status, certificate, label }),
            certificate: publicView(certificate),
            label,
            status,
            // The one line the page shows under the name: why the last order failed, why a request
            // was declined, or that one is under way. The page script paints the same states from
            // the change feed, so its table (views/config/tls.hbs) mirrors STATUS_VARIANTS.
            reason:
                status && REASON_STATES.has(status.state) && status.message
                    ? { variant: STATUS_VARIANTS[status.state] || 'info', message: status.message }
                    : null
        };
    });

    return {
        mode,
        serviceUrl: values.serviceUrl || '',
        hostnames,
        certificates,
        served,
        // Whether the page-level "Request certificates" action has anything to do
        anyWanted: certificates.some(entry => entry.wanted),
        manual: publicView(manual),
        selfSigned: publicView(selfSigned),
        acme: {
            directoryUrl: ACME_DIRECTORY_URL,
            environment: ACME_ENVIRONMENT,
            // A staging certificate is signed by a root nobody trusts, and the badge would
            // otherwise call it valid.
            staging: /staging/i.test(ACME_DIRECTORY_URL)
        }
    };
}

module.exports = {
    buildCertificateStatus,
    certificateLabel,
    summarizeLabels,
    listenerCertificateSummary,
    publicView,
    rehydrateReport,
    SOURCE_LABELS
};
