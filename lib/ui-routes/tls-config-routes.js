'use strict';

// Admin UI routes for TLS certificates (/admin/config/tls).
//
// Certificates used to be configured from a checkbox on two other pages. Ticking it ordered one in
// the foreground, before the setting it belonged to had been saved, and a failure silently unticked
// it. There was nowhere to see what was installed, no way to upload a certificate, and no way to
// find out why an order had failed.
//
// This page separates the three things that checkbox conflated: which names EmailEngine serves,
// where the certificate for them comes from, and which listeners use TLS. The last of those stays
// on the SMTP and IMAP proxy pages, because it is part of what those servers are; this page shows
// it read-only alongside the certificate each listener is actually serving.

const Joi = require('joi');

const settings = require('../settings');
const { failAction, reloadTlsCertificates, redactValidationError } = require('../tools');
const { settingsSchema } = require('../schemas');
const { getServerStatus } = require('./route-helpers');
const { registerSettingsPage } = require('./settings-page');
const {
    getCertificateHostnames,
    setManualCertificate,
    deleteManualCertificate,
    deleteSelfSignedCertificate,
    getSelfSignedCertificate,
    normalizeHostname
} = require('../tls/store');
const { buildCertificateStatus, publicView, rehydrateReport } = require('../tls/status');
const { runPreflight, resolvePreflightProbe, clearProvisioningStatus } = require('../tls/provision');

// Certificates and keys are pasted into a textarea. A generous ceiling that still refuses a file
// upload dressed as a certificate: a full chain with a 4096 bit leaf is a few kilobytes.
const MAX_PEM_SIZE = 128 * 1024;

const configTlsSchema = {
    tlsProvisioning: settingsSchema.tlsProvisioning.default('acme'),
    tlsHostnames: Joi.string().empty('').max(4096).default('')
};

/**
 * Turns the textarea into the hostname list the settings store holds.
 *
 * @param {string} value Raw textarea contents
 * @returns {string[]} Hostnames, deduplicated
 */
function parseHostnameList(value) {
    const seen = new Set();

    for (const entry of (value || '').toString().split(/[\s,]+/)) {
        // A name copied out of a URL keeps the brackets an IPv6 literal wears there; a certificate
        // name has none. Everything else about the fold is the one the certificate stores use.
        const hostname = normalizeHostname(entry).replace(/^\[|\]$/g, '');
        if (hostname) {
            seen.add(hostname);
        }
    }

    return Array.from(seen);
}

/**
 * Refuses a hostname this instance has not been configured to serve.
 *
 * Both the preflight and the provisioning request take a hostname from the browser, and both then
 * act on it: one makes an HTTP request to it, the other asks a CA to validate it. Neither is a
 * reason to accept an arbitrary name from a form post, even an admin-authenticated one.
 *
 * @param {string} hostname Name from the request
 * @returns {Promise<string>} The same name, once it is known
 */
async function assertConfiguredHostname(hostname) {
    const configured = await getCertificateHostnames();
    const name = normalizeHostname(hostname);

    if (!configured.includes(name)) {
        let err = new Error('This hostname is not configured for this instance');
        err.code = 'UnknownHostname';
        throw err;
    }

    return name;
}

function init(args) {
    const { server, call } = args;

    // The path Let's Encrypt fetches to validate a domain, and the only unauthenticated route on
    // this module. It lives here rather than in the routes-ui monolith because it is part of the
    // certificate story, and because the preflight probe below shares its token store.
    server.route({
        method: 'GET',
        path: '/.well-known/acme-challenge/{token}',
        async handler(request, h) {
            let domain = (request.headers.host || '').toString().replace(/:.*$/g, '').trim().toLowerCase();

            // A preflight probe: the admin UI asked this instance to fetch its own challenge path
            // over the public name, to find out whether Let's Encrypt will be able to. The token
            // is random, lives for two minutes, and is answered before anything else, so a probe
            // never reaches the certificate library and cannot be confused with a real challenge.
            let probe = await resolvePreflightProbe(request.params.token);
            if (probe) {
                return h.response(probe).type('application/octet-stream');
            }

            let challenge;
            try {
                // Resolves to the key authorization or throws with a responseCode; it has no third
                // answer, so there is nothing to check the result for.
                challenge = await h.certs.routeHandler(domain, request.params.token);
            } catch (err) {
                // routeHandler() reports the status as responseCode, so reading statusCode turned
                // an unknown token into a 500 rather than the 404 it is
                return h
                    .response(
                        `Request failed: ${err.message}
Domain: ${JSON.stringify(domain)}
Token: ${JSON.stringify(request.params.token)}`
                    )
                    .type('text/plain')
                    .code(err.responseCode || 500);
            }

            // RFC 8555 section 8.3: the key authorization is the whole body, compared byte for byte
            return h.response(challenge).type('application/octet-stream');
        },

        options: {
            auth: false
        }
    });

    registerSettingsPage(server, {
        path: '/admin/config/tls',
        view: 'config/tls',
        pageTitle: 'TLS Certificates',
        menuKey: 'menuConfigTls',
        schema: configTlsSchema,

        async loadValues() {
            const values = await settings.getMulti('tlsProvisioning', 'tlsHostnames');
            return {
                tlsProvisioning: values.tlsProvisioning || 'acme',
                tlsHostnames: [].concat(values.tlsHostnames || []).join('\n')
            };
        },

        viewContext: async (request, values, h) => await tlsPageContext(h),

        async applySettings(request) {
            // The textarea is validated as free text, so what comes out of it is validated against
            // the same schema the REST API applies to this setting. Otherwise the form is the one
            // way to store a "hostname" that no certificate could ever be issued for.
            const parsed = settingsSchema.tlsHostnames.validate(parseHostnameList(request.payload.tlsHostnames));
            if (parsed.error) {
                let err = new Error(parsed.error.message);
                err.details = { tlsHostnames: `Not a valid hostname: ${parsed.error.message}` };
                throw err;
            }

            const hostnames = parsed.value || [];

            await settings.setMulti({
                tlsProvisioning: request.payload.tlsProvisioning,
                tlsHostnames: hostnames
            });

            // The listeners resolve their material against the hostname list and the source mode,
            // and the self-signed fallback is regenerated when that list no longer matches what it
            // covers. Without this a name added here is served the previous certificate until
            // something else restarts the worker, and the page would report a certificate the
            // listener is not using. State for names that are no longer served is cleaned up by
            // the reconciler, which sees changes made through the REST API too.
            await reloadTlsCertificates(call, request.logger, { action: 'settings' });
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/config/tls/request',
        async handler(request, h) {
            try {
                const hostnames = request.payload.hostname ? [await assertConfiguredHostname(request.payload.hostname)] : await getCertificateHostnames();

                // Through the toolkit, because ordering needs the provisioning-capable handle and
                // routes are only given the read-only one.
                const { accepted, declined } = await h.requestCertificates(hostnames, request.logger);

                // A decline is an answer, not a failure: it is why nothing will happen, and the
                // page has to say so rather than leaving a badge reading "Requesting" forever.
                if (!accepted.length && declined.length) {
                    return { success: false, error: declined[0].reason };
                }

                return { success: true, hostnames: accepted };
            } catch (err) {
                request.logger.error({ msg: 'Failed to request a certificate', err });
                return { success: false, error: err.message };
            }
        },
        options: {
            validate: {
                options: { stripUnknown: true, abortEarly: false, convert: true },
                failAction,
                payload: Joi.object({
                    crumb: Joi.string().max(1024),
                    hostname: Joi.string().empty('').max(255)
                })
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/config/tls/preflight',
        async handler(request) {
            try {
                const hostname = await assertConfiguredHostname(request.payload.hostname);
                return Object.assign({ success: true }, await runPreflight({ hostname, logger: request.logger }));
            } catch (err) {
                request.logger.error({ msg: 'Certificate preflight failed', err });
                return { success: false, error: err.message };
            }
        },
        options: {
            validate: {
                options: { stripUnknown: true, abortEarly: false, convert: true },
                failAction,
                payload: Joi.object({
                    crumb: Joi.string().max(1024),
                    hostname: Joi.string().max(255).required()
                })
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/config/tls/upload',
        async handler(request, h) {
            try {
                const stored = await setManualCertificate({
                    cert: request.payload.cert,
                    ca: request.payload.ca,
                    privateKey: request.payload.privateKey,
                    passphrase: request.payload.passphrase
                });

                // An uploaded certificate is only useful once the listeners serve it, and they do
                // not poll for one.
                await reloadTlsCertificates(call, request.logger, { source: 'manual' });

                await request.flash({
                    type: 'info',
                    message: `Installed the certificate for ${(stored.altNames || []).join(', ') || stored.subject}`
                });
            } catch (err) {
                request.logger.error({ msg: 'Failed to store an uploaded certificate', err });
                await request.flash({ type: 'danger', message: err.message });
            }

            return h.redirect('/admin/config/tls');
        },
        options: {
            validate: {
                options: { stripUnknown: true, abortEarly: false, convert: true },

                async failAction(request, h, err) {
                    // The rejected payload is a private key and its passphrase, and a joi error
                    // carries the submitted values in four places. The global redaction list covers
                    // them, but this is the one place in the codebase where the value being logged
                    // is definitely a private key, so it does not lean on that alone.
                    request.logger.error({ msg: 'Failed to validate an uploaded certificate', err: redactValidationError(err) });
                    await request.flash({ type: 'danger', message: 'The certificate or key was not accepted. Check that both are PEM encoded.' });
                    return h.redirect('/admin/config/tls').takeover();
                },

                payload: Joi.object({
                    crumb: Joi.string().max(1024),
                    cert: Joi.string().max(MAX_PEM_SIZE).required(),
                    ca: Joi.string().empty('').max(MAX_PEM_SIZE).default(''),
                    privateKey: Joi.string().max(MAX_PEM_SIZE).required(),
                    passphrase: Joi.string().empty('').max(1024).default('')
                })
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/config/tls/delete',
        async handler(request, h) {
            try {
                switch (request.payload.certificate) {
                    case 'manual':
                        await deleteManualCertificate();
                        await request.flash({ type: 'info', message: 'Removed the uploaded certificate' });
                        break;

                    case 'self-signed':
                        await deleteSelfSignedCertificate();
                        // Regenerated immediately rather than on the next handshake, so the
                        // fingerprint the page shows after this is the one clients will see.
                        await getSelfSignedCertificate(await getCertificateHostnames(), request.logger);
                        await request.flash({ type: 'info', message: 'Generated a new self-signed certificate' });
                        break;

                    default: {
                        const hostname = await assertConfiguredHostname(request.payload.certificate);
                        await h.certs.deleteCertificateData(hostname);
                        await clearProvisioningStatus(hostname);
                        await request.flash({ type: 'info', message: `Removed the certificate for ${hostname}` });
                        break;
                    }
                }

                await reloadTlsCertificates(call, request.logger, { action: 'delete' });
            } catch (err) {
                request.logger.error({ msg: 'Failed to remove a certificate', err });
                await request.flash({ type: 'danger', message: err.message });
            }

            return h.redirect('/admin/config/tls');
        },
        options: {
            validate: {
                options: { stripUnknown: true, abortEarly: false, convert: true },

                async failAction(request, h, err) {
                    request.logger.error({ msg: 'Failed to validate a certificate removal', err });
                    return h.redirect('/admin/config/tls').takeover();
                },

                payload: Joi.object({
                    crumb: Joi.string().max(1024),
                    // Not "target": a form control named `target` shadows HTMLFormElement.target,
                    // and the shared busy-button handler reads that property on every submit.
                    certificate: Joi.string().max(255).required()
                })
            }
        }
    });
}

/**
 * The whole page model: the certificate for every configured name, the stored sources, and the
 * listeners with what each of them is serving right now.
 *
 * A listener reports its own certificate in its state payload rather than having it inferred here.
 * Inferring it would describe what the listener would load if it started now, which is not the same
 * thing as what it is serving, and the difference is exactly the case an operator is looking at
 * this page to understand.
 *
 * @param {Object} h Hapi response toolkit
 * @returns {Promise<Object>} View context
 */
async function tlsPageContext(h) {
    const apiTls = h.apiTlsInfo();

    // Independent reads, so the page costs one round of latency rather than three.
    const listenerReads = Promise.all([
        getServerStatus('smtp'),
        getServerStatus('imapProxy'),
        settings.getMulti('smtpServerEnabled', 'smtpServerTLSEnabled', 'imapProxyServerEnabled', 'imapProxyServerTLSEnabled')
    ]);

    // What each listener says it is serving, in the order the listener list below is built in.
    const reports = listenerReads.then(([smtp, imapProxy]) => [
        apiTls.active || null,
        (smtp.payload && smtp.payload.tls) || null,
        (imapProxy.payload && imapProxy.payload.tls) || null
    ]);

    // The model needs those reports: material supplied through the TLS environment variables is per
    // listener and per process, so a name served only that way has nothing stored for it and would
    // otherwise be described as having no certificate. It is built alongside the listener reads
    // rather than after them, so the page still costs one round of latency and not two.
    const [[smtpState, imapProxyState, serverSettings], reported, status] = await Promise.all([
        listenerReads,
        reports,
        buildCertificateStatus({ certs: h.certs, reported: reports })
    ]);

    // Described the way the certificate table on this same page describes one, so a listener's
    // certificate cannot read differently depending on where it is shown.
    const serving = report => (report ? publicView(rehydrateReport(report)) : null);

    const listeners = [
        {
            key: 'api',
            name: 'Admin UI and REST API',
            configuredAt: null,
            enabled: true,
            tlsEnabled: apiTls.enabled,
            hint: apiTls.enabled ? 'HTTPS is on through EENGINE_API_TLS' : 'Serving plain HTTP. Set EENGINE_API_TLS=true to serve HTTPS directly.',
            active: serving(reported[0])
        },
        {
            key: 'smtp',
            name: 'SMTP server',
            configuredAt: '/admin/config/smtp',
            enabled: !!serverSettings.smtpServerEnabled,
            tlsEnabled: !!serverSettings.smtpServerTLSEnabled,
            state: smtpState.label,
            active: serving(reported[1])
        },
        {
            key: 'imapProxy',
            name: 'IMAP proxy',
            configuredAt: '/admin/config/imap-proxy',
            enabled: !!serverSettings.imapProxyServerEnabled,
            tlsEnabled: !!serverSettings.imapProxyServerTLSEnabled,
            state: imapProxyState.label,
            active: serving(reported[2])
        }
    ];

    return Object.assign({}, status, { listeners });
}

module.exports = init;
module.exports.parseHostnameList = parseHostnameList;
module.exports.tlsPageContext = tlsPageContext;
