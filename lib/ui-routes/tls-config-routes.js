'use strict';

// Admin UI routes for TLS certificates (/admin/config/tls).
//
// Certificates used to be configured from a checkbox on two other pages. Ticking it ordered one in
// the foreground, before the setting it belonged to had been saved, and a failure silently unticked
// it. There was nowhere to see what was installed, no way to upload a certificate, and no way to
// find out why an order had failed.
//
// This page separates the things that checkbox conflated: which names EmailEngine serves, where
// the certificate for them comes from, which certificate each listener presents by default, and
// which listeners use TLS. The last of those stays on the SMTP and IMAP proxy pages, because it is
// part of what those servers are; this page shows it read-only alongside the certificate each
// listener is actually serving.
//
// The page is status first: what each listener serves, then one row per hostname. Hostnames are
// added and removed from that table and post immediately, the way every other list on the admin
// surface is edited; the settings form left over holds one radio group. Uploading a certificate
// has a page of its own, because three PEM fields do not fit a card on a page that is mostly
// about reading.

const Joi = require('joi');

const settings = require('../settings');
const { failAction, reloadTlsCertificates, maybeReloadTlsCertificates, redactValidationError } = require('../tools');
const { settingsSchema } = require('../schemas');
const { getServerStatus } = require('./route-helpers');
const { registerSettingsPage } = require('./settings-page');
const {
    getCertificateHostnames,
    hostnamesFrom,
    extraHostnamesFrom,
    tlsSettingChanged,
    peekManualCertificate,
    setManualCertificate,
    deleteManualCertificate,
    deleteSelfSignedCertificate,
    getSelfSignedCertificate,
    normalizeHostname
} = require('../tls/store');
const { buildCertificateStatus, listenerCertificateSummary, summarizeLabels, publicView, reportedListenerTls } = require('../tls/status');
const { runPreflight, resolvePreflightProbe, clearProvisioningStatus } = require('../tls/provision');
const { LISTENERS, TLS_CERTIFICATE_SETTINGS, AUTO, MANUAL_ID, SELF_SIGNED_ID } = require('../tls/listeners');
const { requestedCertificate, isSelectable, listCertificates } = require('../tls/catalog');

// Certificates and keys are pasted into a textarea. A generous ceiling that still refuses a file
// upload dressed as a certificate: a full chain with a 4096 bit leaf is a few kilobytes.
const MAX_PEM_SIZE = 128 * 1024;

const TLS_PAGE = '/admin/config/tls';
const UPLOAD_PAGE = '/admin/config/tls/upload';

const configTlsSchema = {
    tlsProvisioning: settingsSchema.tlsProvisioning.default('acme')
};

const EMPTY_HOSTNAME_MESSAGE = 'Enter a hostname to add';

/**
 * Folds one typed hostname the way the certificate stores spell it.
 *
 * @param {string} value Raw form input
 * @returns {string} Hostname, empty when there was none
 */
function parseHostname(value) {
    // A name copied out of a URL keeps the brackets an IPv6 literal wears there; a certificate
    // name has none. Everything else about the fold is the one the certificate stores use.
    return normalizeHostname(value).replace(/^\[|\]$/g, '');
}

/**
 * Validates one hostname against the schema the REST API applies to the list, so the form is not
 * the one way to store a "hostname" that no certificate could ever be issued for.
 *
 * @param {string} value Raw form input
 * @returns {string} The folded hostname
 * @throws {Error} When the name is empty or the schema refuses it
 */
function validateHostname(value) {
    const hostname = parseHostname(value);
    const parsed = settingsSchema.tlsHostnames.validate(hostname ? [hostname] : []);

    if (!hostname || parsed.error) {
        throw new Error(hostname ? `Not a valid hostname: ${parsed.error.message}` : EMPTY_HOSTNAME_MESSAGE);
    }

    return hostname;
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
        path: TLS_PAGE,
        view: 'config/tls',
        pageTitle: 'TLS Certificates',
        menuKey: 'menuConfigTls',
        schema: configTlsSchema,

        async loadValues() {
            return {
                tlsProvisioning: (await settings.get('tlsProvisioning')) || 'acme'
            };
        },

        viewContext: async (request, values, h) => await tlsPageContext(h),

        async applySettings(request) {
            const mode = request.payload.tlsProvisioning;
            const changed = tlsSettingChanged('tlsProvisioning', await settings.get('tlsProvisioning'), mode);

            await settings.set('tlsProvisioning', mode);

            // The listeners resolve their material against the source mode, so a change here is
            // what they should be offering from now on. Left alone when nothing changed: a reload
            // for a save that wrote the same value would only churn the secure contexts.
            await maybeReloadTlsCertificates(call, request.logger, changed ? ['tlsProvisioning'] : [], { action: 'settings' });
        }
    });

    // Hostnames are rows of the certificate table, added and removed one at a time. Each write
    // reloads the listeners: they resolve their material against the hostname list, and the
    // self-signed fallback is regenerated when that list no longer matches what it covers. Without
    // the reload a name added here is served the previous certificate until something else restarts
    // the worker, and the page would report a certificate the listener is not using.
    server.route({
        method: 'POST',
        path: '/admin/config/tls/hostnames',
        async handler(request, h) {
            try {
                const hostname = validateHostname(request.payload.hostname);

                // One read serves both the duplicate check (against every configured name, the
                // Service URL's included) and the list the name is appended to
                const values = await settings.getMulti('serviceUrl', 'tlsHostnames');

                if (hostnamesFrom(values).includes(hostname)) {
                    await request.flash({ type: 'info', message: `${hostname} is already listed` });
                    return h.redirect(TLS_PAGE);
                }

                await settings.set('tlsHostnames', extraHostnamesFrom(values).concat(hostname));
                await reloadTlsCertificates(call, request.logger, { action: 'settings' });

                await request.flash({ type: 'info', message: `Added ${hostname}` });
            } catch (err) {
                request.logger.error({ msg: 'Failed to add a certificate hostname', err });
                await request.flash({ type: 'danger', message: err.message });
            }

            return h.redirect(TLS_PAGE);
        },
        options: {
            validate: {
                options: { stripUnknown: true, abortEarly: false, convert: true },

                async failAction(request, h, err) {
                    request.logger.error({ msg: 'Failed to validate a certificate hostname', err });
                    await request.flash({ type: 'danger', message: EMPTY_HOSTNAME_MESSAGE });
                    return h.redirect(TLS_PAGE).takeover();
                },

                payload: Joi.object({
                    crumb: Joi.string().max(1024),
                    hostname: Joi.string().max(255).required()
                })
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/config/tls/hostnames/delete',
        async handler(request, h) {
            try {
                const hostname = parseHostname(request.payload.hostname);
                const values = await settings.getMulti('serviceUrl', 'tlsHostnames');
                const extra = extraHostnamesFrom(values);

                if (!extra.includes(hostname)) {
                    throw new Error(
                        hostnamesFrom(values).includes(hostname)
                            ? 'The Service URL hostname is set on the General page and is always served'
                            : `${hostname} is not listed`
                    );
                }

                // The recorded order state would otherwise describe a name the table no longer has
                // a row for. The issued certificate itself is kept: a name that comes back gets it
                // again instead of a second order against the rate limit. Two independent keys, so
                // the writes go out together; only the reload has to follow both.
                await Promise.all([
                    settings.set(
                        'tlsHostnames',
                        extra.filter(entry => entry !== hostname)
                    ),
                    clearProvisioningStatus(hostname)
                ]);
                await reloadTlsCertificates(call, request.logger, { action: 'settings' });

                await request.flash({ type: 'info', message: `Removed ${hostname}` });
            } catch (err) {
                request.logger.error({ msg: 'Failed to remove a certificate hostname', err });
                await request.flash({ type: 'danger', message: err.message });
            }

            return h.redirect(TLS_PAGE);
        },
        options: {
            validate: {
                options: { stripUnknown: true, abortEarly: false, convert: true },

                async failAction(request, h, err) {
                    request.logger.error({ msg: 'Failed to validate a certificate hostname removal', err });
                    return h.redirect(TLS_PAGE).takeover();
                },

                payload: Joi.object({
                    crumb: Joi.string().max(1024),
                    hostname: Joi.string().max(255).required()
                })
            }
        }
    });

    // Which certificate each listener presents by default. One form for the three listeners,
    // posted with a Save button rather than on change: a wrong default is what a client sees on
    // its next handshake, and three dropdowns that each reload every listener the moment they are
    // touched is three chances to do that by accident.
    server.route({
        method: 'POST',
        path: '/admin/config/tls/listeners',
        async handler(request, h) {
            try {
                // Checked against what exists rather than against the schema alone: the schema
                // knows the shape of an id, not whether a certificate answers to it, and a
                // listener told to present nothing would silently fall back to its automatic
                // choice while the page showed the choice as saved
                const values = await settings.getMulti('serviceUrl', 'tlsHostnames', ...TLS_CERTIFICATE_SETTINGS);
                const catalog = await listCertificates({ certs: h.certs, hostnames: hostnamesFrom(values) });
                const available = new Set(catalog.filter(isSelectable).map(entry => entry.id));

                const changed = [];
                for (const listener of LISTENERS) {
                    const requested = requestedCertificate(request.payload[listener.settingKey]);
                    if (requested !== AUTO && !available.has(requested)) {
                        throw new Error(`${listener.name}: the selected certificate (${requested}) is not available`);
                    }
                    const value = requested === AUTO ? null : requested;
                    if (tlsSettingChanged(listener.settingKey, values[listener.settingKey], value)) {
                        changed.push({ key: listener.settingKey, value });
                    }
                }

                for (const { key, value } of changed) {
                    await settings.set(key, value);
                }

                // The listeners resolve their default against these, so a change is what they
                // should be presenting from now on. Left alone when nothing changed: a reload for
                // a save that wrote the same values would only churn the secure contexts.
                await maybeReloadTlsCertificates(
                    call,
                    request.logger,
                    changed.map(entry => entry.key),
                    { action: 'settings' }
                );

                await request.flash({ type: 'info', message: changed.length ? 'Updated which certificate each listener presents' : 'No changes to save' });
            } catch (err) {
                request.logger.error({ msg: 'Failed to update the listener default certificates', err });
                await request.flash({ type: 'danger', message: err.message });
            }

            return h.redirect(TLS_PAGE);
        },
        options: {
            validate: {
                options: { stripUnknown: true, abortEarly: false, convert: true },

                async failAction(request, h, err) {
                    request.logger.error({ msg: 'Failed to validate the listener default certificates', err });
                    await request.flash({ type: 'danger', message: 'The selected certificate is not a valid choice' });
                    return h.redirect(TLS_PAGE).takeover();
                },

                payload: Joi.object(
                    Object.assign({ crumb: Joi.string().max(1024) }, Object.fromEntries(TLS_CERTIFICATE_SETTINGS.map(key => [key, settingsSchema[key]])))
                )
            }
        }
    });

    server.route({
        method: 'GET',
        path: UPLOAD_PAGE,
        async handler(request, h) {
            return h.view(
                'config/tls-upload',
                {
                    pageTitle: 'Upload a certificate',
                    menuConfig: true,
                    menuConfigTls: true,
                    manual: publicView(await peekManualCertificate())
                },
                { layout: 'app' }
            );
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
                // Back to the form, so the operator can fix the one field that was refused
                return h.redirect(UPLOAD_PAGE);
            }

            return h.redirect(TLS_PAGE);
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
                    return h.redirect(UPLOAD_PAGE).takeover();
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
                // A listener that was told to present the removed certificate keeps the setting
                // and presents its automatic choice, and the page says so under its dropdown: the
                // same thing happens when the certificate goes away through the REST API, and one
                // outcome for one event is worth more than a tidier setting on one of the paths
                switch (request.payload.certificate) {
                    case MANUAL_ID:
                        await deleteManualCertificate();
                        await request.flash({ type: 'info', message: 'Removed the uploaded certificate' });
                        break;

                    case SELF_SIGNED_ID:
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

            return h.redirect(TLS_PAGE);
        },
        options: {
            validate: {
                options: { stripUnknown: true, abortEarly: false, convert: true },

                async failAction(request, h, err) {
                    request.logger.error({ msg: 'Failed to validate a certificate removal', err });
                    return h.redirect(TLS_PAGE).takeover();
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
 * The whole page model: the certificate for every configured name, every certificate the instance
 * holds, and the listeners with the default each is set to and what each is serving right now.
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
    const listenerReads = Promise.all([getServerStatus('smtp'), getServerStatus('imapProxy')]);

    // What each listener says it is serving, keyed the way the model lists them.
    const reports = listenerReads.then(([smtp, imapProxy]) => ({
        api: apiTls.active || null,
        smtp: reportedListenerTls(smtp),
        imapProxy: reportedListenerTls(imapProxy)
    }));

    // The model wants to know whether anything is served at all - a listener reporting a
    // certificate is what says a name is presented to clients. Built alongside the listener
    // reads rather than after them, so the page still costs one round of latency and not two.
    const [[smtpState, imapProxyState], reported, status] = await Promise.all([
        listenerReads,
        reports,
        buildCertificateStatus({ certs: h.certs, served: reports.then(entries => Object.values(entries).some(report => report)) })
    ]);

    // The name clients connect to, and the order state recorded for it, for the summary a listener's
    // report is described with. Described the way the certificate table on this same page
    // describes one, so a listener's certificate cannot read differently depending on where it is
    // shown.
    const primary = status.certificates[0] || null;
    const serving = report =>
        listenerCertificateSummary({ reported: report, hostname: primary ? primary.hostname : null, status: primary ? primary.status : null });

    const states = { smtp: smtpState.label, imapProxy: imapProxyState.label };

    // A server listener that reports no certificate gets one sentence saying why. The template
    // adds the link to the listener's own page when switching something on there is the next
    // step; the API listener has no such page, its TLS is an environment switch.
    const listeners = status.listeners.map(listener => {
        const server = !!listener.configuredAt;
        return Object.assign({}, listener, {
            state: states[listener.key] || null,
            serving: serving(reported[listener.key]),
            hint: !server
                ? null
                : !listener.enabled
                  ? 'The server is disabled.'
                  : listener.tlsEnabled
                    ? 'TLS is on, but the listener has not reported a certificate yet.'
                    : 'TLS is off.',
            needsSetup: server && (!listener.enabled || !listener.tlsEnabled)
        });
    });

    // The header badge: the worst of what the listeners serve and, once something is served, of
    // the rows too, so a failed order for one name is not hidden behind a green tile
    const labels = listeners.map(listener => listener.serving.label);
    if (status.served) {
        labels.push(...status.certificates.map(entry => entry.label));
    }

    return Object.assign({}, status, { listeners, pageLabel: summarizeLabels(labels) });
}

module.exports = init;
module.exports.parseHostname = parseHostname;
module.exports.validateHostname = validateHostname;
module.exports.tlsPageContext = tlsPageContext;
