'use strict';

// The listeners that terminate TLS, and the grammar of a certificate id. Nothing else: this is
// required by lib/tools.js (the reload contract), lib/schemas.js (the settings schema) and
// lib/tls/catalog.js alike, so it must not require any of them back.
//
// Ids are stable strings, because they are stored in settings and posted by forms:
//
//   env:api, env:smtp, env:imapProxy   material from that listener's environment prefix or the
//                                      config file
//   manual                             the certificate uploaded through the admin UI
//   acme:<hostname>                    the Let's Encrypt certificate for that configured name
//   self-signed                        the generated fallback covering every configured name
//
// `auto` is not an id: it is what a listener's setting holds when EmailEngine is to decide.

// In the order the page lists them. `settingKey` holds the id of the certificate that listener
// presents by default; `envPrefix` is where its own operator-supplied material comes from.
const LISTENERS = Object.freeze([
    Object.freeze({
        key: 'api',
        name: 'Admin UI and API',
        // No page of its own: TLS for this listener is an environment switch, not a setting
        configuredAt: null,
        envPrefix: 'EENGINE_API_TLS_',
        envNote: 'EENGINE_API_TLS_* or [api.tls] in the config file',
        settingKey: 'apiTLSCertificate'
    }),
    Object.freeze({
        key: 'smtp',
        name: 'SMTP server',
        configuredAt: '/admin/config/smtp',
        envPrefix: 'EENGINE_SMTP_TLS_',
        envNote: 'EENGINE_SMTP_TLS_*',
        settingKey: 'smtpServerTLSCertificate'
    }),
    Object.freeze({
        key: 'imapProxy',
        name: 'IMAP proxy',
        configuredAt: '/admin/config/imap-proxy',
        envPrefix: 'EENGINE_IMAPPROXY_TLS_',
        envNote: 'EENGINE_IMAPPROXY_TLS_*',
        settingKey: 'imapProxyServerTLSCertificate'
    })
]);

// The settings that name each listener's default certificate
const TLS_CERTIFICATE_SETTINGS = Object.freeze(LISTENERS.map(listener => listener.settingKey));

const AUTO = 'auto';
const MANUAL_ID = 'manual';
const SELF_SIGNED_ID = 'self-signed';

// What a setting may hold. The acme part is a hostname the way the certificate stores spell one,
// lower-cased; the listener part is case-sensitive because the ids are, and a form never types them.
const CERTIFICATE_ID_PATTERN = /^(auto|manual|self-signed|env:(api|smtp|imapProxy)|acme:[a-z0-9._:-]+)$/;

function listenerByKey(key) {
    return LISTENERS.find(listener => listener.key === key) || null;
}

module.exports = { LISTENERS, TLS_CERTIFICATE_SETTINGS, AUTO, MANUAL_ID, SELF_SIGNED_ID, CERTIFICATE_ID_PATTERN, listenerByKey };
