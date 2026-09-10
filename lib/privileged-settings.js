'use strict';

// The settings a narrowed credential may never read or write: what assertNoPrivilegedSettings()
// in lib/api-routes/route-helpers.js refuses on GET and POST /v1/settings, and what the two MCP
// settings tools leave out of their schemas (MCP_SETTINGS_KEYS in lib/api-routes/settings-routes.js).
// `read/settings` and `write/settings` are grantable permissions, and the settings blob is the one
// endpoint whose fields span every trust level, so these are the keys that would make a settings
// editor more than a settings editor.
//
// Grouped by the reason each cluster is on the list, and each group carries the words every
// description of the rule uses for it: the settings tools, the `settings` permission group in the
// OpenAPI document and the token form all render PRIVILEGED_SETTINGS_SUMMARY, so a key added here
// is described everywhere at once rather than in copies that drift.
//
// A leaf module on purpose: lib/enum-descriptions.js is pure prose loaded by lib/schemas.js, and
// lib/settings.js opens Redis, so the list has to live below both. The TLS listener table is the
// one import, dependency-free for the same reason (lib/tls/listeners.js).

const { TLS_CERTIFICATE_SETTINGS } = require('./tls/listeners');

const PRIVILEGED_SETTINGS_GROUPS = [
    {
        // Operator code run inside the instance, and the environment it sees
        label: 'operator scripts',
        keys: ['openAiPreProcessingFn', 'scriptEnv']
    },
    {
        // Signs hosted authentication links and unsubscribe links
        label: 'the link signing secret',
        keys: ['serviceSecret']
    },
    {
        // Where account credentials are fetched from
        label: 'the authentication server',
        keys: ['authServer']
    },
    {
        // Trust of X-Forwarded-For, which the admin address perimeter is checked against, and the
        // outbound address list
        label: 'proxy trust and local addresses',
        keys: ['enableApiProxy', 'localAddresses']
    },
    {
        // Every IMAP, SMTP and HTTP connection, credentials included, goes through these
        label: 'proxies',
        keys: ['proxyEnabled', 'proxyUrl', 'httpProxyEnabled', 'httpProxyUrl']
    },
    {
        // The built-in listeners: what they are, where they bind, whether they demand a credential
        // and whether they speak TLS. The SMTP submission server's authentication switch is the
        // sharpest of these - with it off, the server takes the sending account from a client
        // header, so a settings grant would turn into unauthenticated sending as any account - but a
        // narrowed credential must not move a listener onto a public interface or downgrade it to
        // cleartext either, however delayed the restart that applies it.
        label: 'the built-in listeners',
        keys: [
            'smtpServerEnabled',
            'smtpServerHost',
            'smtpServerPort',
            'smtpServerAuthEnabled',
            'smtpServerPassword',
            'smtpServerProxy',
            'smtpServerTLSEnabled',
            'imapProxyServerEnabled',
            'imapProxyServerHost',
            'imapProxyServerPort',
            'imapProxyServerPassword',
            'imapProxyServerProxy',
            'imapProxyServerTLSEnabled'
        ]
    },
    {
        // Which stored certificate each listener presents, the API's included, and the mode that
        // decides which certificates may be served at all: switched to self-signed, every listener
        // presents the unverifiable certificate, which is a downgrade for every client that checks
        // and an opening for the ones told not to. The hostname list places orders with the CA.
        label: 'TLS certificates and provisioning',
        keys: [...TLS_CERTIFICATE_SETTINGS, 'tlsProvisioning', 'tlsHostnames']
    },
    {
        // The origin everything else is anchored to: the first hostname certificates are ordered
        // for, the issuer and resource the MCP OAuth discovery documents name, where the hosted
        // setup links point (the form where end users type mail passwords), and the signal that
        // marks the cookies Secure. A settings editor that could move it would re-anchor all of
        // that at once. notificationBaseUrl, the documented override, stays ordinary: it only names
        // where Microsoft Graph delivers its change notifications, which carry no content.
        label: 'the service URL',
        keys: ['serviceUrl']
    },
    {
        // Switches certificate checking off for every IMAP and SMTP connection the instance makes,
        // which is the on-path reader's way to the account credentials
        label: 'mail certificate checking',
        keys: ['ignoreMailCertErrors']
    },
    {
        // The AI key, and the base URL it is sent to: a narrowed credential that could point the
        // latter at its own host would receive the former as a bearer header on the next request
        label: 'the AI key and endpoint',
        keys: ['openAiAPIKey', 'openAiAPIUrl']
    },
    {
        // Credential-bearing (the example is an Authorization header)
        label: 'custom webhook headers',
        keys: ['webhooksCustomHeaders']
    },
    {
        // HTML injected into the hosted pages, where end users type mail passwords
        label: 'hosted page markup',
        keys: ['templateHeader', 'templateHtmlHead']
    },
    {
        // A credential must not change the door it came through, enable credential issuance, or
        // switch off its own audit trail
        label: 'the MCP and audit switches',
        keys: ['mcpEnabled', 'mcpOAuthEnabled', 'tokenAuditLog']
    },
    {
        // The deprecated Document Store's endpoint and credentials
        label: 'the Document Store',
        keys: [
            'documentStoreEnabled',
            'documentStoreUrl',
            'documentStoreIndex',
            'documentStoreAuthEnabled',
            'documentStoreUsername',
            'documentStorePassword',
            'documentStoreGenerateEmbeddings',
            'documentStorePreProcessingEnabled'
        ]
    },
    {
        // The error reporting target
        label: 'error reporting',
        keys: ['sentryEnabled', 'sentryDsn']
    }
];

const PRIVILEGED_SETTINGS_KEYS = PRIVILEGED_SETTINGS_GROUPS.flatMap(group => group.keys);

// The groups as one phrase, "operator scripts, the link signing secret, ..., and error reporting",
// for every description that says what a narrowed credential is refused
const PRIVILEGED_SETTINGS_SUMMARY = new Intl.ListFormat('en', { style: 'long', type: 'conjunction' }).format(
    PRIVILEGED_SETTINGS_GROUPS.map(group => group.label)
);

module.exports = { PRIVILEGED_SETTINGS_GROUPS, PRIVILEGED_SETTINGS_KEYS, PRIVILEGED_SETTINGS_SUMMARY };
