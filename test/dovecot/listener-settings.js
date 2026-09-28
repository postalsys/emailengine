'use strict';

// Settings the dovecot tier boots its server with (test/run-tests.js merges them into the prepared
// settings from config/test.toml through EENGINE_SETTINGS), shared with dovecot-live-test.js so
// the test knows where the listeners are and what they accept. Written through the prepared
// settings rather than POST /v1/settings because a settings write does not start a listener:
// the SMTP and IMAP proxy workers are only spawned at boot or by the admin UI's reload command.
//
// Ports well away from the defaults (2525, 2993) so a local development instance does not collide.

module.exports = {
    smtpServerEnabled: true,
    smtpServerHost: '127.0.0.1',
    smtpServerPort: 32525,
    smtpServerAuthEnabled: true,
    smtpServerPassword: 'dovecot-tier-smtp-secret',
    smtpServerTLSEnabled: false,

    imapProxyServerEnabled: true,
    imapProxyServerHost: '127.0.0.1',
    imapProxyServerPort: 32993,
    imapProxyServerPassword: 'dovecot-tier-imap-secret',
    imapProxyServerTLSEnabled: false
};
