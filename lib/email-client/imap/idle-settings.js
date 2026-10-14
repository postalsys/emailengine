'use strict';

/**
 * How often an IMAP connection restarts IDLE (ImapFlow's `maxIdleTime`) and which command keeps it
 * alive on a server without IDLE (`missingIdleCommand`).
 *
 * A few providers get a built-in value, and an account can set its own `imap.maxIdleTime` for a
 * server, or something in front of it, that drops a connection left idle for a few minutes without
 * sending BYE. The account value wins over the built-in one.
 *
 * Kept free of connection and Redis code so the rules can be tested on their own.
 */

const PROVIDER_IDLE_SETTINGS = [
    // Rambler supports IDLE but needs it restarted frequently
    { host: /\.rambler\.ru$/i, maxIdleTime: 55 * 1000 },
    // 163.com (Coremail) does not support IDLE and ignores NOOP for idle timer reset.
    // Use STATUS as the keepalive command - it counts as real activity for the server.
    { host: /\.163\.com$/i, maxIdleTime: 55 * 1000, missingIdleCommand: 'STATUS' },
    // Break IDLE at least once every three minutes
    { host: /\.yahoo\.com$/i, maxIdleTime: 3 * 60 * 1000 }
];

/**
 * Sets the IDLE options on a connection config that is about to be handed to ImapFlow
 * @param {Object} imapConfig - The ImapFlow config, modified in place
 * @param {Object} [accountImap] - The account's stored `imap` object. Read on its own because an
 *   OAuth2 account builds its connection config without it
 */
function applyIdleSettings(imapConfig, accountImap) {
    const provider = PROVIDER_IDLE_SETTINGS.find(entry => entry.host.test(imapConfig.host || ''));
    if (provider) {
        imapConfig.maxIdleTime = provider.maxIdleTime;
        if (provider.missingIdleCommand) {
            imapConfig.missingIdleCommand = provider.missingIdleCommand;
        }
    }

    if (accountImap?.maxIdleTime) {
        imapConfig.maxIdleTime = accountImap.maxIdleTime;
    }
}

module.exports = { applyIdleSettings };
