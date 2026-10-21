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
 * @param {number} [learned] - The interval learned for the host, see adaptive-idle-store.js
 */
function applyIdleSettings(imapConfig, accountImap, learned) {
    const provider = PROVIDER_IDLE_SETTINGS.find(entry => entry.host.test(imapConfig.host || ''));
    if (provider) {
        imapConfig.maxIdleTime = provider.maxIdleTime;
        if (provider.missingIdleCommand) {
            imapConfig.missingIdleCommand = provider.missingIdleCommand;
        }
    }

    // What the drops of this host taught (lib/email-client/imap/adaptive-idle.js), only ever shorter
    // than what would apply without it
    if (learned > 0 && !(imapConfig.maxIdleTime > 0 && imapConfig.maxIdleTime <= learned)) {
        imapConfig.maxIdleTime = learned;
    }

    // An interval the operator set for the account wins over anything learned
    if (accountImap?.maxIdleTime) {
        imapConfig.maxIdleTime = accountImap.maxIdleTime;
    }
}

// How long the command connection may sit unused before it closes itself (ImapFlow's socket
// inactivity timeout, answered by a quiet close and a reconnect on the next command)
const COMMAND_SOCKET_TIMEOUT = 60 * 1000;

/**
 * Inactivity timeout for the command connection. That connection never IDLEs, so a server or a
 * proxy in front of it that drops a session left quiet for less than a minute (TransIP's cuts one at
 * 30 seconds, without BYE) used to tear it down from the other end, logged as a connection error.
 * When an IDLE restart interval is set for the account or its provider, that is the time the server
 * is known to tolerate, so the command connection closes itself by then instead
 * @param {number} [maxIdleTime] - The connection's ImapFlow `maxIdleTime`
 * @returns {number} Milliseconds
 */
function commandSocketTimeout(maxIdleTime) {
    return maxIdleTime > 0 ? Math.min(COMMAND_SOCKET_TIMEOUT, maxIdleTime) : COMMAND_SOCKET_TIMEOUT;
}

module.exports = { applyIdleSettings, commandSocketTimeout, COMMAND_SOCKET_TIMEOUT };
