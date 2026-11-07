'use strict';

// Applies EENGINE_PREPARED_PASSWORD at startup. Split out of server.js so it can be tested.

const { setAdminPassword } = require('./admin-password');

/**
 * Stores the prepared admin password hash when it differs from the stored one.
 *
 * Written only when the stored hash differs: passwordVersion is what every admin session and
 * message-browser token is checked against, so rewriting the same hash on each boot would log every
 * operator out at every restart.
 *
 * The replacement itself, passkeys included, is setAdminPassword(); rotating the password through
 * this variable used to end every session and leave the passkeys working.
 *
 * @param {string} preparedPassword - PBKDF2 hash
 * @param {Object} deps
 * @param {Object} deps.settings - settings store (`get()`, `set()`)
 * @param {Object} deps.passkeys - passkey store (`deleteAllCredentials()`)
 * @param {Object} deps.logger
 * @returns {Promise<{ imported: boolean, clearedPasskeys: number }>}
 */
async function importPreparedPassword(preparedPassword, { settings, passkeys, logger }) {
    let authData = await settings.get('authData');

    if (authData && authData.password === preparedPassword) {
        logger.debug({ msg: 'Password already imported' });
        return { imported: false, clearedPasskeys: 0 };
    }

    const { clearedPasskeys } = await setAdminPassword(preparedPassword, { settings, passkeys, logger }, authData);
    logger.info({ msg: 'Password imported', clearedPasskeys });

    return { imported: true, clearedPasskeys };
}

module.exports = { importPreparedPassword };
