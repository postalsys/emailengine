'use strict';

// Applies EENGINE_PREPARED_PASSWORD at startup. Split out of server.js so it can be tested.

/**
 * Stores the prepared admin password hash when it differs from the stored one.
 *
 * Written only when the stored hash differs: passwordVersion is what every admin session and
 * message-browser token is checked against, so rewriting the same hash on each boot would log every
 * operator out at every restart.
 *
 * A replaced password also removes every passkey of the user, as the password change on the
 * security page and the `emailengine password` command do: registering a passkey takes the password,
 * so one that outlived the rotation could belong to whoever had the old password, and a passkey
 * signs in without the second factor. Rotating the password through this variable used to end every
 * session and leave such a passkey working.
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

    authData = authData || {};
    authData.user = authData.user || 'admin';
    authData.password = preparedPassword;
    authData.passwordVersion = Date.now();

    await settings.set('authData', authData);

    let clearedPasskeys = 0;
    try {
        clearedPasskeys = await passkeys.deleteAllCredentials(authData.user);
    } catch (err) {
        // The password is replaced either way; say loudly that the passkeys are not gone
        logger.error({ msg: 'Failed to remove passkeys after importing a new password', err });
    }
    logger.info({ msg: 'Password imported', clearedPasskeys });

    return { imported: true, clearedPasskeys };
}

module.exports = { importPreparedPassword };
