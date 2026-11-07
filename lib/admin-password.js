'use strict';

// The admin password checks the admin UI's sign-in and step-down routes share. Split out of
// lib/ui-routes/auth-routes.js.

const pbkdf2 = require('./pbkdf2-phc');

// Single place that knows how a failed password check is interpreted: an absent password and a
// verify() that throws (which happens only on a malformed stored hash, never on a wrong password)
// are both failures, never a pass. Sign-in, the password change and both passkey registration
// steps all come through here, so a change to how the account password is checked - a KDF swap,
// a dummy verify to flatten timing - lands in one place.
async function verifyAdminPassword(hash, password, logger) {
    if (!password) {
        return false;
    }
    try {
        return await pbkdf2.verify(hash, password);
    } catch (err) {
        logger.error({ msg: 'Failed to verify password hash', err });
        return false;
    }
}

// The current-password check behind the security page's step-down actions (the password change
// and switching the second factor off). A live session alone is not supposed to reveal the
// password, and unthrottled the field let a hijacked session guess it at full speed, so the
// check is rate limited the way the login form is: keyed on the account rather than the address
// because the caller is already authenticated as it, and with the login form's per-username
// budget. Owns the limiter and the warn logs; the caller decides how to report the failure.
//
// @returns {Promise<{ ok: true } | { ok: false, reason: 'rateLimited' | 'invalid', message: String, statusCode: Number }>}
async function verifyCurrentPassword(request, h, authData, password) {
    let rateLimit = await h.checkRateLimit(`password:verify:${authData.user || 'admin'}`, 1, 10, 60);
    if (!rateLimit.success) {
        request.logger.warn({ msg: 'Rate limited', rateLimit, remoteAddress: request.app.ip });
        return { ok: false, reason: 'rateLimited', message: 'Rate limited, please wait and try again', statusCode: 429 };
    }

    if (!(await verifyAdminPassword(authData.password, password, request.logger))) {
        request.logger.warn({ msg: 'Invalid current password', remoteAddress: request.app.ip });
        return { ok: false, reason: 'invalid', message: 'Invalid password', statusCode: 403 };
    }

    return { ok: true };
}

/**
 * Replaces the admin password: stores the hash, ends every session and message-browser token by
 * bumping passwordVersion, and removes every passkey of the user. Registering a passkey takes the
 * password, so a passkey that outlived a password change could belong to whoever had the old one,
 * and a passkey signs in without the second factor. The one place a password is replaced (the
 * security page, the `emailengine password` command, EENGINE_PREPARED_PASSWORD), so a new way of
 * replacing it can not forget the passkeys again.
 *
 * @param {string} passwordHash - PBKDF2 hash of the new password
 * @param {Object} deps
 * @param {Object} deps.settings - settings store (`get()`, `set()`)
 * @param {Object} deps.passkeys - passkey store (`deleteAllCredentials()`)
 * @param {Object} deps.logger
 * @param {Object} [authData] - The stored authData, when the caller already read it
 * @returns {Promise<{ authData: Object, clearedPasskeys: number }>}
 */
async function setAdminPassword(passwordHash, { settings, passkeys, logger }, authData) {
    // read only when the caller did not: a caller that read nothing passes null, not undefined
    authData = (authData === undefined ? await settings.get('authData') : authData) || {};
    authData.user = authData.user || 'admin';
    authData.password = passwordHash;
    authData.passwordVersion = Date.now();

    await settings.set('authData', authData);

    let clearedPasskeys = 0;
    try {
        clearedPasskeys = await passkeys.deleteAllCredentials(authData.user);
        logger.info({ msg: 'All passkeys cleared after password change', user: authData.user, cleared: clearedPasskeys });
    } catch (err) {
        // The password is replaced either way; say loudly that the passkeys are not gone
        logger.error({ msg: 'Failed to clear passkeys after password change', err });
    }

    return { authData, clearedPasskeys };
}

module.exports = { verifyAdminPassword, verifyCurrentPassword, setAdminPassword };
