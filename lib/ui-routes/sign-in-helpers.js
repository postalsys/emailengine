'use strict';

// Two steps of the password sign-in that lib/ui-routes/auth-routes.js takes around the credential
// check: the per-account failure budget, and the upgrade of a password hash written with weaker
// parameters than hash() uses today.

const { windowBudget, reserveAttempts, releaseAttempts } = require('../rate-limit');
const pbkdf2 = require('../pbkdf2-phc');
const settings = require('../settings');

// Failed password sign-ins one account name may accumulate per minute before further attempts are
// refused. Failures only: a successful sign-in gives its reservation back
const LOGIN_FAILURE_BUDGET = 10;
const LOGIN_FAILURE_WINDOW = 60;

/**
 * Reserves one sign-in attempt for an account name.
 *
 * Counted on failure only: the attempt is reserved before the credential check and given back
 * through `release()` once the sign-in succeeded, so ten successful sign-ins a minute do not lock
 * the account and ten wrong passwords do. Keyed under its own namespace, since the username is the
 * attacker's to choose and `ip:<address>` used to land on the per-address counter.
 *
 * @param {String} username - the account name the client is signing in as
 * @returns {Promise<{admitted: Boolean, key: String, release: Function}>}
 */
async function reserveLoginAttempt(username) {
    const budget = windowBudget(`login:user:${username}`, LOGIN_FAILURE_BUDGET, LOGIN_FAILURE_WINDOW);
    const { admitted } = await reserveAttempts([budget]);
    return {
        admitted,
        key: budget.key,
        // Best effort: a lost release costs this account one attempt of its budget
        release: () => releaseAttempts([budget.key])
    };
}

/**
 * Rewrites the stored password hash with the current parameters when it was written with weaker
 * ones (fewer iterations, SHA-1). Only right after the password was checked against it, which is
 * the one moment the password is known; verify() keeps accepting the old hash otherwise. Not a
 * password change, so the version that ends every other session stays as it is.
 *
 * @param {Object} authData - the stored authData record, updated in place when rewritten
 * @param {String} password - the password that just verified
 * @param {Object} logger
 * @returns {Promise<Boolean>} whether the hash was rewritten
 */
async function upgradePasswordHash(authData, password, logger) {
    if (!authData || !pbkdf2.needsRehash(authData.password)) {
        return false;
    }
    authData.password = await pbkdf2.hash(password);
    await settings.set('authData', authData);
    logger.info({ msg: 'Admin password hash upgraded to the current parameters', user: authData.user });
    return true;
}

module.exports = { reserveLoginAttempt, upgradePasswordHash, LOGIN_FAILURE_BUDGET };
