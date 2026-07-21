'use strict';

// tokens.provision() refuses to mint a token while the instance has no admin password, so that a
// credential issued during the unprotected window cannot outlive it (see lib/tokens.js). Tests that
// exercise token mechanics rather than that guard need to stand the instance up as a secured one.
//
// `authData` is a global setting, so every helper here restores the previous value rather than
// clearing it - a test that blindly reset it to false would leave the setting wrong for anything
// sharing the same Redis prefix.

const settings = require('../../lib/settings');

// A minimally valid "authentication is configured" record. Never used to authenticate - only the
// presence of authData is checked.
const SECURED_AUTH_DATA = { user: 'admin', password: 'hash', passwordVersion: 1 };

// Runs fn with authData forced to `value`, restoring the previous value afterwards.
async function withAuthData(value, fn) {
    const previous = await settings.get('authData');
    try {
        await settings.set('authData', value);
        return await fn();
    } finally {
        await settings.set('authData', previous);
    }
}

// For suites that need the instance secured for their whole lifetime: call setAuthData() in a
// before hook and pass the returned restore function to the teardown.
async function secureInstance(value = SECURED_AUTH_DATA) {
    const previous = await settings.get('authData');
    await settings.set('authData', value);
    return async () => {
        await settings.set('authData', previous);
    };
}

module.exports = { withAuthData, secureInstance, SECURED_AUTH_DATA };
