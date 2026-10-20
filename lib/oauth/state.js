'use strict';

// The single-use nonce of a hosted account setup, and the OAuth2 `state` that carries it to the
// provider and back (`account:add:<nonce>`). A nonce is NONCE_BYTES random bytes, base64url encoded
// (21-22 characters); base64 (+, / and = padding) is accepted too, for nonces issued before the
// switch to base64url that may still be cached in a pending setup.

const OAUTH_NONCE_PATTERN = /^[A-Za-z0-9_\-+/]{21,22}={0,2}$/;

const OAUTH_STATE_PREFIX = 'account:add:';

const OAUTH_STATE_PATTERN = new RegExp(`^${OAUTH_STATE_PREFIX}${OAUTH_NONCE_PATTERN.source.slice(1)}`);

/**
 * Whether an OAuth2 callback's `state` has the shape EmailEngine issues
 *
 * @param {*} state - The `state` query argument
 * @returns {boolean}
 */
function isValidOAuthState(state) {
    return OAUTH_STATE_PATTERN.test(state);
}

module.exports = { OAUTH_NONCE_PATTERN, isValidOAuthState };
