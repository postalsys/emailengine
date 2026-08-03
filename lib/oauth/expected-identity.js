'use strict';

function normalizeEmail(value) {
    return typeof value === 'string' ? value.trim().toLowerCase() : '';
}

function matchesExpectedOAuthIdentity(expectedEmail, providerIdentities) {
    const expected = normalizeEmail(expectedEmail);
    if (!expected) {
        return false;
    }

    return providerIdentities.some(identity => normalizeEmail(identity) === expected);
}

module.exports = { matchesExpectedOAuthIdentity };
