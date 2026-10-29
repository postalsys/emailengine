'use strict';

// One-time passcodes from the OTP-Token header (draft-goto-otp-token), see "One-time passcodes"
// in CLAUDE.md. mailparser applies the draft's parsing rules; the header itself is not
// authenticated, so the code is reported together with whether the receiving server vouches for
// its origin.

const { parseOtpToken } = require('mailparser');
const { parseAuthenticationResults, isTrustedAuthservId } = require('@postalsys/email-ai-tools/lib/authentication.js');
const { authenticationTrust } = require('./llm-pre-process');
const { getRegistrableDomain } = require('./utils/public-suffix');

// What the fetch paths ask for besides the configured headers when messageNew carries otp: the
// header itself, and what authenticationTrust() reads (Received for a Microsoft mailbox)
const OTP_FETCH_HEADERS = ['otp-token', 'authentication-results', 'received'];

/**
 * Tells whether the receiving server recorded a passing DKIM signature aligned with the origin:
 * from the same organizational domain, the way DMARC's relaxed alignment compares domains. Only
 * the topmost Authentication-Results header counts, written by a server authenticationTrust() names
 *
 * @param {string} origin - The origin the code is bound to, as parseOtpToken() returns it
 * @param {Object} headers - The message headers, lower-case names to value lists
 * @param {string|null} provider - As summaryProvider() names it
 * @returns {boolean}
 */
function isAuthenticatedOrigin(origin, headers, provider) {
    const trust = authenticationTrust(provider, headers);
    const parsed = parseAuthenticationResults([].concat(headers['authentication-results'] || [])[0]);
    if (!parsed || !parsed.dkimDomains.length || !isTrustedAuthservId(parsed.authservId, trust.trustedAuthservIds, trust.acceptUnnamedAuthentication)) {
        return false;
    }

    // an IP address, a loopback name or a public suffix has no organizational domain to match
    const originDomain = getRegistrableDomain(new URL(origin).hostname);
    return !!originDomain && parsed.dkimDomains.some(domain => getRegistrableDomain(domain) === originDomain);
}

/**
 * The one-time passcode of a message, from its OTP-Token header
 *
 * @param {Object} [headers] - The message headers, lower-case names to value lists
 * @param {string|null} provider - As summaryProvider() names it, decides which Authentication-Results header counts
 * @returns {{code: string, origin: string, authenticated: boolean}|undefined}
 */
function getMessageOtp(headers, provider) {
    const otp = headers && headers['otp-token'] && parseOtpToken([].concat(headers['otp-token']));
    if (!otp) {
        return undefined;
    }

    return { code: otp.code, origin: otp.origin, authenticated: isAuthenticatedOrigin(otp.origin, headers, provider) };
}

/**
 * Tells whether the notifyHeaders setting asks for the OTP-Token header, the only case the
 * messageNew payload carries the otp field
 *
 * @param {string[]} [notifyHeaders] - The notifyHeaders setting
 * @returns {boolean}
 */
function notifyHeadersIncludeOtp(notifyHeaders) {
    return [].concat(notifyHeaders || []).some(header => header === '*' || String(header).toLowerCase() === 'otp-token');
}

module.exports = { getMessageOtp, notifyHeadersIncludeOtp, OTP_FETCH_HEADERS };
