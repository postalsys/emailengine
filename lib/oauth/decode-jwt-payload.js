'use strict';

// Maximum size of the encoded payload segment we are willing to decode. Real id_tokens are a few
// hundred bytes of claims; anything larger is malformed or hostile, and the segment reaches us from a
// provider response we do not otherwise bound.
const MAX_PAYLOAD_LENGTH = 16 * 1024;

// Decode the claims of a JWT WITHOUT verifying its signature, returning null for anything that does not
// parse. Never throws - callers treat a null payload as "no claims available" and fall back.
//
// Not verifying is deliberate and only safe at the sites that use it: every caller obtained the token
// from the provider's token endpoint over a direct TLS back-channel POST (lib/oauth/*.js getToken), so
// authenticity comes from the transport, not from the token. The claims are trustworthy for that reason
// alone. Do NOT reuse this for a token that arrived through the browser or any other front channel -
// there the signature is the only thing standing between you and attacker-authored claims.
function decodeJwtPayload(token) {
    if (!token || typeof token !== 'string') {
        return null;
    }

    const [, encodedPayload] = token.split('.');
    if (!encodedPayload || encodedPayload.length > MAX_PAYLOAD_LENGTH) {
        return null;
    }

    try {
        const payload = JSON.parse(Buffer.from(encodedPayload, 'base64url').toString());
        // A JWT payload is a JSON object. Anything else (a bare string, a number, null, an array) is not
        // a claims set, and returning it would hand callers a value that fails on property access.
        if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
            return null;
        }
        return payload;
    } catch (err) {
        return null;
    }
}

module.exports = { decodeJwtPayload, MAX_PAYLOAD_LENGTH };
