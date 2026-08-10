'use strict';

const crypto = require('crypto');
const { base32Encode } = require('./base32');

// In-house RFC 4226 / RFC 6238 TOTP implementation (SHA-1, 6 digits, 30-second period).
// Replaces the unmaintained speakeasy package while staying byte-compatible with seeds it
// generated: `totpSeed` is stored as an ASCII string and its raw bytes are the shared secret.

const TOTP_STEP_SECONDS = 30;
const TOTP_DIGITS = 6;
const TOTP_TOKEN_RE = new RegExp(`^[0-9]{${TOTP_DIGITS}}$`);

const SEED_LENGTH = 20;
const SEED_CHARSET = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';

function hotp(secret, counter) {
    let counterBuf = Buffer.alloc(8);
    counterBuf.writeBigUInt64BE(BigInt(counter));

    let digest = crypto.createHmac('sha1', secret).update(counterBuf).digest();

    let offset = digest[digest.length - 1] & 0x0f;
    let code = (digest.readUInt32BE(offset) & 0x7fffffff) % 10 ** TOTP_DIGITS;

    return code.toString().padStart(TOTP_DIGITS, '0');
}

function generateTotpSeed() {
    let seed = '';
    for (let i = 0; i < SEED_LENGTH; i++) {
        seed += SEED_CHARSET[crypto.randomInt(SEED_CHARSET.length)];
    }
    return seed;
}

function verifyTotp(seed, token, options) {
    let { window = 0, now = Date.now() } = options || {};

    token = (token || '').toString().trim();
    if (!TOTP_TOKEN_RE.test(token)) {
        return false;
    }

    let secret = Buffer.from(seed);
    let tokenBuf = Buffer.from(token);
    let counter = Math.floor(now / 1000 / TOTP_STEP_SECONDS);

    let verified = false;
    for (let delta = -window; delta <= window; delta++) {
        if (counter + delta < 0) {
            continue;
        }
        // no early break - every offset is checked so response timing does not depend on which one matched
        if (crypto.timingSafeEqual(Buffer.from(hotp(secret, counter + delta)), tokenBuf)) {
            verified = true;
        }
    }

    return verified;
}

function generateTotpUrl(seed, { label, issuer }) {
    return `otpauth://totp/${encodeURIComponent(label)}?secret=${base32Encode(Buffer.from(seed))}&issuer=${encodeURIComponent(issuer)}`;
}

module.exports = { generateTotpSeed, verifyTotp, generateTotpUrl };
