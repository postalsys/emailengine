'use strict';

// A PKCE S256 verifier/challenge pair (RFC 7636), shared by every suite that drives the MCP
// OAuth flow so the construction - verifier entropy, encoding, digest - lives in one place.

const crypto = require('crypto');

function pkcePair() {
    const verifier = crypto.randomBytes(48).toString('base64url');
    const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
    return { verifier, challenge };
}

module.exports = { pkcePair };
