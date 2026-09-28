'use strict';

const { matchIp, parseComparableIp, parseComparableCidr } = require('../utils/network');

// POST /v1/tokens is only reachable by a full-privilege root token, so the new token can never
// hold a wider grant than its creator. The creator's restrictions and lifetime are a different
// axis, though: a root token limited to one address, one referrer, a rate limit or a one hour
// lifetime could otherwise mint a successor with none of those and walk out of every limit it
// was issued with. Rather than silently narrowing what the caller asked for (which would hand
// back a token that behaves differently from the request), the mint is refused unless the
// payload repeats each of the creator's limits at least as narrowly.

// Parses a single allowlist entry into [address, bits] with the same parsers matchIp() uses, so
// the containment check unwraps the IPv4-mapped IPv6 form exactly as the strategy does
function parseEntry(entry) {
    if (/\/\d+$/.test(entry)) {
        return parseComparableCidr(entry);
    }
    const addr = parseComparableIp(entry);
    return [addr, addr.kind() === 'ipv6' ? 128 : 32];
}

// True when every address the entry describes is also allowed by the creator's list
function entryCovered(entry, allowed) {
    let addr;
    let bits;
    try {
        [addr, bits] = parseEntry(entry);
    } catch (err) {
        return false;
    }

    // A single address only needs to match; matchIp() already handles the forms the strategy uses
    if (bits === (addr.kind() === 'ipv6' ? 128 : 32)) {
        return matchIp(addr.toString(), allowed);
    }

    // A range is covered when it sits entirely inside one allowed range: same family, a prefix at
    // least as long, and its network address inside that range
    for (let candidate of allowed) {
        try {
            let [range, rangeBits] = parseEntry(candidate);
            if (range.kind() === addr.kind() && bits >= rangeBits && addr.match(range, rangeBits)) {
                return true;
            }
        } catch (err) {
            // an unparseable allowlist entry covers nothing
        }
    }
    return false;
}

/**
 * Lists the ways a requested token would be less restricted than the token minting it.
 *
 * @param {Object} creator - the minting token's record (request.auth.artifacts)
 * @param {Object} payload - the validated mint payload
 * @returns {string[]} human readable reasons, empty when the new token is at least as narrow
 */
function mintWidenings(creator, payload) {
    const reasons = [];
    if (!creator || typeof creator !== 'object') {
        return reasons;
    }

    const own = creator.restrictions || {};
    const requested = (payload && payload.restrictions) || {};

    if (Array.isArray(own.addresses) && own.addresses.length) {
        const list = Array.isArray(requested.addresses) ? requested.addresses : [];
        if (!list.length || !list.every(entry => entryCovered(entry, own.addresses))) {
            reasons.push("restrictions.addresses must be set to addresses within the creating token's own address allowlist");
        }
    }

    if (Array.isArray(own.referrers) && own.referrers.length) {
        // Referrer entries are wildcard patterns, and deciding whether one pattern is contained in
        // another is not worth the risk of getting it wrong, so each has to be repeated verbatim
        const list = Array.isArray(requested.referrers) ? requested.referrers : [];
        if (!list.length || !list.every(entry => own.referrers.includes(entry))) {
            reasons.push("restrictions.referrers must be set to a subset of the creating token's own referrer allowlist");
        }
    }

    if (own.rateLimit && own.rateLimit.maxRequests && own.rateLimit.timeWindow) {
        const limit = requested.rateLimit;
        // Both the burst and the sustained rate have to stay within the creator's limit
        const narrow =
            limit &&
            limit.maxRequests &&
            limit.timeWindow &&
            limit.maxRequests <= own.rateLimit.maxRequests &&
            limit.maxRequests * own.rateLimit.timeWindow <= own.rateLimit.maxRequests * limit.timeWindow;
        if (!narrow) {
            reasons.push("restrictions.rateLimit must be set no higher than the creating token's own rate limit");
        }
    }

    if (creator.expires) {
        const ownExpires = new Date(creator.expires).getTime();
        const requestedExpires = payload && payload.expires ? new Date(payload.expires).getTime() : NaN;
        if (!Number.isFinite(requestedExpires) || !(requestedExpires <= ownExpires)) {
            reasons.push("expires must be set no later than the creating token's own expiry");
        }
    }

    return reasons;
}

module.exports = { mintWidenings };
