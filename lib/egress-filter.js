'use strict';

const net = require('net');
const dns = require('dns').promises;
const ipaddr = require('ipaddr.js');

// Egress policies for operator-supplied outbound URLs (webhook targets), least to most
// restrictive. EmailEngine is usually self-hosted alongside the services it notifies, so
// blocking private ranges outright would break ordinary deployments - the default therefore only
// blocks the link-local range, which is where every cloud provider parks its instance metadata
// service and which no real webhook receiver lives on.
const POLICY_OFF = 'off';
const POLICY_LINK_LOCAL = 'link-local';
const POLICY_PRIVATE = 'private';

const VALID_POLICIES = new Set([POLICY_OFF, POLICY_LINK_LOCAL, POLICY_PRIVATE]);

// Range names come from ipaddr.js `range()`
const LINK_LOCAL_BLOCKED_RANGES = new Set(['linkLocal']);

const PRIVATE_BLOCKED_RANGES = new Set([
    'linkLocal',
    'loopback',
    'private',
    'uniqueLocal',
    'carrierGradeNat',
    'reserved',
    'unspecified',
    'broadcast',
    'multicast'
]);

// Metadata endpoints that range classification alone does not catch under the default policy:
// AWS serves IMDS over IPv6 from a unique-local address, and Alibaba Cloud parks its IMDS in the
// carrier-grade NAT range. Normalized forms, compared against a normalized subject.
const ALWAYS_BLOCKED_ADDRESSES = new Set(['fd00:ec2:0:0:0:0:0:254', '100.100.100.200']);

/**
 * Resolves the configured egress policy, falling back to the default for unknown values.
 * @param {string} [value] - Raw configured value
 * @returns {string} One of the POLICY_* constants
 */
function normalizePolicy(value) {
    let policy = (value || '').toString().trim().toLowerCase();
    return VALID_POLICIES.has(policy) ? policy : POLICY_LINK_LOCAL;
}

/**
 * Checks a single IP address against an egress policy.
 *
 * IPv4-mapped IPv6 addresses are unwrapped first, otherwise `::ffff:169.254.169.254` would be
 * classified as a plain IPv6 unicast address and sail through.
 *
 * @param {string} ip - IP address to classify
 * @param {string} policy - One of the POLICY_* constants
 * @returns {boolean} True when the address must not be contacted
 */
function isBlockedAddress(ip, policy) {
    if (policy === POLICY_OFF) {
        return false;
    }

    let parsed;
    try {
        parsed = ipaddr.parse(ip);
    } catch (err) {
        // Fail closed: an address we can not classify is not one we should connect to
        return true;
    }

    if (parsed.kind() === 'ipv6' && parsed.isIPv4MappedAddress()) {
        parsed = parsed.toIPv4Address();
    }

    if (ALWAYS_BLOCKED_ADDRESSES.has(parsed.toNormalizedString())) {
        return true;
    }

    const blockedRanges = policy === POLICY_PRIVATE ? PRIVATE_BLOCKED_RANGES : LINK_LOCAL_BLOCKED_RANGES;

    return blockedRanges.has(parsed.range());
}

/**
 * Builds the error thrown for a blocked destination. Carries `code` so callers can recognize a
 * policy rejection and stop retrying: a blocked target is a configuration problem, and burning
 * ten attempts on it only delays the operator seeing the real reason.
 * @param {string} reason - Human readable explanation
 * @returns {Error} Error tagged with code EEGRESSBLOCKED
 */
function blockedError(reason) {
    let err = new Error(reason);
    err.code = 'EEGRESSBLOCKED';
    return err;
}

// Verdict cache for resolved hostnames. Node's dns.lookup has no cache of its own and glibc has
// none either without nscd, so without this every webhook delivery pays a resolver round trip -
// and the notify worker runs at concurrency 1 by default, so that cost is fully serialized ahead
// of each POST. Caching the verdict rather than the addresses keeps entries tiny.
//
// This gives up nothing: undici resolves the name again independently when it connects, so the
// check is inherently time-of-check/time-of-use racy and a short TTL introduces no hole that was
// not already there. Distinct webhook targets are few, so the hit rate is effectively total.
const VERDICT_TTL = 60 * 1000;
const VERDICT_CACHE_LIMIT = 1000;
const verdictCache = new Map();

function readCachedVerdict(key) {
    const hit = verdictCache.get(key);
    if (!hit) {
        return null;
    }

    if (hit.expires <= Date.now()) {
        verdictCache.delete(key);
        return null;
    }

    return hit;
}

function cacheVerdict(key, blockedBy) {
    // Bounded: drop the oldest entry once full. Map preserves insertion order.
    if (verdictCache.size >= VERDICT_CACHE_LIMIT) {
        verdictCache.delete(verdictCache.keys().next().value);
    }

    verdictCache.set(key, { blockedBy, expires: Date.now() + VERDICT_TTL });
}

/**
 * Verifies that a URL may be contacted under the given egress policy.
 *
 * Hostnames are resolved and every returned address is checked, so a name that points at a
 * blocked address is rejected just like a literal would be.
 *
 * @param {string} url - Destination URL
 * @param {Object} [opts]
 * @param {string} [opts.policy] - One of the POLICY_* constants, defaults to the link-local policy
 * @param {Function} [opts.resolve] - Injectable resolver returning [{address}], defaults to dns.lookup
 * @returns {Promise<void>} Resolves when the destination is allowed
 * @throws {Error} Tagged with code EEGRESSBLOCKED when the destination is not allowed
 */
async function assertAllowedUrl(url, opts) {
    const { policy = POLICY_LINK_LOCAL, resolve } = opts || {};

    if (policy === POLICY_OFF) {
        return;
    }

    let hostname;
    try {
        hostname = new URL(url).hostname;
    } catch (err) {
        throw blockedError(`Invalid webhook URL: ${url}`);
    }

    // URL keeps IPv6 literals in brackets, ipaddr.js does not want them
    if (hostname.startsWith('[') && hostname.endsWith(']')) {
        hostname = hostname.slice(1, -1);
    }

    // A literal needs no resolution, so it is both the cheapest path and never cached
    if (net.isIP(hostname)) {
        if (isBlockedAddress(hostname, policy)) {
            throw blockedError(`Refusing to deliver to a blocked address (${hostname})`);
        }
        return;
    }

    const cacheKey = `${policy}:${hostname}`;
    const cached = readCachedVerdict(cacheKey);
    if (cached) {
        if (cached.blockedBy) {
            throw blockedError(`Refusing to deliver to ${hostname}, it resolves to a blocked address (${cached.blockedBy})`);
        }
        return;
    }

    let addresses;
    try {
        addresses = resolve ? await resolve(hostname) : await dns.lookup(hostname, { all: true });
    } catch (err) {
        // A name that does not resolve is a delivery problem, not a policy one. Let the request
        // proceed and fail with the transport's own error so it retries like any other DNS blip.
        // Deliberately not cached, so a resolver blip cannot pin a verdict for a whole minute.
        return;
    }

    for (let { address } of addresses) {
        if (isBlockedAddress(address, policy)) {
            cacheVerdict(cacheKey, address);
            throw blockedError(`Refusing to deliver to ${hostname}, it resolves to a blocked address (${address})`);
        }
    }

    cacheVerdict(cacheKey, null);
}

module.exports = {
    assertAllowedUrl,
    isBlockedAddress,
    normalizePolicy,
    // Exported so tests can start from a known state; nothing in production clears the cache,
    // entries simply expire.
    clearVerdictCache: () => verdictCache.clear(),
    POLICY_OFF,
    POLICY_LINK_LOCAL,
    POLICY_PRIVATE
};
