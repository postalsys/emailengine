/* eslint no-bitwise: 0 */

'use strict';

const net = require('net');
const dns = require('dns').promises;
const ipaddr = require('ipaddr.js');

// Egress policies for operator-supplied outbound URLs (webhook targets), least to most
// restrictive. EmailEngine is usually self-hosted alongside the services it notifies, so
// blocking private ranges outright would break ordinary deployments - the default therefore only
// blocks the link-local range, which is where every cloud provider parks its instance metadata
// service and which no real webhook receiver lives on.
//
// Scope: this is a guardrail against misconfiguration and mistakes, not a boundary against a
// hostile operator. Anyone who can set a webhook target can generally also author fn/map scripts,
// which lib/sub-script.js runs with full server privileges and hands an unfiltered fetch. Do not
// treat the policy as tenant isolation.
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

const ipv4FromHextets = (hi, lo) => new ipaddr.IPv4([hi >> 8, hi & 0xff, lo >> 8, lo & 0xff]);

/**
 * Extracts the IPv4 address an IPv6 transition address carries, if it is one.
 *
 * It is the embedded address the policy has to judge: `::ffff:169.254.169.254` (IPv4-mapped),
 * `64:ff9b::169.254.169.254` (NAT64) and `2002:a9fe:a9fe::1` (6to4) all lead to the metadata
 * service while classifying as plain unicast or as a transition range the policy does not list.
 * Unwrapping rather than blocking the ranges outright keeps a NAT64-only host working: there,
 * every IPv4-only receiver resolves into 64:ff9b::/96.
 *
 * @param {Object} parsed - An ipaddr.js IPv6 address
 * @returns {Object|null} The embedded ipaddr.js IPv4 address, or null for a native IPv6 address
 */
function embeddedIPv4(parsed) {
    if (parsed.isIPv4MappedAddress()) {
        return parsed.toIPv4Address();
    }

    const parts = parsed.parts;
    switch (parsed.range()) {
        case 'rfc6052': // 64:ff9b::/96 and 64:ff9b:1::/48, NAT64: the IPv4 is the low 32 bits
        case 'rfc6145': // ::ffff:0:0:0/96, IPv4-translated: same layout
            return ipv4FromHextets(parts[6], parts[7]);
        case '6to4': // 2002:AABB:CCDD::/48, the IPv4 follows the 16-bit prefix
            return ipv4FromHextets(parts[1], parts[2]);
        case 'teredo': // 2001::/32, the client's IPv4 is the low 32 bits, bit-inverted
            return ipv4FromHextets(parts[6] ^ 0xffff, parts[7] ^ 0xffff);
        default:
            return null;
    }
}

/**
 * Checks a single IP address against an egress policy.
 *
 * IPv6 transition addresses are unwrapped to the IPv4 address they carry first, see
 * embeddedIPv4().
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

    if (parsed.kind() === 'ipv6') {
        parsed = embeddedIPv4(parsed) || parsed;
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

// An operator who does not know this policy exists otherwise has nothing to search for: the
// message would describe a refusal without naming what is refusing. It also reaches operators who
// only ever see the log line, which no amount of UI help would.
const POLICY_HINT = 'See EENGINE_WEBHOOK_EGRESS_POLICY if this destination is intended.';

// A destination the policy refuses, as opposed to one we could not parse - the hint belongs on the
// former only, since the setting cannot help with a malformed URL
const policyBlockedError = reason => blockedError(`${reason}. ${POLICY_HINT}`);

// Verdict cache for resolved hostnames. Node's dns.lookup has no cache of its own and glibc has
// none either without nscd, so without this every webhook delivery pays a resolver round trip -
// and the notify worker runs at concurrency 1 by default, so that cost is fully serialized ahead
// of each POST. Caching the verdict rather than the addresses keeps entries tiny.
//
// A stale verdict opens no hole. This pre-check exists to refuse a bad destination early and with
// an error worth reading; the binding decision is made by createEgressLookup() at connect time,
// against the very addresses the socket is opened to. Distinct webhook targets are few, so the hit
// rate is effectively total.
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
 * Finds the first address in a resolver answer that the policy refuses.
 *
 * A name is judged by its whole answer, not by whichever record the resolver happened to order
 * first: one that hands back a mix of permitted and blocked addresses is not one to reach under
 * any of them.
 *
 * @param {Array} addresses - Resolver answer, in the shape dns.lookup(host, {all: true}) returns
 * @param {string} policy - One of the POLICY_* constants
 * @returns {string|null} The offending address, or null when every address is permitted
 */
function findBlockedAddress(addresses, policy) {
    for (let { address } of addresses || []) {
        if (isBlockedAddress(address, policy)) {
            return address;
        }
    }
    return null;
}

/**
 * Verifies that a URL may be contacted under the given egress policy.
 *
 * Hostnames are resolved and every returned address is checked, so a name that points at a
 * blocked address is rejected just like a literal would be.
 *
 * This is the early, human-facing half of the guard: it fails a bad destination before the request
 * is built and names the reason. It is not the half that binds - see createEgressLookup(), which
 * enforces the same policy against the addresses actually connected to.
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
            throw policyBlockedError(`Refusing to deliver to a blocked address (${hostname})`);
        }
        return;
    }

    const cacheKey = `${policy}:${hostname}`;
    const cached = readCachedVerdict(cacheKey);
    if (cached) {
        if (cached.blockedBy) {
            throw policyBlockedError(`Refusing to deliver to ${hostname}, it resolves to a blocked address (${cached.blockedBy})`);
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

    // Compared against null, not for truthiness: isBlockedAddress fails closed on a value it
    // cannot parse, including an empty string, and that verdict has to survive the return trip.
    const blocked = findBlockedAddress(addresses, policy);
    if (blocked !== null) {
        cacheVerdict(cacheKey, blocked);
        throw policyBlockedError(`Refusing to deliver to ${hostname}, it resolves to a blocked address (${blocked})`);
    }

    cacheVerdict(cacheKey, null);
}

/**
 * Builds a Node-compatible `lookup` implementation that applies an egress policy at the moment of
 * connection.
 *
 * `assertAllowedUrl()` can only vet the addresses it resolved itself, and undici resolves the
 * hostname again when it connects. A name that answers differently between the two lookups is
 * therefore checked as one address and connected to as another - deliberately, in a DNS rebinding
 * setup, but equally by accident behind a short TTL or a round-robin record. Handing this function
 * to an undici Agent as `connect: { lookup }` collapses check and use into a single step: the
 * addresses returned here are the addresses the socket is opened to, so no window remains between
 * the two.
 *
 * Only names reach this: net.connect skips the lookup when the host is already an IP. That is the
 * whole story for literals anyway, since an address cannot change between being checked by
 * assertAllowedUrl() and being connected to.
 *
 * @param {string} [policy] - One of the POLICY_* constants, defaults to the link-local policy
 * @param {Object} [opts]
 * @param {Function} [opts.resolve] - Injectable resolver returning [{address, family}], defaults to dns.lookup
 * @returns {Function} lookup(hostname, options, callback), in the shape net.connect expects
 */
function createEgressLookup(policy, opts) {
    const resolvedPolicy = normalizePolicy(policy);
    const { resolve = dns.lookup } = opts || {};

    return (hostname, options, callback) => {
        // Forwarded as given, plus `all`, which autoSelectFamily (Happy Eyeballs, on by default
        // since Node 20) already asks for anyway. Forcing it means every address gets classified,
        // not just the one the resolver happened to order first.
        resolve(hostname, Object.assign({}, options, { all: true })).then(addresses => {
            if (!addresses || !addresses.length) {
                let err = new Error(`Could not resolve ${hostname}`);
                err.code = 'ENOTFOUND';
                return callback(err);
            }

            const blocked = findBlockedAddress(addresses, resolvedPolicy);
            if (blocked !== null) {
                return callback(policyBlockedError(`Refusing to connect to ${hostname}, it resolves to a blocked address (${blocked})`));
            }

            if (options.all) {
                return callback(null, addresses);
            }
            callback(null, addresses[0].address, addresses[0].family);
        }, callback);
    };
}

module.exports = {
    assertAllowedUrl,
    createEgressLookup,
    isBlockedAddress,
    normalizePolicy,
    // Exported so tests can start from a known state; nothing in production clears the cache,
    // entries simply expire.
    clearVerdictCache: () => verdictCache.clear(),
    POLICY_OFF,
    POLICY_LINK_LOCAL,
    POLICY_PRIVATE
};
