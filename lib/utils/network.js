'use strict';

const os = require('os');
const net = require('net');
const ipaddr = require('ipaddr.js');
const { reverse: dnsReverse } = require('dns').promises;
const { resolvePublicInterfaces } = require('pubface');
const googleCrawlerRanges = require('../../data/google-crawlers.json');
const settings = require('../settings');
const logger = require('../logger');
const { REDIS_PREFIX } = require('../consts');

// Build Google crawler IP range map for efficient lookup
const googleCrawlerMap = new Map();
for (let prefixEntry of googleCrawlerRanges.prefixes) {
    for (let prefixKey of ['ipv6Prefix', 'ipv4Prefix']) {
        if (prefixEntry[prefixKey]) {
            let parsed = ipaddr.parseCIDR(prefixEntry[prefixKey]);
            if (!googleCrawlerMap.has(prefixKey)) {
                googleCrawlerMap.set(prefixKey, []);
            }
            googleCrawlerMap.get(prefixKey).push(parsed);
        }
    }
}

/**
 * Parses an address, unwrapping the IPv4-mapped IPv6 form to the plain IPv4 it carries.
 *
 * A dual-stack listener reports an IPv4 peer as `::ffff:10.0.0.5`, while operators write the
 * allowlist as `10.0.0.5`. Without this the two never compare equal, so a proxy declared in
 * `EENGINE_API_PROXY_ADDRESSES` is not recognized and its X-Forwarded-For is discarded - which
 * then denies the admin allowlist the very address it is configured to match.
 *
 * @param {string} address - IP address in any textual form
 * @returns {Object} ipaddr.js address object, IPv4 whenever the input describes an IPv4 address
 */
function parseComparableIp(address) {
    let parsed = ipaddr.parse(address);

    if (parsed.kind() === 'ipv6' && parsed.isIPv4MappedAddress()) {
        return parsed.toIPv4Address();
    }

    return parsed;
}

/**
 * Parses a CIDR range the same way, so an IPv4-mapped range matches plain IPv4 subjects.
 *
 * The mapped prefix occupies the first 96 bits, so the remaining bits are the IPv4 prefix length:
 * `::ffff:10.0.0.0/104` describes exactly `10.0.0.0/8`.
 *
 * @param {string} range - CIDR range
 * @returns {Array} `[address, bits]` as ipaddr.js reports it, unwrapped where applicable
 */
function parseComparableCidr(range) {
    let [parsed, bits] = ipaddr.parseCIDR(range);

    if (parsed.kind() === 'ipv6' && parsed.isIPv4MappedAddress()) {
        return [parsed.toIPv4Address(), Math.max(bits - 96, 0)];
    }

    return [parsed, bits];
}

/**
 * Matches an IP address against a list of addresses or CIDR ranges
 * @param {string} ip - IP address to check
 * @param {string[]} addresses - Array of IP addresses or CIDR ranges
 * @returns {boolean} True if IP matches any address in the list
 */
function matchIp(ip, addresses) {
    let parsed;
    try {
        parsed = parseComparableIp(ip);
    } catch (err) {
        // Every caller uses this for an allowlist decision, so an address we can not parse must
        // match nothing. Throwing here used to surface as a 500 for any request that carried a
        // non-IP value in a trusted X-Forwarded-For header.
        //
        // Logged at debug, not error: the subject address is client-supplied (it can come from an
        // X-Forwarded-For chain entry), so junk here is expected input rather than a fault. Bad
        // entries in the allowlist itself are a config problem and still log at error below.
        logger.debug({ msg: 'Failed to parse IP address', ip, err });
        return false;
    }

    for (let addr of addresses) {
        try {
            let match;
            if (/\/\d+$/.test(addr)) {
                let [range, bits] = parseComparableCidr(addr);
                // ipaddr.js throws when the families differ, and a list that mixes IPv4 and IPv6
                // entries is ordinary rather than a misconfiguration, so a mismatch is simply not
                // a match instead of an error log on every request
                match = range.kind() === parsed.kind() && parsed.match(range, bits);
            } else {
                match = parsed.toNormalizedString() === parseComparableIp(addr).toNormalizedString();
            }
            if (match) {
                return true;
            }
        } catch (err) {
            logger.error({ msg: 'Failed to parse IP address', ip, addr, err });
        }
    }

    return false;
}

/**
 * Resolves the effective client IP address for an incoming HTTP request.
 *
 * `X-Forwarded-For` is a list that each proxy APPENDS to, so the left-most entry is whatever the
 * original caller sent and is never trustworthy on its own - nginx's canonical
 * `$proxy_add_x_forwarded_for`, Apache's mod_proxy and HAProxy's `option forwardfor` all preserve
 * a client-supplied value and add the peer after it. Two security controls key off the resolved
 * address (the `EENGINE_ADMIN_ACCESS_ADDRESSES` admin allowlist and per-token
 * `restrictions.addresses`), so taking the left-most entry lets any caller present the address the
 * allowlist expects and walk through both.
 *
 * With `trustedProxies` (`EENGINE_API_PROXY_ADDRESSES`) configured the chain is therefore walked
 * from the right, discarding entries contributed by declared proxies; the first entry that is not
 * one of our proxies is the closest address they actually observed. Both the peer and the chain
 * are checked, so a caller that is not behind a declared proxy gets no say at all.
 *
 * With no `trustedProxies` there is no way to know how many hops to believe, so the historical
 * left-most behavior is kept for compatibility. That mode is fine for logging but must not be
 * relied on for allowlists - which is what the startup warning in the API worker is about.
 *
 * @param {Object} opts
 * @param {string} opts.remoteAddress - Peer address of the socket the request arrived on
 * @param {string} [opts.forwardedFor] - Raw `X-Forwarded-For` header value, if any
 * @param {boolean} [opts.enableApiProxy] - Whether the deployment is configured to sit behind a proxy
 * @param {string[]} [opts.trustedProxies] - Addresses or CIDR ranges of our own proxies
 * @returns {string} Address to treat as the client for logging and allowlist checks
 */
function resolveClientIp({ remoteAddress, forwardedFor, enableApiProxy, trustedProxies }) {
    if (!enableApiProxy || !forwardedFor) {
        return remoteAddress;
    }

    // Anything that is not a bare IP (a port suffix, an obfuscated identifier, junk) can not be
    // matched against an allowlist, so it is treated as no claim at all
    const asClientAddress = value => (net.isIP(value) ? value : remoteAddress);

    if (!trustedProxies || !trustedProxies.length) {
        return asClientAddress(forwardedFor.split(',')[0].trim());
    }

    if (!matchIp(remoteAddress, trustedProxies)) {
        // Request did not come from a declared proxy, so its forwarding header means nothing
        return remoteAddress;
    }

    const chain = forwardedFor
        .split(',')
        .map(entry => entry.trim())
        .filter(entry => entry);

    for (let i = chain.length - 1; i >= 0; i--) {
        if (!matchIp(chain[i], trustedProxies)) {
            return asClientAddress(chain[i]);
        }
    }

    // Every hop was one of ours, so nothing in the chain describes an external caller
    return remoteAddress;
}

/**
 * Detects if a request is from an automated scanner (Google, Barracuda, etc.)
 * @param {string} ip - IP address to check
 * @returns {Promise<boolean>} True if request appears to be automated
 */
async function detectAutomatedRequest(ip) {
    let prefixKey;
    if (net.isIPv4(ip)) {
        prefixKey = 'ipv4Prefix';
    } else if (net.isIPv6(ip)) {
        prefixKey = 'ipv6Prefix';
    } else {
        return false;
    }

    const addr = ipaddr.parse(ip);

    // Check if it is a Google security scanner
    for (let prefixEntry of googleCrawlerMap.get(prefixKey)) {
        if (addr.match(prefixEntry)) {
            return true;
        }
    }

    // Check known scanners via reverse DNS
    let hostnames;
    try {
        hostnames = await dnsReverse(ip);
    } catch (err) {
        logger.trace({
            msg: 'Failed to reverse resolve IP',
            ip,
            err
        });
    }

    if (!hostnames || !hostnames.length) {
        return false;
    }

    const hostname = []
        .concat(hostnames || [])
        .shift()
        .toString()
        .trim()
        .toLowerCase();

    // Barracuda, spfbl
    if (/\bbarracuda\.com$|\bspfbl\.net$/gi.test(hostname)) {
        return true;
    }

    return false;
}

/**
 * Updates Redis with information about available public network interfaces
 * @param {Object} redis - Redis client instance
 * @returns {Promise<void>}
 */
async function updatePublicInterfaces(redis) {
    let interfaces = await resolvePublicInterfaces();

    for (let iface of interfaces) {
        if (!iface.localAddress) {
            continue;
        }

        if (iface.defaultInterface) {
            await redis.hset(`${REDIS_PREFIX}interfaces`, `default:${iface.family}`, iface.localAddress);
        }

        let existingEntry = await redis.hget(`${REDIS_PREFIX}interfaces`, iface.localAddress);
        if (existingEntry) {
            try {
                existingEntry = JSON.parse(existingEntry);

                iface.name = iface.name || existingEntry.name;

                if (!iface.localAddress || !iface.ip || !iface.name) {
                    continue;
                }
            } catch (err) {
                // ignore parsing errors
            }
        }

        delete iface.defaultInterface;
        await redis.hset(`${REDIS_PREFIX}interfaces`, iface.localAddress, JSON.stringify(iface));
    }
}

/**
 * Gets the local address to use for outbound connections
 * @param {Object} redis - Redis client instance
 * @param {string} protocol - Protocol name (e.g., 'smtp', 'imap')
 * @param {string} account - Account identifier
 * @param {string} [hint] - Optional IP address hint
 * @returns {Promise<Object>} Address information object
 */
async function getLocalAddress(redis, protocol, account, hint) {
    // Dynamic require to access tools.getServiceHostname() and tools.selectRendezvousAddress()
    // These functions are defined in tools.js, which also imports from this module
    const tools = require('../tools');

    let existingAddresses = Object.values(os.networkInterfaces())
        .flatMap(entry => entry)
        .map(entry => entry.address);

    if (hint) {
        let parsedHint = ipaddr.parse(hint);
        let normalizedHint = parsedHint.toNormalizedString();
        let iface = await redis.hget(`${REDIS_PREFIX}interfaces`, normalizedHint);
        try {
            iface = iface ? JSON.parse(iface) : null;
        } catch (err) {
            // ignore parsing errors
        }
        if (iface && existingAddresses.includes(iface.localAddress)) {
            iface.addressSelector = 'hint';
            return iface;
        }
    }

    let addressStrategy = await settings.get(`${protocol}Strategy`);
    let localAddresses = []
        .concat((await settings.get(`localAddresses`)) || [])
        .filter(address => existingAddresses.includes(address))
        .filter(address => net.isIPv4(address));
    let localAddress;

    let hostname = await tools.getServiceHostname(await settings.get('smtpEhloName'));

    let addressSelector;

    if (!localAddresses.length) {
        addressSelector = 'default';
        return { address: false, name: hostname, addressSelector };
    }

    if (localAddresses.length === 1) {
        addressSelector = 'single';
        localAddress = localAddresses[0];
    } else {
        switch (addressStrategy) {
            case 'random':
                addressSelector = 'random';
                localAddress = localAddresses[Math.floor(Math.random() * localAddresses.length)];
                break;
            case 'dedicated':
                addressSelector = 'dedicated';
                localAddress = tools.selectRendezvousAddress(account, localAddresses);
                break;
            default:
                addressSelector = 'unknown';
                return { address: false, name: hostname, addressSelector };
        }
    }

    if (!localAddress) {
        addressSelector = 'unset';
        return { address: false, name: hostname, addressSelector };
    }

    try {
        let addressData = JSON.parse(await redis.hget(`${REDIS_PREFIX}interfaces`, localAddress));
        addressData.name = addressData.name || hostname;
        addressData.addressSelector = addressSelector;
        return addressData;
    } catch (err) {
        logger.error({ msg: 'Failed to load address data', localAddress, err });
        addressSelector = 'error';
        return { address: false, name: hostname, addressSelector };
    }
}

module.exports = {
    resolvePublicInterfaces,
    updatePublicInterfaces,
    getLocalAddress,
    matchIp,
    resolveClientIp,
    detectAutomatedRequest,
    googleCrawlerMap
};
