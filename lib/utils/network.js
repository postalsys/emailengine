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
 * Matches an IP address against a list of addresses or CIDR ranges
 * @param {string} ip - IP address to check
 * @param {string[]} addresses - Array of IP addresses or CIDR ranges
 * @returns {boolean} True if IP matches any address in the list
 */
function matchIp(ip, addresses) {
    let parsed = ipaddr.parse(ip);
    for (let addr of addresses) {
        try {
            let match;
            if (/\/\d+$/.test(addr)) {
                match = parsed.match(ipaddr.parseCIDR(addr));
            } else {
                match = parsed.toNormalizedString() === ipaddr.parse(addr).toNormalizedString();
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
    // Import dynamically to avoid circular dependency issues
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
    detectAutomatedRequest,
    googleCrawlerMap
};
