'use strict';

// Registrable-domain lookup against the Public Suffix List (https://publicsuffix.org/list/), through
// tldts, which compiles the list in and releases with every change to it. @postalsys/email-ai-tools
// already loads the same tldts for its own lookups. Until 2026-11 EmailEngine parsed its own copy of
// the list (data/public_suffix_list.dat, refreshed by copy-static-files.sh); over all 31 678 names
// derived from that list's rules, this answers the same.
//
// Both the ICANN and the private section count (allowPrivateDomains), as they always did here.

const net = require('net');
const { getDomain } = require('tldts');

// Full stops other scripts use, which URL host parsing folds into "."
const FULL_STOPS = /[。．｡]/g;

/**
 * Returns the registrable domain of a host name: the public suffix plus one label, e.g.
 * "example.co.uk" for "imap.mail.example.co.uk".
 *
 * @param {string} host
 * @returns {string|null} The registrable domain in the spelling of the input (lower-cased, an IDN
 *     stays in Unicode), or null for an IP address, an invalid name, or a name that is itself a
 *     public suffix
 */
function getRegistrableDomain(host) {
    if (typeof host !== 'string') {
        return null;
    }

    host = host.trim().toLowerCase().replace(FULL_STOPS, '.').replace(/\.$/, '');
    if (!host || net.isIP(host.replace(/^\[|\]$/g, '')) || host.split('.').some(label => !label)) {
        return null;
    }

    // validateHostname is off because the callers pass names they did not choose (DKIM domains,
    // configured server hosts), and a label with an underscore or a leading hyphen still has a
    // registrable domain
    return getDomain(host, { allowPrivateDomains: true, validateHostname: false }) || null;
}

module.exports = { getRegistrableDomain };
