'use strict';

// Registrable-domain lookup against the Public Suffix List (https://publicsuffix.org/list/), in
// place of the psl package, whose bundled copy of the list had not been refreshed since its last
// release. The list itself lives in data/public_suffix_list.dat and is refreshed by
// copy-static-files.sh on every `npm run update`.
//
// The matching follows the list's own algorithm (https://github.com/publicsuffix/list/wiki/Format):
// an exception rule wins outright, otherwise the matching rule with the most labels does, and a
// name no rule covers falls back to the implicit "*" rule (its last label is the suffix). Both the
// ICANN and the private section are used, as psl did.

const fs = require('fs');
const pathlib = require('path');
const net = require('net');
const { domainToASCII } = require('url');

const LIST_PATH = pathlib.join(__dirname, '..', '..', 'data', 'public_suffix_list.dat');

/**
 * @param {string} text The list in its published format
 * @returns {{ exact: Set<string>, wildcard: Set<string>, exception: Set<string> }} Rules in ASCII
 *     (punycode) form; `wildcard` holds the parent of each "*." rule, which `exact` holds as well
 */
function parseList(text) {
    const rules = { exact: new Set(), wildcard: new Set(), exception: new Set() };

    for (let line of text.split('\n')) {
        // a rule is the first whitespace-delimited token of a line that is not a comment
        line = line.trim().split(/\s/)[0];
        if (!line || line.startsWith('//')) {
            continue;
        }

        let set = rules.exact;
        if (line.startsWith('!')) {
            set = rules.exception;
            line = line.slice(1);
        } else if (line.startsWith('*.')) {
            set = rules.wildcard;
            line = line.slice(2);
        }

        const rule = domainToASCII(line) || line.toLowerCase();
        set.add(rule);

        // The parent of a wildcard rule counts as a public suffix of its own, as it does in psl and
        // libpsl: "*.kawasaki.jp" makes "kawasaki.jp" no more registrable than "foo.kawasaki.jp"
        if (set === rules.wildcard) {
            rules.exact.add(rule);
        }
    }

    return rules;
}

let defaultRules = null;

/**
 * Returns the registrable domain of a host name: the public suffix plus one label, e.g.
 * "example.co.uk" for "imap.mail.example.co.uk".
 *
 * @param {string} host
 * @param {Object} [rules] Parsed rules, the bundled list when omitted
 * @returns {string|null} The registrable domain in the spelling of the input (lower-cased), or null
 *     for an IP address, an invalid name, or a name that is itself a public suffix
 */
function getRegistrableDomain(host, rules) {
    if (typeof host !== 'string') {
        return null;
    }

    host = host.trim().toLowerCase().replace(/\.$/, '');
    if (!host || net.isIP(host.replace(/^\[|\]$/g, ''))) {
        return null;
    }

    const ascii = domainToASCII(host);
    if (!ascii) {
        return null;
    }

    const labels = ascii.split('.');
    if (labels.some(label => !label)) {
        return null;
    }

    if (!rules) {
        defaultRules = defaultRules || parseList(fs.readFileSync(LIST_PATH, 'utf-8'));
        rules = defaultRules;
    }

    // number of labels in the public suffix
    let suffixLength = 0;

    for (let i = 0; i < labels.length && !suffixLength; i++) {
        // an exception marks its own name as registrable: the suffix is one label shorter
        if (rules.exception.has(labels.slice(i).join('.'))) {
            suffixLength = labels.length - i - 1;
        }
    }

    for (let i = 0; i < labels.length && !suffixLength; i++) {
        if (rules.exact.has(labels.slice(i).join('.')) || (i + 1 < labels.length && rules.wildcard.has(labels.slice(i + 1).join('.')))) {
            suffixLength = labels.length - i;
        }
    }

    suffixLength = suffixLength || 1;

    if (labels.length <= suffixLength) {
        return null;
    }

    // Answer in the caller's spelling (an IDN stays in Unicode) when the label counts line up, which
    // they do unless the input used an ideographic full stop that domainToASCII folded into a dot
    const original = host.split('.');
    const source = original.length === labels.length ? original : labels;
    return source.slice(-(suffixLength + 1)).join('.');
}

module.exports = { getRegistrableDomain, parseList, LIST_PATH };
