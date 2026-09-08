'use strict';

const test = require('node:test');
const assert = require('node:assert').strict;
const fs = require('fs');
const path = require('path');

// getCurrentListing() processes only half of the diff it computes: it clears deleted folders
// itself, but the folders that appeared are reported through the one-shot `isNew` flag on the
// entries it returns, and it persists the new listing in the same call. A caller that reads
// the listing and drops the result therefore consumes that flag, and the folder is registered
// by a later resync with its mailboxNew notification never sent.
//
// That is a "the next caller forgets" failure: invisible in review, and invisible to any test
// that does not happen to cover the new call site. So the rule is asserted against the source.

const SOURCE = path.join(__dirname, '..', 'lib', 'email-client', 'imap-client.js');

// Every method that reads a listing, and what it has to do with it.
// 'handover' - must pass the listing to processListing()/processNewListingEntries()
// anything else - the reason this method may keep the listing to itself
const EXPECTED = new Map([
    ['refreshAndProcessListing', 'handover'],
    ['listMailboxes', 'handover'],
    ['uploadMessage', 'handover'],
    ['processSubConnections', 'handover'],
    ['connect', 'registers every listed folder in its own loop, and picks the folder to IDLE on']
]);

// How far below a call site the handover may appear
const WINDOW = 12;

const METHOD = /^ {4}(?:async )?([a-zA-Z_$][\w$]*)\(/;

function readCallSites() {
    const lines = fs.readFileSync(SOURCE, 'utf8').split('\n');

    return lines.reduce((sites, line, index) => {
        if (!line.includes('this.getCurrentListing(')) {
            return sites;
        }

        let method = false;
        for (let back = index; back >= 0 && !method; back--) {
            const declaration = lines[back].match(METHOD);
            if (declaration) {
                method = declaration[1];
            }
        }

        sites.push({
            method,
            line: index + 1,
            follows: lines.slice(index + 1, index + 1 + WINDOW).join('\n')
        });
        return sites;
    }, []);
}

test('every method that reads a mailbox listing is accounted for', () => {
    const methods = new Set(readCallSites().map(site => site.method));

    assert.ok(methods.size >= 5, `expected the known readers to be found, got ${[...methods].join(', ')}`);
    assert.deepEqual(
        [...methods].filter(method => !EXPECTED.has(method)),
        [],
        'a new listing reader must either hand the listing to processNewListingEntries() or be listed in EXPECTED with its reason'
    );
    assert.deepEqual(
        [...EXPECTED.keys()].filter(method => !methods.has(method)),
        [],
        'EXPECTED names a method that no longer reads a listing'
    );
});

test('every listing reader that must hand its listing over does so', () => {
    const unhandled = readCallSites()
        .filter(site => EXPECTED.get(site.method) === 'handover')
        .filter(site => !/this\.process(Listing|NewListingEntries)\(/.test(site.follows));

    assert.deepEqual(
        unhandled.map(site => `${site.method}() at line ${site.line}`),
        [],
        'a listing that is only read still consumes the one-shot isNew flag - pass it to processNewListingEntries()'
    );
});
