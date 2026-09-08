'use strict';

const test = require('node:test');
const assert = require('node:assert').strict;
const fs = require('fs');
const path = require('path');

// Account configuration (`path`, `subconnections`) is stored exactly as the API received it,
// while a server listing carries whatever spelling the server answered with. IMAP makes the name
// INBOX case-insensitive, so the two sides disagree about it, and a raw `===` between them reads
// as "no match": an account configured `path: ["INBOX"]` against a server answering "Inbox"
// flagged every folder syncDisabled and indexed nothing, and a subconnection configured "INBOX"
// was marked mailboxMissing forever while the revival trigger kept finding the folder.
//
// That is a "the next caller forgets" failure - invisible in review, and invisible to any test
// that does not happen to exercise a mixed-case server. So the rule is asserted against the
// source: inside the IMAP client, a folder path is compared through samePath() (or the listing
// helpers built on it), never with a bare === or a bare normalizePath() pair.

const FILES = [
    'lib/email-client/imap-client.js',
    'lib/email-client/imap/mailbox.js',
    'lib/email-client/imap/sync-operations.js',
    'lib/email-client/imap/subconnection.js',
    'lib/email-client/imap/listing-diff.js'
];

// Two forbidden shapes: a raw equality against something that reads like a path, and the
// hand-written normalizePath() pair that samePath() exists to replace.
const RAW_PATH_COMPARE = /(?:\w+(?:\?)?\.path|\bpath)\s*(?:===|!==)\s*(?!=)/;
const RAW_NORMALIZE_PAIR = /normalizePath\([^)]*\)\s*(?:===|!==)\s*normalizePath\(/;

// Comparisons that are deliberately not path-vs-path, keyed by the exact source line so a new one
// has to be added here on purpose rather than slipping in. Empty today: every path comparison in
// these files goes through the helpers, and samePath's own definition lives in
// lib/utils/mailbox-path.js, which is not scanned.
const ALLOWED = new Set([]);

function offendingLines(file) {
    const source = fs.readFileSync(path.join(__dirname, '..', file), 'utf8');

    return source.split('\n').reduce((hits, line, index) => {
        const trimmed = line.trim();
        if (trimmed.startsWith('//') || trimmed.startsWith('*') || ALLOWED.has(trimmed)) {
            return hits;
        }
        // `typeof entry.path === 'string'` is a shape check, not a folder comparison
        const testable = trimmed.replace(/typeof\s+[\w.?[\]]+/g, 'TYPEOF');
        if (RAW_PATH_COMPARE.test(testable) || RAW_NORMALIZE_PAIR.test(testable)) {
            hits.push(`${file}:${index + 1}  ${trimmed}`);
        }
        return hits;
    }, []);
}

test('folder paths in the IMAP client are compared through samePath()', () => {
    const hits = FILES.flatMap(offendingLines);

    assert.deepStrictEqual(
        hits,
        [],
        `Compare folder paths with samePath() from lib/utils/mailbox-path.js (or matchesListingEntry()/configuredPathIndex() ` +
            `when matching account configuration against a listing). A bare === misses the case a server chose for INBOX. ` +
            `Offending lines:\n${hits.join('\n')}`
    );
});
