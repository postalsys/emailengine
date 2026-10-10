'use strict';

// translations/messages.pot must come out of `npm run gettext` byte-identical from an unchanged
// tree; see gettext-extract.js for why that takes sorting. Pure filesystem read, no Redis.

const test = require('node:test');
const assert = require('node:assert').strict;
const fs = require('fs');
const pathlib = require('path');
const { po } = require('gettext-parser');

const { compareReferences, compileCanonical } = require('../gettext-extract');

const POT_PATH = pathlib.join(__dirname, '..', 'translations', 'messages.pot');

test('references sort by file, then numerically by line', () => {
    const references = ['views/b.hbs:3', 'views/a.hbs:10', 'lib/x.js:7', 'views/a.hbs:9'];
    assert.deepEqual(references.sort(compareReferences), ['lib/x.js:7', 'views/a.hbs:9', 'views/a.hbs:10', 'views/b.hbs:3']);
});

test('the catalog compiles the same whatever order its entries and references arrived in', () => {
    const canonical = source => compileCanonical(po.parse(Buffer.from(source))).toString();

    const first = canonical(
        ['#: views/b.hbs:2', '#: views/a.hbs:5', 'msgid "Shared"', 'msgstr ""', '', '#: views/a.hbs:1', 'msgid "Only in a"', 'msgstr ""', ''].join('\n') +
            ['#: views/b.hbs:1', 'msgid "Only in b"', 'msgstr ""', ''].join('\n')
    );
    const second = canonical(
        ['#: views/b.hbs:1', 'msgid "Only in b"', 'msgstr ""', '', '#: views/a.hbs:1', 'msgid "Only in a"', 'msgstr ""', ''].join('\n') +
            ['#: views/a.hbs:5', '#: views/b.hbs:2', 'msgid "Shared"', 'msgstr ""', ''].join('\n')
    );

    assert.equal(first, second);
    assert.match(first, /#: views\/a\.hbs:1\nmsgid "Only in a"[\s\S]*#: views\/a\.hbs:5\n#: views\/b\.hbs:2\nmsgid "Shared"[\s\S]*msgid "Only in b"/);
});

test('the committed messages.pot is in canonical order', () => {
    // Fails when the file was produced by an older extractor or edited by hand: `npm run gettext`
    // rewrites it into the order checked here
    const existing = fs.readFileSync(POT_PATH);
    assert.equal(compileCanonical(po.parse(existing)).toString(), existing.toString());
});
