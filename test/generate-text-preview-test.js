'use strict';

const test = require('node:test');
const assert = require('node:assert').strict;

const { generateTextPreview } = require('../lib/generate-text-preview');

test('generateTextPreview', async t => {
    await t.test('returns short text as it is', () => {
        assert.equal(generateTextPreview({ plain: 'Hello there' }, 128), 'Hello there');
    });

    await t.test('cuts at a word boundary', () => {
        assert.equal(generateTextPreview({ plain: 'alpha beta gamma delta' }, 12), 'alpha beta');
    });

    await t.test('keeps the hard cut when the chunk has no boundary to cut at', () => {
        // Used to strip the "partial word" - which was the whole chunk - and return an empty preview
        const token = 'abcdefghij'.repeat(10);
        assert.equal(generateTextPreview({ plain: token }, 20), token.substring(0, 20));
    });

    await t.test('renders HTML to text first', () => {
        assert.equal(generateTextPreview({ html: '<p>Hello <b>world</b></p>' }, 128), 'Hello world');
    });

    await t.test('returns null without content', () => {
        assert.equal(generateTextPreview({}, 128), null);
    });
});
