'use strict';

// The one severity order behind every "worst of" badge (lib/utils/severity.js).

const test = require('node:test');
const assert = require('node:assert').strict;

const { severityRank, worstBy } = require('../lib/utils/severity');

test('severity order', async t => {
    await t.test('ranks attention over information over health', () => {
        assert.ok(severityRank('error') > severityRank('warning'));
        assert.ok(severityRank('warning') > severityRank('info'));
        assert.ok(severityRank('info') > severityRank('neutral'));
        assert.ok(severityRank('neutral') > severityRank('success'));
    });

    await t.test('an unknown type ranks with success rather than above everything', () => {
        assert.equal(severityRank('purple'), severityRank('success'));
        assert.equal(severityRank(undefined), severityRank('success'));
    });

    await t.test('picks the worst item, the first of equals', () => {
        const items = [
            { type: 'success', id: 1 },
            { type: 'warning', id: 2 },
            { type: 'warning', id: 3 },
            { type: 'info', id: 4 }
        ];
        assert.equal(worstBy(items, item => item.type).id, 2);
        assert.equal(worstBy([items[0]], item => item.type).id, 1);
    });
});
