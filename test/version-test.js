'use strict';

// lib/utils/version.js decides whether the update check offers an upgrade and whether the license
// check can skip revalidation, so precedence has to follow semver exactly.

const test = require('node:test');
const assert = require('node:assert').strict;

const { parseVersion, compareVersions } = require('../lib/utils/version');

test('parseVersion', async t => {
    await t.test('parses release and pre-release versions, with or without a v prefix', () => {
        assert.deepStrictEqual(parseVersion('2.84.2'), { core: [2, 84, 2], prerelease: [] });
        assert.deepStrictEqual(parseVersion('v2.84.2'), { core: [2, 84, 2], prerelease: [] });
        assert.deepStrictEqual(parseVersion('3.0.0-beta.11'), { core: [3, 0, 0], prerelease: ['beta', '11'] });
        assert.deepStrictEqual(parseVersion('1.0.0+build.5'), { core: [1, 0, 0], prerelease: [] });
        assert.deepStrictEqual(parseVersion('1.0.0-rc.1+build.5'), { core: [1, 0, 0], prerelease: ['rc', '1'] });
    });

    await t.test('rejects anything that is not a full version', () => {
        for (const input of [
            '',
            '2',
            '2.84',
            '2.84.2.1',
            '02.84.2',
            '2.84.x',
            '>=2.84.2',
            ' 2.84.2',
            '2.84.2-',
            '2.84.2-beta..1',
            'latest',
            null,
            undefined,
            284,
            {}
        ]) {
            assert.strictEqual(parseVersion(input), null, JSON.stringify(input));
        }
    });
});

test('compareVersions', async t => {
    await t.test('orders the semver 2.0.0 precedence example', () => {
        const ordered = [
            '1.0.0-alpha',
            '1.0.0-alpha.1',
            '1.0.0-alpha.beta',
            '1.0.0-beta',
            '1.0.0-beta.2',
            '1.0.0-beta.11',
            '1.0.0-rc.1',
            '1.0.0',
            '1.0.1',
            '1.1.0',
            '1.10.0',
            '2.0.0'
        ];
        for (let i = 0; i < ordered.length; i++) {
            for (let j = 0; j < ordered.length; j++) {
                assert.strictEqual(compareVersions(ordered[i], ordered[j]), Math.sign(i - j), `${ordered[i]} vs ${ordered[j]}`);
            }
        }
    });

    await t.test('compares numerically, not as strings', () => {
        assert.strictEqual(compareVersions('2.84.10', '2.84.9'), 1);
        assert.strictEqual(compareVersions('2.9.0', '2.10.0'), -1);
    });

    await t.test('ignores the v prefix and build metadata', () => {
        assert.strictEqual(compareVersions('v2.84.2', '2.84.2'), 0);
        assert.strictEqual(compareVersions('2.84.2+a', '2.84.2+b'), 0);
    });

    await t.test('throws a TypeError naming the bad argument', () => {
        assert.throws(() => compareVersions('2.84', '2.84.2'), { name: 'TypeError', message: 'Invalid version: "2.84"' });
        assert.throws(() => compareVersions('2.84.2', null), { name: 'TypeError', message: 'Invalid version: null' });
    });
});
