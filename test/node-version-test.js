'use strict';

// The startup warning for a Node.js release older than the dependency tree supports, and the
// guardrail that keeps its threshold equal to the engines field npm reads.

const test = require('node:test');
const assert = require('node:assert').strict;
const fs = require('fs');
const pathlib = require('path');

const { MIN_SUPPORTED_NODE, isBelowSupportedNode } = require('../lib/node-version');

test('isBelowSupportedNode()', async t => {
    await t.test('releases older than the minimum are flagged', () => {
        for (const version of ['20.0.0', '20.18.1', '20.18.99', '18.20.4', 'v20.18.0']) {
            assert.equal(isBelowSupportedNode(version), true, version);
        }
    });

    await t.test('the minimum itself and anything newer are not', () => {
        for (const version of ['20.19.0', '20.19.1', '20.20.0', '22.0.0', '22.12.0', '24.11.1', 'v24.0.0']) {
            assert.equal(isBelowSupportedNode(version), false, version);
        }
    });

    await t.test('a component compared numerically, not as text', () => {
        // '20.9.0' sorts after '20.19.0' as a string
        assert.equal(isBelowSupportedNode('20.9.0'), true);
        assert.equal(isBelowSupportedNode('20.100.0'), false);
    });

    await t.test('the running Node passes, since CI runs the minimum and newer', () => {
        assert.equal(isBelowSupportedNode(process.versions.node), false);
    });
});

test('the threshold matches engines.node in package.json', () => {
    const pkg = JSON.parse(fs.readFileSync(pathlib.join(__dirname, '..', 'package.json'), 'utf-8'));
    assert.equal(pkg.engines.node, `>=${MIN_SUPPORTED_NODE}`);
});
