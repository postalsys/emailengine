'use strict';

// The release identifier EmailEngine reports to Sentry. See the comment on SENTRY_RELEASE in
// lib/sentry.js for why the package prefix is load bearing.
//
// This is a guardrail, not a behavior test: the value only has to keep the shape Sentry's
// release detector accepts.

const test = require('node:test');
const assert = require('node:assert').strict;

const { SENTRY_RELEASE, licenseTag } = require('../lib/sentry');
const packageData = require('../package.json');

// lib/sentry.js pulls in lib/tools, which keeps the event loop alive; the shared teardown forces
// the exit once the tests are done
require('./helpers/redis-teardown')();

test('Sentry release identifier', async t => {
    await t.test('names the package and the running version', () => {
        assert.equal(SENTRY_RELEASE, `${packageData.name}@${packageData.version}`);
    });

    await t.test('keeps the package prefix Sentry needs to order releases by semver', () => {
        // Release.is_semver_version(): no "@" means the project is ordered by the date each
        // version was first seen, whatever the digits say
        assert.match(SENTRY_RELEASE, /^[^@]+@\d+\.\d+\.\d+/);
    });
});

test('Sentry license tag (WORK-16)', async t => {
    await t.test('is a stable short digest, never the key itself', () => {
        const key = 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6';
        const tag = licenseTag(key);
        assert.match(tag, /^[0-9a-f]{16}$/);
        assert.ok(!key.includes(tag) && !tag.includes(key.slice(0, 8)), 'no part of the key is sent');
        assert.equal(licenseTag(key), tag, 'the same license always maps to the same tag');
        assert.notEqual(licenseTag(`${key}x`), tag);
    });
});
