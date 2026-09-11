'use strict';

// The release identifier EmailEngine reports to Sentry. See the comment on SENTRY_RELEASE in
// lib/sentry.js for why the package prefix is load bearing.
//
// This is a guardrail, not a behavior test: the value only has to keep the shape Sentry's
// release detector accepts.

const test = require('node:test');
const assert = require('node:assert').strict;

const { SENTRY_RELEASE } = require('../lib/sentry');
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
