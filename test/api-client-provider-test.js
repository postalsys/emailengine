'use strict';

// The provider each API client names for the authentication trust rule (summaryProvider()), which
// decides whose Authentication-Results header the AI summary and the OTP-Token check believe.
// GmailClient never set its type, so a Gmail API account trusted no header at all.

const test = require('node:test');
const assert = require('node:assert').strict;

const { GmailClient } = require('../lib/email-client/gmail-client');
const { OutlookClient } = require('../lib/email-client/outlook-client');
const { redis } = require('../lib/db');
const registerRedisTeardown = require('./helpers/redis-teardown');

registerRedisTeardown(redis);

test('the API clients name their provider for the authentication trust rule', () => {
    assert.equal(new GmailClient('provider-test', {}).summaryProvider(), 'gmail');
    assert.equal(new OutlookClient('provider-test', {}).summaryProvider(), 'outlook');
});
