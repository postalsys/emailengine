'use strict';

// The keys the SMTP and IMAP proxy failed-login budgets are kept under (lib/auth-token.js): a
// client-chosen username is digested rather than written into Redis as it was, and an IPv6 client
// is budgeted per /64, the block it controls, rather than per address.

const test = require('node:test');
const assert = require('node:assert').strict;

const { authFailureKey, authFailureAddressKey } = require('../lib/auth-token');
const { redis } = require('../lib/db');
const registerRedisTeardown = require('./helpers/redis-teardown');

registerRedisTeardown(redis);

test('a username is digested into the budget key', () => {
    const key = authFailureKey('203.0.113.7', 'alice@example.com');
    assert.match(key, /^auth:fail:203\.0\.113\.7:[A-Za-z0-9_-]{22}$/);
    assert.doesNotMatch(key, /alice/);
    assert.equal(authFailureKey('203.0.113.7', 'alice@example.com'), key, 'stable per name');
    assert.notEqual(authFailureKey('203.0.113.7', 'bob@example.com'), key);

    // a megabyte of username makes the same size of key as a short one, so an unauthenticated
    // client can no longer fill Redis with keys the size of its upload
    assert.equal(authFailureKey('203.0.113.7', 'x'.repeat(1024 * 1024)).length, key.length);
    assert.equal(authFailureKey('203.0.113.7', ''), 'auth:fail:203.0.113.7:');
    assert.equal(authFailureKey(undefined, undefined), 'auth:fail:unknown:');
});

test('an IPv6 client is budgeted per /64', () => {
    assert.equal(authFailureAddressKey('2001:db8:1:2:3:4:5:6'), 'auth:fail-addr:2001:db8:1:2::/64');
    assert.equal(authFailureAddressKey('2001:db8:1:2:ffff:ffff:ffff:ffff'), 'auth:fail-addr:2001:db8:1:2::/64', 'the same block');
    assert.notEqual(authFailureAddressKey('2001:db8:1:3::1'), authFailureAddressKey('2001:db8:1:2::1'), 'another block');
    assert.equal(authFailureKey('2001:db8:1:2:3:4:5:6', 'u'), authFailureKey('2001:db8:1:2::9', 'u'));

    // IPv4 and IPv4-mapped IPv6 are kept whole, and as the same address
    assert.equal(authFailureAddressKey('203.0.113.7'), 'auth:fail-addr:203.0.113.7');
    assert.equal(authFailureAddressKey('::ffff:203.0.113.7'), 'auth:fail-addr:203.0.113.7');
    // anything that is not an address is used as it was, the PROXY header case
    assert.equal(authFailureAddressKey('not-an-address'), 'auth:fail-addr:not-an-address');
});
