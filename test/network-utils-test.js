'use strict';

const test = require('node:test');
const assert = require('node:assert').strict;

const { matchIp, googleCrawlerMap } = require('../lib/utils/network');

test('Network Utilities tests', async t => {
    t.after(() => {
        setTimeout(() => process.exit(), 1000).unref();
    });

    // matchIp tests
    await t.test('matchIp() matches exact IPv4 address', async () => {
        assert.strictEqual(matchIp('192.168.1.1', ['192.168.1.1']), true);
        assert.strictEqual(matchIp('192.168.1.1', ['192.168.1.2']), false);
    });

    await t.test('matchIp() matches IPv4 CIDR range', async () => {
        assert.strictEqual(matchIp('192.168.1.50', ['192.168.1.0/24']), true);
        assert.strictEqual(matchIp('192.168.1.255', ['192.168.1.0/24']), true);
        assert.strictEqual(matchIp('192.168.2.1', ['192.168.1.0/24']), false);
    });

    await t.test('matchIp() matches against multiple addresses', async () => {
        const addresses = ['10.0.0.0/8', '192.168.0.0/16', '172.16.0.0/12'];

        assert.strictEqual(matchIp('10.5.5.5', addresses), true);
        assert.strictEqual(matchIp('192.168.50.50', addresses), true);
        assert.strictEqual(matchIp('172.20.1.1', addresses), true);
        assert.strictEqual(matchIp('8.8.8.8', addresses), false);
    });

    await t.test('matchIp() handles /32 single host CIDR', async () => {
        assert.strictEqual(matchIp('192.168.1.1', ['192.168.1.1/32']), true);
        assert.strictEqual(matchIp('192.168.1.2', ['192.168.1.1/32']), false);
    });

    await t.test('matchIp() handles wide CIDR ranges', async () => {
        assert.strictEqual(matchIp('10.255.255.255', ['10.0.0.0/8']), true);
        assert.strictEqual(matchIp('11.0.0.0', ['10.0.0.0/8']), false);
    });

    await t.test('matchIp() handles localhost', async () => {
        assert.strictEqual(matchIp('127.0.0.1', ['127.0.0.0/8']), true);
        assert.strictEqual(matchIp('127.0.0.1', ['127.0.0.1']), true);
    });

    await t.test('matchIp() handles IPv6 addresses', async () => {
        assert.strictEqual(matchIp('::1', ['::1']), true);
        assert.strictEqual(matchIp('::1', ['::2']), false);
    });

    await t.test('matchIp() handles IPv6 CIDR ranges', async () => {
        assert.strictEqual(matchIp('2001:db8::1', ['2001:db8::/32']), true);
        assert.strictEqual(matchIp('2001:db9::1', ['2001:db8::/32']), false);
    });

    await t.test('matchIp() handles IPv4-mapped IPv6 addresses', async () => {
        // IPv4-mapped IPv6 addresses match other IPv4-mapped addresses
        assert.strictEqual(matchIp('::ffff:192.168.1.1', ['::ffff:192.168.1.1']), true);
        // Note: Direct comparison between IPv4 and IPv4-mapped IPv6 may not work
        // due to different address family handling in ipaddr.js
    });

    await t.test('matchIp() returns false for empty address list', async () => {
        assert.strictEqual(matchIp('192.168.1.1', []), false);
    });

    await t.test('matchIp() handles invalid addresses gracefully', async () => {
        // Should not throw, just return false
        assert.strictEqual(matchIp('192.168.1.1', ['invalid-address']), false);
    });

    await t.test('matchIp() handles mixed IPv4 and IPv6 in list gracefully', async () => {
        // When matching IPv4 address against a list with IPv6 entries,
        // the IPv6 entries are skipped (logged as errors but not thrown)
        const addresses = ['192.168.1.0/24', '2001:db8::/32', '10.0.0.1'];

        // IPv4 addresses match IPv4 entries in the list
        assert.strictEqual(matchIp('192.168.1.50', addresses), true);
        assert.strictEqual(matchIp('10.0.0.1', addresses), true);

        // IPv6 addresses match IPv6 entries in the list
        assert.strictEqual(matchIp('2001:db8::1', addresses), true);

        // Non-matching address returns false (even with mixed list)
        assert.strictEqual(matchIp('8.8.8.8', addresses), false);
    });

    // googleCrawlerMap tests
    await t.test('googleCrawlerMap is initialized', async () => {
        assert.ok(googleCrawlerMap instanceof Map);
        assert.ok(googleCrawlerMap.has('ipv4Prefix') || googleCrawlerMap.has('ipv6Prefix'));
    });

    await t.test('googleCrawlerMap contains IPv4 prefixes', async () => {
        const ipv4Prefixes = googleCrawlerMap.get('ipv4Prefix');
        if (ipv4Prefixes) {
            assert.ok(Array.isArray(ipv4Prefixes));
            assert.ok(ipv4Prefixes.length > 0);
        }
    });

    await t.test('googleCrawlerMap contains IPv6 prefixes', async () => {
        const ipv6Prefixes = googleCrawlerMap.get('ipv6Prefix');
        if (ipv6Prefixes) {
            assert.ok(Array.isArray(ipv6Prefixes));
            assert.ok(ipv6Prefixes.length > 0);
        }
    });

    // Edge cases for matchIp
    await t.test('matchIp() handles class A network', async () => {
        assert.strictEqual(matchIp('10.0.0.1', ['10.0.0.0/8']), true);
        assert.strictEqual(matchIp('10.255.255.254', ['10.0.0.0/8']), true);
    });

    await t.test('matchIp() handles class B network', async () => {
        assert.strictEqual(matchIp('172.16.0.1', ['172.16.0.0/12']), true);
        assert.strictEqual(matchIp('172.31.255.254', ['172.16.0.0/12']), true);
        assert.strictEqual(matchIp('172.32.0.1', ['172.16.0.0/12']), false);
    });

    await t.test('matchIp() handles class C network', async () => {
        assert.strictEqual(matchIp('192.168.0.1', ['192.168.0.0/16']), true);
        assert.strictEqual(matchIp('192.168.255.254', ['192.168.0.0/16']), true);
        assert.strictEqual(matchIp('192.169.0.1', ['192.168.0.0/16']), false);
    });

    await t.test('matchIp() handles /0 (all addresses)', async () => {
        assert.strictEqual(matchIp('1.2.3.4', ['0.0.0.0/0']), true);
        assert.strictEqual(matchIp('255.255.255.255', ['0.0.0.0/0']), true);
    });

    await t.test('matchIp() correctly handles broadcast address in range', async () => {
        assert.strictEqual(matchIp('192.168.1.255', ['192.168.1.0/24']), true);
    });

    await t.test('matchIp() correctly handles network address in range', async () => {
        assert.strictEqual(matchIp('192.168.1.0', ['192.168.1.0/24']), true);
    });
});
