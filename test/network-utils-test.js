'use strict';

const test = require('node:test');
const assert = require('node:assert').strict;

const { matchIp, resolveClientIp, googleCrawlerMap, detectAutomatedRequest, updatePublicInterfaces, getLocalAddress } = require('../lib/utils/network');

test('Network Utilities tests', async t => {
    t.after(() => {
        setTimeout(() => process.exit(), 1000).unref();
    });

    // matchIp tests
    await t.test('matchIp() refuses an IPv4-mapped range whose prefix predates the mapped block', async () => {
        // ::ffff:10.0.0.0/104 is 10.0.0.0/8 - the mapped prefix takes the first 96 bits
        assert.strictEqual(matchIp('10.1.2.3', ['::ffff:10.0.0.0/104']), true);
        assert.strictEqual(matchIp('11.1.2.3', ['::ffff:10.0.0.0/104']), false);

        // A shorter prefix describes no IPv4 subnet at all. Clamping the remainder to zero turned
        // it into 0.0.0.0/0, so one mistyped digit in an allowlist matched every IPv4 address -
        // the one direction an allowlist must never fail in.
        assert.strictEqual(matchIp('203.0.113.9', ['::ffff:10.0.0.0/80']), false);
        assert.strictEqual(matchIp('10.1.2.3', ['::ffff:10.0.0.0/80']), false);

        // and a bad entry does not take the rest of the list with it
        assert.strictEqual(matchIp('10.1.2.3', ['::ffff:10.0.0.0/80', '10.0.0.0/8']), true);
    });

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
    });

    await t.test('matchIp() treats an IPv4-mapped address as the IPv4 address it carries', async () => {
        // A dual-stack listener reports an IPv4 peer as ::ffff:a.b.c.d, while the allowlist is
        // written in plain IPv4. The two used to never compare equal, which silently disabled
        // EENGINE_API_PROXY_ADDRESSES on any deployment bound to `::`.
        assert.strictEqual(matchIp('::ffff:10.0.0.5', ['10.0.0.5']), true);
        assert.strictEqual(matchIp('::ffff:10.0.0.5', ['10.0.0.0/8']), true);
        assert.strictEqual(matchIp('::ffff:10.0.0.5', ['10.0.0.6']), false);
        assert.strictEqual(matchIp('::ffff:11.0.0.5', ['10.0.0.0/8']), false);

        // and the same in reverse, for an allowlist written in the mapped form
        assert.strictEqual(matchIp('10.0.0.5', ['::ffff:10.0.0.5']), true);
        assert.strictEqual(matchIp('10.0.0.5', ['::ffff:10.0.0.0/104']), true);
        assert.strictEqual(matchIp('11.0.0.5', ['::ffff:10.0.0.0/104']), false);
    });

    await t.test('matchIp() does not match a real IPv6 address against an IPv4 range', async () => {
        // The unwrap above must not turn a family mismatch into a match
        assert.strictEqual(matchIp('2001:db8::1', ['0.0.0.0/0']), false);
        assert.strictEqual(matchIp('::1', ['127.0.0.1']), false);
        assert.strictEqual(matchIp('127.0.0.1', ['::1']), false);
    });

    await t.test('matchIp() returns false for empty address list', async () => {
        assert.strictEqual(matchIp('192.168.1.1', []), false);
    });

    await t.test('matchIp() handles invalid addresses gracefully', async () => {
        // Should not throw, just return false
        assert.strictEqual(matchIp('192.168.1.1', ['invalid-address']), false);
    });

    await t.test('matchIp() handles mixed IPv4 and IPv6 in list gracefully', async () => {
        // Entries of the other family are simply not a match. A list mixing both is ordinary
        // configuration rather than a mistake, so it does not log an error per entry per request.
        const addresses = ['192.168.1.0/24', '2001:db8::/32', '10.0.0.1'];

        // IPv4 addresses match IPv4 entries in the list
        assert.strictEqual(matchIp('192.168.1.50', addresses), true);
        assert.strictEqual(matchIp('10.0.0.1', addresses), true);

        // IPv6 addresses match IPv6 entries in the list
        assert.strictEqual(matchIp('2001:db8::1', addresses), true);

        // Non-matching address returns false (even with mixed list)
        assert.strictEqual(matchIp('8.8.8.8', addresses), false);
    });

    await t.test('matchIp() fails closed for an unparseable subject address', async () => {
        // A non-IP value reaching an allowlist check must match nothing rather than throw. These
        // all used to escape matchIp() and surface as a 500 on any allowlist-protected route.
        for (let bad of ['not-an-ip', '', ' 1.2.3.4', '1.2.3.4:5678', '[::1]:443', 'unknown', '1.2.3.4.5']) {
            assert.strictEqual(matchIp(bad, ['1.2.3.4', '10.0.0.0/8']), false, `expected no match for ${JSON.stringify(bad)}`);
        }
    });

    // resolveClientIp tests
    // Every case shares the same peer address and an enabled proxy setting; each test varies only
    // the key it is actually about.
    const resolveFrom = overrides => resolveClientIp(Object.assign({ remoteAddress: '10.0.0.9', enableApiProxy: true }, overrides));

    await t.test('resolveClientIp() uses the socket address when the API proxy is disabled', async () => {
        assert.strictEqual(resolveFrom({ forwardedFor: '8.8.8.8', enableApiProxy: false }), '10.0.0.9');
    });

    await t.test('resolveClientIp() uses the socket address when no header is present', async () => {
        assert.strictEqual(resolveFrom({}), '10.0.0.9');
    });

    await t.test('resolveClientIp() ignores a forwarded value that is not a bare IP', async () => {
        for (let bad of ['unknown', '8.8.8.8:1234', '[2001:db8::1]:443', 'garbage', '']) {
            assert.strictEqual(resolveFrom({ forwardedFor: bad }), '10.0.0.9', `expected fallback for ${JSON.stringify(bad)}`);
        }
    });

    await t.test('resolveClientIp() discards the header entirely when the peer is not a declared proxy', async () => {
        assert.strictEqual(resolveFrom({ remoteAddress: '203.0.113.5', forwardedFor: '8.8.8.8', trustedProxies: ['10.0.0.0/8'] }), '203.0.113.5');
    });

    await t.test('resolveClientIp() takes the entry the closest trusted proxy observed, not the left-most one', async () => {
        // THE bypass this list exists to stop. Proxies APPEND to X-Forwarded-For rather than
        // overwriting it (nginx `$proxy_add_x_forwarded_for`, Apache mod_proxy, HAProxy
        // `option forwardfor`), so a caller that sends its own X-Forwarded-For has its value
        // preserved as the left-most entry. Reading left-most would hand an internet caller the
        // office address that EENGINE_ADMIN_ACCESS_ADDRESSES is gating on.
        const resolved = resolveFrom({
            remoteAddress: '10.0.0.2', // nginx
            forwardedFor: '203.0.113.10, 198.51.100.77', // spoofed by the caller, then the real peer nginx saw
            trustedProxies: ['10.0.0.2']
        });

        assert.strictEqual(resolved, '198.51.100.77');
        assert.strictEqual(matchIp(resolved, ['203.0.113.10']), false, 'the spoofed address must not satisfy an allowlist');
    });

    await t.test('resolveClientIp() walks back through a whole chain of declared proxies', async () => {
        // attacker -> nginx1 (10.0.0.2) -> nginx2 (10.0.0.3) -> EmailEngine
        assert.strictEqual(
            resolveFrom({
                remoteAddress: '10.0.0.3',
                forwardedFor: '203.0.113.10, 198.51.100.77, 10.0.0.2',
                trustedProxies: ['10.0.0.0/8']
            }),
            '198.51.100.77'
        );
    });

    await t.test('resolveClientIp() handles a single-entry chain from an overwriting proxy', async () => {
        // A proxy configured to replace rather than append leaves exactly one entry, which is the
        // real client either way
        assert.strictEqual(resolveFrom({ remoteAddress: '10.0.0.2', forwardedFor: '198.51.100.77', trustedProxies: ['10.0.0.2'] }), '198.51.100.77');
    });

    await t.test('resolveClientIp() falls back to the peer when every hop is one of ours', async () => {
        assert.strictEqual(resolveFrom({ remoteAddress: '10.0.0.3', forwardedFor: '10.0.0.2, 10.0.0.4', trustedProxies: ['10.0.0.0/8'] }), '10.0.0.3');
    });

    await t.test('resolveClientIp() falls back to the peer when the observed entry is not an IP', async () => {
        assert.strictEqual(resolveFrom({ remoteAddress: '10.0.0.2', forwardedFor: 'unknown, garbage', trustedProxies: ['10.0.0.2'] }), '10.0.0.2');
    });

    await t.test('resolveClientIp() trims whitespace around chain entries', async () => {
        assert.strictEqual(
            resolveFrom({ remoteAddress: '10.0.0.2', forwardedFor: ' 203.0.113.10 ,  198.51.100.77 ', trustedProxies: ['10.0.0.2'] }),
            '198.51.100.77'
        );
    });

    await t.test('resolveClientIp() keeps legacy left-most behavior when no trusted proxies are configured', async () => {
        // Without a proxy list there is no way to know how many hops to believe, so existing
        // deployments keep the address they have always logged. Documented as unsafe for
        // allowlists; the API worker warns about exactly this combination at startup.
        for (let trustedProxies of [null, undefined, []]) {
            assert.strictEqual(resolveFrom({ remoteAddress: '203.0.113.5', forwardedFor: '8.8.8.8, 10.0.0.9', trustedProxies }), '8.8.8.8');
        }
    });

    await t.test('resolveClientIp() accepts IPv6 forwarded addresses', async () => {
        assert.strictEqual(resolveFrom({ remoteAddress: '::1', forwardedFor: '2001:db8::1', trustedProxies: ['::1'] }), '2001:db8::1');
    });

    await t.test('resolveClientIp() recognizes a declared proxy reported in the IPv4-mapped form', async () => {
        // A listener bound to `::` reports an IPv4 proxy as ::ffff:10.0.0.5, while the operator
        // configured EENGINE_API_PROXY_ADDRESSES as plain IPv4. The peer used to fail the trust
        // check, so the header was discarded and the admin allowlist then saw the proxy's own
        // address instead of the client's - locking out the very setup the startup warning asks for.
        assert.strictEqual(resolveFrom({ remoteAddress: '::ffff:10.0.0.5', forwardedFor: '203.0.113.9', trustedProxies: ['10.0.0.5'] }), '203.0.113.9');
        assert.strictEqual(resolveFrom({ remoteAddress: '::ffff:10.0.0.5', forwardedFor: '203.0.113.9', trustedProxies: ['10.0.0.0/8'] }), '203.0.113.9');

        // chain entries arrive in the mapped form too when the hop itself is dual-stack
        assert.strictEqual(
            resolveFrom({ remoteAddress: '::ffff:10.0.0.5', forwardedFor: '203.0.113.9, ::ffff:10.0.0.6', trustedProxies: ['10.0.0.0/8'] }),
            '203.0.113.9'
        );

        // and a peer that is still not one of ours gets no say
        assert.strictEqual(resolveFrom({ remoteAddress: '::ffff:192.0.2.1', forwardedFor: '203.0.113.9', trustedProxies: ['10.0.0.5'] }), '::ffff:192.0.2.1');
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

    // detectAutomatedRequest tests
    await t.test('detectAutomatedRequest() returns false for invalid IP format', async () => {
        const result = await detectAutomatedRequest('not-an-ip');
        assert.strictEqual(result, false);
    });

    await t.test('detectAutomatedRequest() returns false for regular IPv4', async () => {
        // A random IP that is not a Google crawler
        const result = await detectAutomatedRequest('192.168.1.1');
        assert.strictEqual(result, false);
    });

    await t.test('detectAutomatedRequest() returns false for regular IPv6', async () => {
        const result = await detectAutomatedRequest('2001:db8::1');
        assert.strictEqual(result, false);
    });

    await t.test('detectAutomatedRequest() detects Google crawler IPv4', async () => {
        // Get a real Google crawler IP from the map
        const ipv4Prefixes = googleCrawlerMap.get('ipv4Prefix');
        if (ipv4Prefixes && ipv4Prefixes.length > 0) {
            // The prefixes are in CIDR format [address, bits]
            // Create an IP within the first prefix range
            const prefix = ipv4Prefixes[0];
            const baseIp = prefix[0].toString();
            const result = await detectAutomatedRequest(baseIp);
            assert.strictEqual(result, true, `Expected ${baseIp} to be detected as Google crawler`);
        }
    });

    await t.test('detectAutomatedRequest() detects Google crawler IPv6', async () => {
        const ipv6Prefixes = googleCrawlerMap.get('ipv6Prefix');
        if (ipv6Prefixes && ipv6Prefixes.length > 0) {
            const prefix = ipv6Prefixes[0];
            const baseIp = prefix[0].toString();
            const result = await detectAutomatedRequest(baseIp);
            assert.strictEqual(result, true, `Expected ${baseIp} to be detected as Google crawler`);
        }
    });

    await t.test('detectAutomatedRequest() handles DNS lookup failures gracefully', async () => {
        // This IP should not be a Google crawler and DNS reverse will likely fail
        // The function should handle this gracefully and return false
        const result = await detectAutomatedRequest('192.0.2.1'); // TEST-NET-1, reserved
        assert.strictEqual(result, false);
    });

    // updatePublicInterfaces tests with mock Redis
    await t.test('updatePublicInterfaces() updates Redis with interface data', async () => {
        const storedData = new Map();
        const mockRedis = {
            hset: async (key, field, value) => {
                if (!storedData.has(key)) {
                    storedData.set(key, new Map());
                }
                storedData.get(key).set(field, value);
                return 1;
            },
            hget: async (key, field) => {
                if (!storedData.has(key)) return null;
                return storedData.get(key).get(field) || null;
            }
        };

        // This should not throw
        await updatePublicInterfaces(mockRedis);

        // Check that some data was stored (depends on system having network interfaces)
        // At minimum, it should complete without error
        assert.ok(true, 'updatePublicInterfaces completed without error');
    });

    await t.test('updatePublicInterfaces() handles existing interface entries', async () => {
        const storedData = new Map();
        const mockRedis = {
            hset: async (key, field, value) => {
                if (!storedData.has(key)) {
                    storedData.set(key, new Map());
                }
                storedData.get(key).set(field, value);
                return 1;
            },
            hget: async (key, field) => {
                // Return existing entry for first call
                if (field !== 'default:IPv4' && field !== 'default:IPv6') {
                    return JSON.stringify({ name: 'existing-name', localAddress: field, ip: '1.2.3.4' });
                }
                return null;
            }
        };

        await updatePublicInterfaces(mockRedis);
        assert.ok(true, 'updatePublicInterfaces handled existing entries');
    });

    await t.test('updatePublicInterfaces() handles malformed JSON in existing entry', async () => {
        const mockRedis = {
            hset: async () => 1,
            hget: async (key, field) => {
                if (field !== 'default:IPv4' && field !== 'default:IPv6') {
                    return 'not-valid-json{';
                }
                return null;
            }
        };

        // Should not throw even with malformed JSON
        await updatePublicInterfaces(mockRedis);
        assert.ok(true, 'updatePublicInterfaces handled malformed JSON');
    });

    // getLocalAddress tests with mock Redis
    await t.test('getLocalAddress() returns default when no local addresses configured', async () => {
        const mockRedis = {
            hget: async () => null
        };

        // Mock settings module - this is tricky since it's required internally
        // For now, test that the function handles missing data gracefully
        const result = await getLocalAddress(mockRedis, 'smtp', 'test-account');

        assert.ok(result, 'Should return a result object');
        assert.ok('addressSelector' in result, 'Should have addressSelector property');
    });

    await t.test('getLocalAddress() uses hint when provided and valid', async () => {
        const testAddress = '192.168.1.100';
        const mockRedis = {
            hget: async (key, field) => {
                if (field === testAddress) {
                    return JSON.stringify({
                        localAddress: testAddress,
                        ip: '203.0.113.1',
                        name: 'test-host'
                    });
                }
                return null;
            }
        };

        // Note: This test may not work fully because the hint address
        // needs to exist in os.networkInterfaces(). We're testing the code path.
        const result = await getLocalAddress(mockRedis, 'smtp', 'test-account', testAddress);
        assert.ok(result, 'Should return a result object');
    });

    await t.test('getLocalAddress() handles Redis JSON parse errors', async () => {
        const mockRedis = {
            hget: async () => 'invalid-json{'
        };

        const result = await getLocalAddress(mockRedis, 'smtp', 'test-account', '192.168.1.1');
        assert.ok(result, 'Should return a result object even with parse error');
    });

    // Additional edge cases
    await t.test('matchIp() handles IPv6 localhost', async () => {
        assert.strictEqual(matchIp('::1', ['::1/128']), true);
        assert.strictEqual(matchIp('::1', ['::0/0']), true);
    });

    await t.test('matchIp() handles full IPv6 address format', async () => {
        assert.strictEqual(matchIp('2001:0db8:0000:0000:0000:0000:0000:0001', ['2001:db8::/32']), true);
    });

    await t.test('matchIp() handles compressed IPv6 against full format', async () => {
        assert.strictEqual(matchIp('2001:db8::1', ['2001:0db8:0000:0000:0000:0000:0000:0001']), true);
    });

    await t.test('matchIp() handles link-local IPv6', async () => {
        assert.strictEqual(matchIp('fe80::1', ['fe80::/10']), true);
        assert.strictEqual(matchIp('fe80::ffff:ffff:ffff:ffff', ['fe80::/10']), true);
    });

    await t.test('matchIp() handles unique local IPv6 (ULA)', async () => {
        assert.strictEqual(matchIp('fd00::1', ['fc00::/7']), true);
        assert.strictEqual(matchIp('fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff', ['fc00::/7']), true);
    });

    await t.test('detectAutomatedRequest() returns false for empty string', async () => {
        const result = await detectAutomatedRequest('');
        assert.strictEqual(result, false);
    });

    await t.test('googleCrawlerMap prefixes are valid CIDR ranges', async () => {
        const ipv4Prefixes = googleCrawlerMap.get('ipv4Prefix');
        const ipv6Prefixes = googleCrawlerMap.get('ipv6Prefix');

        if (ipv4Prefixes) {
            for (const prefix of ipv4Prefixes) {
                // Each prefix should be an array [address, bits]
                assert.ok(Array.isArray(prefix), 'Prefix should be an array');
                assert.strictEqual(prefix.length, 2, 'Prefix should have 2 elements');
                assert.ok(typeof prefix[1] === 'number', 'CIDR bits should be a number');
                assert.ok(prefix[1] >= 0 && prefix[1] <= 32, 'IPv4 CIDR bits should be 0-32');
            }
        }

        if (ipv6Prefixes) {
            for (const prefix of ipv6Prefixes) {
                assert.ok(Array.isArray(prefix), 'Prefix should be an array');
                assert.strictEqual(prefix.length, 2, 'Prefix should have 2 elements');
                assert.ok(typeof prefix[1] === 'number', 'CIDR bits should be a number');
                assert.ok(prefix[1] >= 0 && prefix[1] <= 128, 'IPv6 CIDR bits should be 0-128');
            }
        }
    });
});
