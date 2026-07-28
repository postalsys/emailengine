'use strict';

// Unit tests for lib/egress-filter.js. The module is pure apart from an optional DNS lookup, which
// is injected here, so this suite needs no Redis and no network.

const test = require('node:test');
const assert = require('node:assert').strict;

const {
    assertAllowedUrl,
    isBlockedAddress,
    normalizePolicy,
    clearVerdictCache,
    POLICY_OFF,
    POLICY_LINK_LOCAL,
    POLICY_PRIVATE
} = require('../lib/egress-filter');

// Resolver stub in the shape dns.lookup(host, {all: true}) returns
const resolvesTo =
    (...addresses) =>
    async () =>
        addresses.map(address => ({ address, family: address.includes(':') ? 6 : 4 }));

const assertBlocked = async (url, opts) => {
    await assert.rejects(assertAllowedUrl(url, opts), err => err.code === 'EEGRESSBLOCKED', `expected ${url} to be blocked`);
};

test('normalizePolicy', async t => {
    await t.test('accepts the known policies', () => {
        assert.strictEqual(normalizePolicy('off'), POLICY_OFF);
        assert.strictEqual(normalizePolicy('private'), POLICY_PRIVATE);
        assert.strictEqual(normalizePolicy('link-local'), POLICY_LINK_LOCAL);
    });

    await t.test('is case and whitespace insensitive', () => {
        assert.strictEqual(normalizePolicy('  PRIVATE '), POLICY_PRIVATE);
    });

    await t.test('falls back to the link-local default for unset or unknown values', () => {
        for (let value of [undefined, null, '', 'nonsense', 'true']) {
            assert.strictEqual(normalizePolicy(value), POLICY_LINK_LOCAL);
        }
    });
});

test('isBlockedAddress', async t => {
    await t.test('blocks cloud instance metadata under the default policy', () => {
        assert.strictEqual(isBlockedAddress('169.254.169.254', POLICY_LINK_LOCAL), true);
        // AWS serves IMDS over IPv6 from a unique-local address, which range checks alone miss
        assert.strictEqual(isBlockedAddress('fd00:ec2::254', POLICY_LINK_LOCAL), true);
    });

    await t.test('blocks IPv4-mapped IPv6 forms of a blocked address', () => {
        // Without unwrapping, this classifies as ordinary IPv6 unicast and sails through
        assert.strictEqual(isBlockedAddress('::ffff:169.254.169.254', POLICY_LINK_LOCAL), true);
    });

    await t.test('blocks IPv6 link-local under the default policy', () => {
        assert.strictEqual(isBlockedAddress('fe80::1', POLICY_LINK_LOCAL), true);
    });

    await t.test('allows ordinary public and private destinations under the default policy', () => {
        // Self-hosted EmailEngine commonly webhooks to a service on the same private network,
        // so the default policy must not break that
        for (let ip of ['93.184.216.34', '10.0.0.5', '192.168.1.20', '172.16.4.4', '127.0.0.1', '2606:2800:220:1:248:1893:25c8:1946']) {
            assert.strictEqual(isBlockedAddress(ip, POLICY_LINK_LOCAL), false, `expected ${ip} to be allowed`);
        }
    });

    await t.test('blocks the full set of internal ranges under the private policy', () => {
        for (let ip of ['10.0.0.5', '192.168.1.20', '172.16.4.4', '127.0.0.1', '169.254.169.254', '100.64.0.1', '::1', 'fc00::1', 'fe80::1', '0.0.0.0']) {
            assert.strictEqual(isBlockedAddress(ip, POLICY_PRIVATE), true, `expected ${ip} to be blocked`);
        }
    });

    await t.test('still allows public destinations under the private policy', () => {
        assert.strictEqual(isBlockedAddress('93.184.216.34', POLICY_PRIVATE), false);
        assert.strictEqual(isBlockedAddress('2606:2800:220:1:248:1893:25c8:1946', POLICY_PRIVATE), false);
    });

    await t.test('allows everything when the policy is off', () => {
        assert.strictEqual(isBlockedAddress('169.254.169.254', POLICY_OFF), false);
        assert.strictEqual(isBlockedAddress('not-an-ip', POLICY_OFF), false);
    });

    await t.test('fails closed on an address it cannot classify', () => {
        assert.strictEqual(isBlockedAddress('not-an-ip', POLICY_LINK_LOCAL), true);
        assert.strictEqual(isBlockedAddress('', POLICY_LINK_LOCAL), true);
    });
});

test('assertAllowedUrl', async t => {
    t.beforeEach(() => clearVerdictCache());

    await t.test('blocks a literal metadata address', async () => {
        await assertBlocked('http://169.254.169.254/latest/meta-data/', { policy: POLICY_LINK_LOCAL });
    });

    await t.test('blocks a bracketed IPv6 literal', async () => {
        await assertBlocked('http://[fe80::1]/hook', { policy: POLICY_LINK_LOCAL });
    });

    await t.test('blocks a hostname that resolves to a blocked address', async () => {
        // The DNS indirection that a literal-only check would miss
        await assertBlocked('https://metadata.example.com/hook', {
            policy: POLICY_LINK_LOCAL,
            resolve: resolvesTo('169.254.169.254')
        });
    });

    await t.test('blocks when any resolved address is blocked', async () => {
        // A name with a mix of records must not be allowed just because one record is fine
        await assertBlocked('https://mixed.example.com/hook', {
            policy: POLICY_LINK_LOCAL,
            resolve: resolvesTo('93.184.216.34', '169.254.169.254')
        });
    });

    await t.test('allows a hostname that resolves to a public address', async () => {
        await assertAllowedUrl('https://hooks.example.com/hook', {
            policy: POLICY_LINK_LOCAL,
            resolve: resolvesTo('93.184.216.34')
        });
    });

    await t.test('allows a private destination under the default policy but not under private', async () => {
        const opts = { policy: POLICY_LINK_LOCAL, resolve: resolvesTo('10.1.2.3') };
        await assertAllowedUrl('https://internal.example.com/hook', opts);
        await assertBlocked('https://internal.example.com/hook', { ...opts, policy: POLICY_PRIVATE });
    });

    await t.test('does not resolve or block anything when the policy is off', async () => {
        let resolveCalled = false;
        await assertAllowedUrl('http://169.254.169.254/latest/meta-data/', {
            policy: POLICY_OFF,
            resolve: async () => {
                resolveCalled = true;
                return [];
            }
        });
        assert.strictEqual(resolveCalled, false);
    });

    await t.test('rejects a malformed URL', async () => {
        await assertBlocked('not a url', { policy: POLICY_LINK_LOCAL });
    });

    await t.test('lets an unresolvable hostname through to the transport', async () => {
        // A name that does not resolve is a delivery problem, not a policy one. Blocking here
        // would turn every transient DNS blip into a permanent, non-retried webhook failure.
        await assertAllowedUrl('https://nx.example.com/hook', {
            policy: POLICY_LINK_LOCAL,
            resolve: async () => {
                let err = new Error('getaddrinfo ENOTFOUND');
                err.code = 'ENOTFOUND';
                throw err;
            }
        });
    });

    await t.test('defaults to the link-local policy when none is given', async () => {
        await assertBlocked('http://169.254.169.254/', {});
    });

    await t.test('names the policy setting in a rejection', async () => {
        // The message is what the admin UI shows and what the delivery log carries, and a refusal
        // that does not say what refused leaves the operator with nothing to look up
        const resolve = resolvesTo('169.254.169.254');

        for (let url of ['http://169.254.169.254/', 'https://metadata.example.com/hook']) {
            await assert.rejects(assertAllowedUrl(url, { policy: POLICY_LINK_LOCAL, resolve }), err => err.message.includes('EENGINE_WEBHOOK_EGRESS_POLICY'));
        }
    });
});

test('assertAllowedUrl verdict caching', async t => {
    t.beforeEach(() => clearVerdictCache());

    const countingResolver = (...addresses) => {
        let calls = 0;
        const resolve = async () => {
            calls++;
            return addresses.map(address => ({ address, family: address.includes(':') ? 6 : 4 }));
        };
        return { resolve, calls: () => calls };
    };

    await t.test('resolves a hostname once across repeated deliveries', async () => {
        // The notify worker runs at concurrency 1, so an uncached lookup is serialized ahead of
        // every single POST
        const { resolve, calls } = countingResolver('93.184.216.34');

        for (let i = 0; i < 5; i++) {
            await assertAllowedUrl('https://hooks.example.com/hook', { policy: POLICY_LINK_LOCAL, resolve });
        }

        assert.strictEqual(calls(), 1);
    });

    await t.test('keeps blocking a cached blocked host without re-resolving', async () => {
        const { resolve, calls } = countingResolver('169.254.169.254');

        await assertBlocked('https://metadata.example.com/hook', { policy: POLICY_LINK_LOCAL, resolve });
        await assertBlocked('https://metadata.example.com/hook', { policy: POLICY_LINK_LOCAL, resolve });

        assert.strictEqual(calls(), 1);
    });

    await t.test('keys the cache by policy, so a stricter policy is not served a stale allow', async () => {
        const { resolve } = countingResolver('10.1.2.3');

        await assertAllowedUrl('https://internal.example.com/hook', { policy: POLICY_LINK_LOCAL, resolve });
        await assertBlocked('https://internal.example.com/hook', { policy: POLICY_PRIVATE, resolve });
    });

    await t.test('does not cache a resolver failure', async () => {
        // A resolver blip must not pin an allow verdict for the whole TTL
        let calls = 0;
        const resolve = async () => {
            calls++;
            throw Object.assign(new Error('getaddrinfo EAI_AGAIN'), { code: 'EAI_AGAIN' });
        };

        await assertAllowedUrl('https://flaky.example.com/hook', { policy: POLICY_LINK_LOCAL, resolve });
        await assertAllowedUrl('https://flaky.example.com/hook', { policy: POLICY_LINK_LOCAL, resolve });

        assert.strictEqual(calls, 2);
    });

    await t.test('never consults the cache for an IP literal', async () => {
        let calls = 0;
        const resolve = async () => {
            calls++;
            return [];
        };

        await assertBlocked('http://169.254.169.254/', { policy: POLICY_LINK_LOCAL, resolve });
        assert.strictEqual(calls, 0, 'a literal needs no resolution');
    });
});
