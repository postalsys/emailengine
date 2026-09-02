'use strict';

// Unit tests for lib/egress-filter.js. The module is pure apart from an optional DNS lookup, which
// is injected here, so this suite needs no Redis and no outbound network. The last block does open
// a loopback socket, deliberately: the point of createEgressLookup() is which address gets
// connected to, and only a real connection can show that.

const test = require('node:test');
const assert = require('node:assert').strict;
const { Agent, fetch: fetchCmd } = require('undici');
const { withCapturingServer } = require('./helpers/capture-http-server');

const {
    assertAllowedUrl,
    createEgressLookup,
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

    await t.test('blocks IPv6 transition forms that embed a blocked address', () => {
        // NAT64 well-known and local-use prefixes, IPv4-translated, 6to4, and Teredo (where the
        // client address is stored bit-inverted: a9fe -> 5601)
        for (let ip of [
            '64:ff9b::169.254.169.254',
            '64:ff9b::a9fe:a9fe',
            '64:ff9b:1::a9fe:a9fe',
            '::ffff:0:169.254.169.254',
            '2002:a9fe:a9fe::1',
            '2001:0:4136:e378:8000:63bf:5601:5601'
        ]) {
            assert.strictEqual(isBlockedAddress(ip, POLICY_LINK_LOCAL), true, `expected ${ip} to be blocked`);
        }
    });

    await t.test('allows transition forms that embed a public address', () => {
        // A NAT64-only host resolves every IPv4-only receiver into 64:ff9b::/96, so the range as
        // such must stay reachable; only the embedded address is judged
        for (let ip of ['64:ff9b::5db8:d822', '2002:5db8:d822::1']) {
            assert.strictEqual(isBlockedAddress(ip, POLICY_LINK_LOCAL), false, `expected ${ip} to be allowed`);
            assert.strictEqual(isBlockedAddress(ip, POLICY_PRIVATE), false, `expected ${ip} to be allowed`);
        }
    });

    await t.test('judges the embedded address under the private policy too', () => {
        assert.strictEqual(isBlockedAddress('64:ff9b::10.0.0.1', POLICY_PRIVATE), true);
        assert.strictEqual(isBlockedAddress('64:ff9b::10.0.0.1', POLICY_LINK_LOCAL), false);
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

test('createEgressLookup', async t => {
    // Promisified, since the lookup speaks the callback shape net.connect expects
    const lookup = (fn, hostname, options = {}) =>
        new Promise((resolve, reject) => {
            fn(hostname, options, (err, ...result) => (err ? reject(err) : resolve(result)));
        });

    await t.test('passes through a public address', async () => {
        const fn = createEgressLookup(POLICY_LINK_LOCAL, { resolve: resolvesTo('93.184.216.34') });
        assert.deepStrictEqual(await lookup(fn, 'hooks.example.com'), ['93.184.216.34', 4]);
    });

    await t.test('blocks an address the policy refuses', async () => {
        const fn = createEgressLookup(POLICY_LINK_LOCAL, { resolve: resolvesTo('169.254.169.254') });
        await assert.rejects(lookup(fn, 'metadata.example.com'), err => err.code === 'EEGRESSBLOCKED');
    });

    await t.test('blocks when any resolved address is blocked', async () => {
        // Connecting to the permitted half of a mixed answer would still be reaching a name that
        // is trying to hand us an internal address
        const fn = createEgressLookup(POLICY_PRIVATE, { resolve: resolvesTo('93.184.216.34', '10.0.0.5') });
        await assert.rejects(lookup(fn, 'mixed.example.com'), err => err.code === 'EEGRESSBLOCKED');
    });

    await t.test('applies the policy it was built with', async () => {
        const resolve = resolvesTo('10.1.2.3');
        assert.deepStrictEqual(await lookup(createEgressLookup(POLICY_LINK_LOCAL, { resolve }), 'internal.example.com'), ['10.1.2.3', 4]);
        await assert.rejects(lookup(createEgressLookup(POLICY_PRIVATE, { resolve }), 'internal.example.com'), err => err.code === 'EEGRESSBLOCKED');
    });

    await t.test('returns the full list when `all` is requested', async () => {
        // autoSelectFamily (Happy Eyeballs) asks for `all`; handing it a bare string breaks connect
        const fn = createEgressLookup(POLICY_LINK_LOCAL, { resolve: resolvesTo('93.184.216.34', '2606:2800:220:1::1') });
        const [addresses] = await lookup(fn, 'hooks.example.com', { all: true });

        assert.deepStrictEqual(addresses, [
            { address: '93.184.216.34', family: 4 },
            { address: '2606:2800:220:1::1', family: 6 }
        ]);
    });

    await t.test('surfaces a resolver failure as the transport error', async () => {
        const fn = createEgressLookup(POLICY_LINK_LOCAL, {
            resolve: async () => {
                throw Object.assign(new Error('getaddrinfo ENOTFOUND'), { code: 'ENOTFOUND' });
            }
        });
        await assert.rejects(lookup(fn, 'nx.example.com'), err => err.code === 'ENOTFOUND');
    });

    await t.test('refuses an empty answer rather than connecting to nothing', async () => {
        const fn = createEgressLookup(POLICY_LINK_LOCAL, { resolve: async () => [] });
        await assert.rejects(lookup(fn, 'empty.example.com'), err => err.code === 'ENOTFOUND');
    });

    await t.test('stops a DNS rebind that the pre-check already allowed', async () => {
        // The reported bypass, end to end: assertAllowedUrl() resolves the name and sees a public
        // address, then the connect resolves it again and gets an internal one. The pre-check has
        // to allow here (that is the premise), so the delivery is only stopped if the lookup the
        // socket uses applies the policy itself.
        await withCapturingServer(null, async ({ baseUrl, getCaptured }) => {
            // The rebinding nameserver: public on the first query, loopback on every one after
            let queries = 0;
            const rebind = async () => [{ address: ++queries === 1 ? '93.184.216.34' : '127.0.0.1', family: 4 }];

            const url = `http://rebind.example.com:${new URL(baseUrl).port}/hook`;
            const dispatcher = new Agent({ connect: { lookup: createEgressLookup(POLICY_PRIVATE, { resolve: rebind }) } });

            try {
                clearVerdictCache();
                await assertAllowedUrl(url, { policy: POLICY_PRIVATE, resolve: rebind });
                assert.strictEqual(queries, 1, 'the pre-check must have been the one that saw the public address');

                await assert.rejects(fetchCmd(url, { method: 'post', body: '{}', dispatcher }), err => (err.cause || err).code === 'EEGRESSBLOCKED');
                assert.strictEqual(getCaptured(), null, 'the internal service must not have been reached');
            } finally {
                await dispatcher.close();
            }
        });
    });
});
