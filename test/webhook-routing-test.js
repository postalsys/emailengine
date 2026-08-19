'use strict';

const test = require('node:test');
const assert = require('node:assert').strict;

const { resolveTargetUrl, isDeliverableRoute, eventAllowed, describeEffectiveRouting } = require('../lib/webhook-routing');

test('Webhook routing tests', async t => {
    await t.test('resolveTargetUrl() prefers the custom route target', async () => {
        assert.deepStrictEqual(resolveTargetUrl('https://route.example.com', 'https://account.example.com', 'https://global.example.com'), {
            url: 'https://route.example.com',
            source: 'route'
        });
    });

    await t.test('resolveTargetUrl() falls back to the account override', async () => {
        assert.deepStrictEqual(resolveTargetUrl(null, 'https://account.example.com', 'https://global.example.com'), {
            url: 'https://account.example.com',
            source: 'account'
        });
        assert.deepStrictEqual(resolveTargetUrl(false, 'https://account.example.com', null), {
            url: 'https://account.example.com',
            source: 'account'
        });
    });

    await t.test('resolveTargetUrl() falls back to the global setting', async () => {
        assert.deepStrictEqual(resolveTargetUrl(null, null, 'https://global.example.com'), {
            url: 'https://global.example.com',
            source: 'global'
        });
        // an empty account value must not shadow the global URL
        assert.deepStrictEqual(resolveTargetUrl(null, '', 'https://global.example.com'), {
            url: 'https://global.example.com',
            source: 'global'
        });
    });

    await t.test('resolveTargetUrl() returns nulls when nothing is configured', async () => {
        assert.deepStrictEqual(resolveTargetUrl(null, null, null), { url: null, source: null });
        assert.deepStrictEqual(resolveTargetUrl(undefined, '', undefined), { url: null, source: null });
    });

    await t.test('isDeliverableRoute() requires an enabled route with a target', async () => {
        assert.equal(isDeliverableRoute({ enabled: true, targetUrl: 'https://r.example.com' }), true);
        assert.equal(isDeliverableRoute({ enabled: false, targetUrl: 'https://r.example.com' }), false);
        assert.equal(isDeliverableRoute({ enabled: true }), false);
        assert.equal(isDeliverableRoute(null), false);
    });

    await t.test('eventAllowed() honors the wildcard and explicit entries', async () => {
        assert.equal(eventAllowed(['*'], 'messageNew'), true);
        assert.equal(eventAllowed(['messageNew'], 'messageNew'), true);
        assert.equal(eventAllowed(['messageNew'], 'messageBounce'), false);
        // no selection at all means nothing is delivered on the default route
        assert.equal(eventAllowed([], 'messageNew'), false);
        assert.equal(eventAllowed(null, 'messageNew'), false);
    });

    await t.test('describeEffectiveRouting() labels the target source', async () => {
        let described = describeEffectiveRouting({
            webhooksEnabled: true,
            globalWebhooks: 'https://global.example.com',
            accountWebhooks: 'https://account.example.com'
        });
        assert.strictEqual(described.enabled, true);
        assert.strictEqual(described.defaultRoute.url, 'https://account.example.com');
        assert.strictEqual(described.defaultRoute.source, 'account');

        described = describeEffectiveRouting({
            webhooksEnabled: true,
            globalWebhooks: 'https://global.example.com'
        });
        assert.strictEqual(described.defaultRoute.url, 'https://global.example.com');
        assert.strictEqual(described.defaultRoute.source, 'global');

        described = describeEffectiveRouting({ webhooksEnabled: false });
        assert.strictEqual(described.enabled, false);
        assert.strictEqual(described.defaultRoute.url, null);
        assert.strictEqual(described.defaultRoute.source, null);
    });

    await t.test('describeEffectiveRouting() reports the event allowlist', async () => {
        let described = describeEffectiveRouting({ webhookEvents: ['*'] });
        assert.strictEqual(described.defaultRoute.allEvents, true);
        assert.deepStrictEqual(described.defaultRoute.events, []);

        described = describeEffectiveRouting({ webhookEvents: ['messageNew', 'messageBounce'] });
        assert.strictEqual(described.defaultRoute.allEvents, false);
        assert.deepStrictEqual(described.defaultRoute.events, ['messageNew', 'messageBounce']);

        // no selection at all means the default route delivers nothing
        described = describeEffectiveRouting({});
        assert.strictEqual(described.defaultRoute.allEvents, false);
        assert.deepStrictEqual(described.defaultRoute.events, []);
        assert.strictEqual(described.defaultRoute.inboxNewOnly, false);
    });

    await t.test('describeEffectiveRouting() summarizes custom headers per level', async () => {
        let described = describeEffectiveRouting({
            globalCustomHeaders: [{ key: 'X-One', value: '1' }],
            accountCustomHeaders: [
                { key: 'X-Two', value: '2' },
                { key: 'X-Three', value: '3' }
            ]
        });
        assert.strictEqual(described.defaultRoute.customHeadersLabel, '1 global, 2 account-specific');

        described = describeEffectiveRouting({ globalCustomHeaders: [{ key: 'X-One', value: '1' }] });
        assert.strictEqual(described.defaultRoute.customHeadersLabel, '1 global');

        described = describeEffectiveRouting({ accountCustomHeaders: [{ key: 'X-Two', value: '2' }] });
        assert.strictEqual(described.defaultRoute.customHeadersLabel, '1 account-specific');

        described = describeEffectiveRouting({});
        assert.strictEqual(described.defaultRoute.customHeadersLabel, null);
    });

    await t.test('describeEffectiveRouting() lists only usable custom routes', async () => {
        let described = describeEffectiveRouting({
            routes: [
                { id: 'r1', name: 'Enabled', targetUrl: 'https://r1.example.com', enabled: true, tcount: 7 },
                { id: 'r2', name: 'Disabled', targetUrl: 'https://r2.example.com', enabled: false },
                { id: 'r3', name: 'No target', enabled: true },
                null
            ]
        });
        assert.deepStrictEqual(described.customRoutes, [{ id: 'r1', name: 'Enabled', targetUrl: 'https://r1.example.com', missingFilter: false }]);
    });

    await t.test('describeEffectiveRouting() flags an enabled route that has no filter function', async () => {
        // The worker's delivery gate (lib/webhooks.js pushToQueue) also requires a compiled
        // filter function, so an enabled route without one never fires - the card must not
        // present it as delivering.
        let described = describeEffectiveRouting({
            routes: [
                { id: 'r1', name: 'With filter', targetUrl: 'https://r1.example.com', enabled: true, hasFilter: true },
                { id: 'r2', name: 'No filter', targetUrl: 'https://r2.example.com', enabled: true, hasFilter: false },
                // no marker at all (the caller did not probe this route) must not raise the flag
                { id: 'r3', name: 'Unknown', targetUrl: 'https://r3.example.com', enabled: true }
            ]
        });

        assert.deepStrictEqual(
            described.customRoutes.map(route => ({ id: route.id, missingFilter: route.missingFilter })),
            [
                { id: 'r1', missingFilter: false },
                { id: 'r2', missingFilter: true },
                { id: 'r3', missingFilter: false }
            ]
        );
    });
});
