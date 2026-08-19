'use strict';

// Shared webhook routing rules. The notify pipeline (lib/webhooks.js, workers/webhooks.js)
// and the admin account page's routing card resolve targets and gates through the helpers
// here, so the debug view cannot drift from what the worker actually does.

// Precedence: custom route target, then the per-account webhooks override, then the global
// webhooks setting. Returns the winning URL and which configuration level provided it.
function resolveTargetUrl(customRouteTargetUrl, accountWebhooks, globalWebhooks) {
    if (customRouteTargetUrl) {
        return { url: customRouteTargetUrl, source: 'route' };
    }
    if (accountWebhooks) {
        return { url: accountWebhooks, source: 'account' };
    }
    if (globalWebhooks) {
        return { url: globalWebhooks, source: 'global' };
    }
    return { url: null, source: null };
}

// A custom route can only deliver when it is enabled and has a target URL
function isDeliverableRoute(route) {
    return !!(route && route.enabled && route.targetUrl);
}

// The webhookEvents allowlist applies to the default route only; '*' allows everything
function eventAllowed(webhookEvents, eventName) {
    let events = [].concat(webhookEvents || []);
    return events.includes('*') || events.includes(eventName);
}

// Assembles a render-ready description of the webhook routing that applies to one account.
// All inputs are pre-fetched values; this function does not touch Redis or settings.
function describeEffectiveRouting(opts) {
    opts = opts || {};

    let events = [].concat(opts.webhookEvents || []);
    let allEvents = events.includes('*');

    let { url, source } = resolveTargetUrl(null, opts.accountWebhooks, opts.globalWebhooks);

    let globalHeaders = [].concat(opts.globalCustomHeaders || []).length;
    let accountHeaders = [].concat(opts.accountCustomHeaders || []).length;

    let customHeadersLabel = null;
    if (globalHeaders && accountHeaders) {
        customHeadersLabel = `${globalHeaders} global, ${accountHeaders} account-specific`;
    } else if (globalHeaders) {
        customHeadersLabel = `${globalHeaders} global`;
    } else if (accountHeaders) {
        customHeadersLabel = `${accountHeaders} account-specific`;
    }

    return {
        enabled: !!opts.webhooksEnabled,

        defaultRoute: {
            url,
            source,
            events: allEvents ? [] : events,
            allEvents,
            inboxNewOnly: !!opts.inboxNewOnly,
            customHeadersLabel
        },

        // Enabled custom routes deliver independently of the default route, each gated by its
        // own filter function instead of the webhookEvents allowlist. The worker requires that
        // filter to exist (lib/webhooks.js pushToQueue skips a route without a compiled
        // function), so a route whose `hasFilter` marker is false is flagged rather than
        // presented as delivering - it never fires anything.
        customRoutes: []
            .concat(opts.routes || [])
            .filter(isDeliverableRoute)
            .map(route => ({
                id: route.id,
                name: route.name,
                targetUrl: route.targetUrl,
                missingFilter: route.hasFilter === false
            }))
    };
}

module.exports = { resolveTargetUrl, isDeliverableRoute, eventAllowed, describeEffectiveRouting };
