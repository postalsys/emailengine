'use strict';

// Admin UI routes for the dashboard and standalone informational pages: the main
// /admin dashboard (stats counters), the Swagger API reference, the legal page, and the
// upgrade page. Extracted verbatim from lib/routes-ui.js.

const { getStats, getBoolean, readEnvValue } = require('../tools');
const settings = require('../settings');
const { redis } = require('../db');
const { ALLOWED_REDIS_LATENCY } = require('../consts');
const { ACCOUNT_STATE_DISPLAY } = require('./route-helpers');
const { ERROR_STATES } = require('../account/account-state');

function init(args) {
    const { server, call } = args;

    // Time windows selectable for the Activity counters. Counter buckets are retained for
    // MAX_DAYS_STATS + 1 (8) days, so 7d is the longest window guaranteed to have full data.
    const ACTIVITY_WINDOWS = [
        { seconds: 3600, label: '1h' },
        { seconds: 24 * 3600, label: '24h', default: true },
        { seconds: 7 * 24 * 3600, label: '7d' }
    ].map(entry => Object.assign(entry, { url: entry.default ? '/admin' : `/admin?seconds=${entry.seconds}` }));

    // Account states surfaced as filter chips under the Accounts cards, from the
    // shared display table; connected is covered by its own card
    const CHIP_STATES = ACCOUNT_STATE_DISPLAY.filter(entry => entry.state !== 'connected');

    server.route({
        method: 'GET',
        path: '/admin',
        async handler(request, h) {
            // Snap to the window whitelist: this is the only interface the UI offers, and
            // it keeps arbitrary ?seconds= values from selecting an unbounded scan window
            let selectedWindow =
                ACTIVITY_WINDOWS.find(entry => entry.seconds === Number(request.query.seconds)) || ACTIVITY_WINDOWS.find(entry => entry.default);

            let stats = await getStats(redis, call, selectedWindow.seconds);

            let hasAccounts = !!stats.accounts;
            stats.connectedAccounts = (stats.connections.connected || 0) + (stats.connections.syncing || 0);

            // the same error-state list backs the accounts page's virtual 'errors' filter
            // that the "Needs attention" card links to, so count and link cannot diverge
            let attentionCount = ERROR_STATES.reduce((sum, state) => sum + (stats.connections[state] || 0), 0);

            let stateChips = CHIP_STATES.map(entry => Object.assign({ count: stats.connections[entry.state] || 0 }, entry)).filter(entry => entry.count > 0);

            let activity = {
                messageNew: stats.counters['events:messageNew'] || 0,
                submitSuccess: stats.counters['submit:success'] || 0,
                submitFail: stats.counters['submit:fail'] || 0,
                webhooksSuccess: stats.counters['webhooks:success'] || 0,
                webhooksFail: stats.counters['webhooks:fail'] || 0,
                apiSuccess: stats.counters['apiCall:success'] || 0,
                apiFail: stats.counters['apiCall:fail'] || 0
            };

            let activityWindows = ACTIVITY_WINDOWS.map(entry => ({
                label: entry.label,
                url: entry.url,
                active: entry === selectedWindow
            }));

            let defaultLocale = (await settings.get('locale')) || 'en';

            let nrFormatter;

            let nrFormatterOpts = {
                style: 'decimal'
            };

            try {
                nrFormatter = new Intl.NumberFormat(defaultLocale, nrFormatterOpts);
            } catch (err) {
                nrFormatter = new Intl.NumberFormat('en-US', nrFormatterOpts);
            }

            return h.view(
                'dashboard',
                {
                    pageTitle: 'Dashboard',
                    menuDashboard: true,
                    stats,
                    hasAccounts,

                    attentionCount,
                    stateChips,
                    activity,
                    activityWindows,

                    redisWarnings: stats.redisWarnings || [],

                    redisPing: {
                        key: 'redisPing',
                        title: 'Redis Latency',
                        color: typeof stats.redisPing !== 'number' ? 'warning' : stats.redisPing < ALLOWED_REDIS_LATENCY ? 'success' : 'danger',
                        icon: 'icon-[tabler--clock]',
                        comment: 'How many milliseconds does it take to run a Redis command',
                        value: typeof stats.redisPing !== 'number' ? '\u2013' : nrFormatter.format(stats.redisPing / 1000000)
                    }
                },
                {
                    layout: 'app'
                }
            );
        }
    });

    server.route({
        method: 'GET',
        path: '/admin/swagger',
        async handler(request, h) {
            return h.view(
                'swagger/index',
                {
                    pageTitle: 'API Reference',
                    menuSwagger: true,
                    injectHtmlHead: `<link rel="stylesheet" type="text/css" href="/admin/swagger/resources/swagger-ui.css" />
<style>
    .download-url-wrapper,
    .topbar {
        display: none !important;
    }
</style>`
                },
                {
                    layout: 'app'
                }
            );
        }
    });

    server.route({
        method: 'GET',
        path: '/admin/legal',
        async handler(request, h) {
            return h.view(
                'legal',
                {
                    pageTitle: 'Legal',
                    menuLegal: true
                },
                {
                    layout: 'app'
                }
            );
        }
    });

    server.route({
        method: 'GET',
        path: '/admin/upgrade',
        async handler(request, h) {
            const isDO = getBoolean(readEnvValue('EENGINE_DOCEAN'));
            const isScriptInstalled = getBoolean(readEnvValue('EENGINE_INSTALL_SCRIPT'));
            const isRender = typeof readEnvValue('RENDER_SERVICE_SLUG') === 'string' && readEnvValue('RENDER_SERVICE_SLUG');
            const isGeneral = !isDO && !isRender && !isScriptInstalled;

            return h.view(
                'upgrade',
                {
                    pageTitle: 'Upgrade',
                    isDO,
                    isRender,
                    isScriptInstalled,
                    isGeneral
                },
                {
                    layout: 'app'
                }
            );
        }
    });
}

module.exports = init;
