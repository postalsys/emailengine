'use strict';

// Admin UI routes for the dashboard and standalone informational pages: the main
// /admin dashboard (stats counters), the Swagger API reference, the legal page, and the
// upgrade page. Extracted verbatim from lib/routes-ui.js.

const { getStats, getBoolean, readEnvValue } = require('../tools');
const settings = require('../settings');
const { redis } = require('../db');
const { ALLOWED_REDIS_LATENCY } = require('../consts');

function init(args) {
    const { server, call } = args;

    server.route({
        method: 'GET',
        path: '/admin',
        async handler(request, h) {
            let stats = await getStats(redis, call, request.query.seconds || 24 * 3600);

            let counterList = [
                {
                    key: 'events:messageNew',
                    title: 'New emails',
                    color: 'primary',
                    icon: 'envelope',
                    comment: 'Detected new emails in IMAP mailboxes.'
                },
                {
                    key: 'webhooks:success',
                    title: 'Webhooks sent',
                    color: 'primary',
                    icon: 'network-wired',
                    comment: 'Count of successfully delivered webhooks.'
                },
                {
                    key: 'webhooks:fail',
                    title: 'Webhooks failed',
                    color: 'danger',
                    icon: 'network-wired',
                    comment: 'Count of webhooks that failed to deliver.'
                },
                {
                    key: 'submit:success',
                    title: 'Emails sent',
                    color: 'primary',
                    icon: 'mail-bulk',
                    comment: 'Count of emails sent to MTA servers.'
                },
                {
                    key: 'submit:fail',
                    title: 'Emails rejected',
                    color: 'danger',
                    icon: 'mail-bulk',
                    comment: 'Count of emails rejected by MTA servers.'
                },
                {
                    key: 'apiCall:success',
                    title: 'Successful API calls',
                    color: 'primary',
                    icon: 'file-code',
                    comment: 'Successful API calls with positive responses.'
                },
                {
                    key: 'apiCall:fail',
                    title: 'Failed API calls',
                    color: 'danger',
                    icon: 'file-code',
                    comment: 'API calls that returned error responses.'
                }
            ];

            for (let counter of counterList) {
                counter.value = stats.counters[counter.key] || 0;
            }

            let hasAccounts = !!stats.accounts;
            stats.connectedAccounts = (stats.connections.connected || 0) + (stats.connections.syncing || 0);

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
                    counterList,
                    hasAccounts,

                    redisWarnings: stats.redisWarnings || [],

                    redisPing: {
                        key: 'redisPing',
                        title: 'Redis Latency',
                        color: typeof stats.redisPing !== 'number' ? 'warning' : stats.redisPing < ALLOWED_REDIS_LATENCY ? 'success' : 'danger',
                        icon: 'clock',
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
