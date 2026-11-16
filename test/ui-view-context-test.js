'use strict';

// lib/ui-view-context.js: the view context every rendered page receives, moved out of
// workers/api.js (which a test cannot load). The settings and OAuth2 app reads are stood in on the
// shared module objects; nothing here touches Redis except a flash lookup without a crumb, which
// returns before it does.

const test = require('node:test');
const assert = require('node:assert').strict;

const settings = require('../lib/settings');
const logger = require('../lib/logger');
const { oauth2Apps } = require('../lib/oauth2-apps');
const { redis } = require('../lib/db');
const { LAST_DOCUMENT_STORE_VERSION } = require('../lib/consts');
const registerRedisTeardown = require('./helpers/redis-teardown');
const { buildViewContext, buildSystemAlerts, resolveAuthDisplay, licenseDetailsView, CONTEXT_SETTINGS } = require('../lib/ui-view-context');

registerRedisTeardown(redis);

const DAY = 24 * 3600 * 1000;
const NOW = Date.parse('2026-11-16T12:00:00.000Z');

function stub(t, target, methods) {
    const original = {};
    for (const [name, fn] of Object.entries(methods)) {
        original[name] = target[name];
        target[name] = fn;
    }
    t.after(() => Object.assign(target, original));
}

const alertState = overrides =>
    Object.assign(
        {
            settingsValues: {},
            licenseInfo: { active: true, details: {} },
            licenseDetails: {},
            oauthAuthFlags: [],
            disableSetupWarnings: false
        },
        overrides
    );

test('buildSystemAlerts', async t => {
    await t.test('a licensed, healthy instance shows nothing', () => {
        assert.deepEqual(buildSystemAlerts(alertState()), []);
    });

    await t.test('every alert, in display order', () => {
        const alerts = buildSystemAlerts(
            alertState({
                settingsValues: {
                    upgrade: { canUpgrade: true, available: '9.9.9' },
                    webhooksEnabled: true,
                    webhookErrorFlag: { message: 'failed' },
                    disableTokens: true,
                    documentStoreEnabled: true
                },
                licenseInfo: { active: true, details: { expires: 'x' }, subscription: { days: 1 } },
                licenseDetails: { expires: 'x', expiresDays: 1, trial: true },
                oauthAuthFlags: [
                    { app: 'a b', authFlag: { message: 'Refused' } },
                    { app: 'c', authFlag: { message: 'Also refused', url: '/admin/custom' } }
                ]
            })
        );
        assert.deepEqual(alerts, [
            { url: '/admin/upgrade', level: 'info', icon: 'icon-[tabler--alert-triangle]', message: 'An update is available: Emailengine v9.9.9' },
            {
                url: '/admin/config/license',
                level: 'danger',
                icon: 'icon-[tabler--alert-triangle]',
                message: 'Subscription payment overdue: EmailEngine pauses in 1 day unless it is paid'
            },
            { url: '/admin/config/oauth/app/a%20b', level: 'danger', icon: 'icon-[tabler--lock-open]', message: 'Refused' },
            { url: '/admin/custom', level: 'danger', icon: 'icon-[tabler--lock-open]', message: 'Also refused' },
            { url: '/admin/config/webhooks', level: 'danger', icon: 'icon-[tabler--link]', message: 'Webhook delivery is failing' },
            { url: '/admin/config/license', level: 'warning', icon: 'icon-[tabler--key]', message: 'Your trial license key will expire in 1 day' },
            { url: '/admin/config/security', level: 'warning', icon: 'icon-[tabler--key]', message: 'Access tokens are disabled for API requests' },
            {
                url: '/admin',
                level: 'danger',
                icon: 'icon-[tabler--database]',
                message: `The Document Store has been removed from EmailEngine. Downgrade to v${LAST_DOCUMENT_STORE_VERSION} if you still need it.`
            }
        ]);
    });

    await t.test('setup warnings can be suppressed, danger alerts stay', () => {
        const alerts = buildSystemAlerts(
            alertState({
                settingsValues: {
                    upgrade: { canUpgrade: true, available: '1' },
                    disableTokens: true,
                    webhooksEnabled: true,
                    webhookErrorFlag: { message: 'x' }
                },
                licenseInfo: null,
                disableSetupWarnings: true
            })
        );
        assert.deepEqual(
            alerts.map(alert => alert.message),
            ['Webhook delivery is failing']
        );
    });

    await t.test('a suspended subscription replaces the overdue notice', () => {
        const alerts = buildSystemAlerts(alertState({ licenseInfo: { active: false, details: {}, subscription: { status: 'suspended', days: 3 } } }));
        assert.deepEqual(
            alerts.map(alert => alert.message),
            ['EmailEngine is paused: the subscription behind the license key is not in good standing']
        );
    });

    await t.test('the overdue notice counts days in the plural', () => {
        const [alert] = buildSystemAlerts(alertState({ licenseInfo: { active: true, details: {}, subscription: { days: 3 } } }));
        assert.equal(alert.message, 'Subscription payment overdue: EmailEngine pauses in 3 days unless it is paid');
    });

    await t.test('no license key, but not for a registered key that is paused', () => {
        for (const licenseInfo of [null, undefined, { active: false }]) {
            assert.deepEqual(
                buildSystemAlerts(alertState({ licenseInfo })).map(alert => alert.message),
                ['No license key registered']
            );
        }
        assert.deepEqual(buildSystemAlerts(alertState({ licenseInfo: { active: false, details: { key: 'k' } } })), []);
    });

    await t.test('the expiry warning starts 30 days out', () => {
        const expiring = days => buildSystemAlerts(alertState({ licenseDetails: { expires: 'x', expiresDays: days } }));
        assert.equal(expiring(31).length, 0);
        assert.equal(expiring(30)[0].message, 'Your license key will expire in 30 days');
        assert.equal(expiring(0)[0].message, 'Your license key will expire in 0 days');
    });

    await t.test('a webhook error is only shown while webhooks are enabled and the flag has a message', () => {
        assert.deepEqual(buildSystemAlerts(alertState({ settingsValues: { webhooksEnabled: false, webhookErrorFlag: { message: 'x' } } })), []);
        assert.deepEqual(buildSystemAlerts(alertState({ settingsValues: { webhooksEnabled: true, webhookErrorFlag: {} } })), []);
    });
});

test('licenseDetailsView', async t => {
    await t.test('copies the details and counts whole days left, never below 0', () => {
        const details = { expires: new Date(NOW + 10 * DAY - 1000).toISOString(), trial: true };
        const view = licenseDetailsView({ details }, NOW);
        assert.deepEqual(view, Object.assign({}, details, { expiresDays: 10 }));
        assert.notEqual(view, details);
        assert.equal(details.expiresDays, undefined, 'the license record itself is not modified');

        assert.equal(licenseDetailsView({ details: { expires: new Date(NOW - DAY).toISOString() } }, NOW).expiresDays, 0);
    });

    await t.test('no details, no expiry', () => {
        assert.deepEqual(licenseDetailsView(undefined, NOW), {});
        assert.deepEqual(licenseDetailsView({ details: { lt: true } }, NOW), { lt: true });
    });
});

test('resolveAuthDisplay', async t => {
    await t.test('an Okta session shows the profile name', async () => {
        assert.deepEqual(await resolveAuthDisplay({ provider: 'okta', profile: { username: 'u', firstName: 'Ann', lastName: 'Lee' } }), {
            user: 'u',
            name: 'Ann Lee',
            enabled: true,
            isAdmin: false
        });
        assert.deepEqual(await resolveAuthDisplay({ provider: 'okta' }), { user: undefined, name: undefined, enabled: false, isAdmin: false });
    });

    await t.test('an OIDC session shows the display name, else the user name', async () => {
        assert.equal((await resolveAuthDisplay({ provider: 'oidc', profile: { username: 'u', displayName: 'Dee' } })).name, 'Dee');
        assert.equal((await resolveAuthDisplay({ provider: 'oidc', profile: { username: 'u' } })).name, 'u');
    });

    await t.test('anything else is the local admin, or a placeholder without a password', async t => {
        stub(t, settings, { get: async key => (key === 'authData' ? { user: 'boss', password: 'hash' } : undefined) });
        assert.deepEqual(await resolveAuthDisplay(undefined), { user: 'boss', password: 'hash', name: 'boss', enabled: true, isAdmin: true });
        assert.equal((await resolveAuthDisplay({ provider: 'constructor' })).name, 'boss');

        stub(t, settings, { get: async () => null });
        assert.deepEqual(await resolveAuthDisplay({}), { name: 'admin', user: 'admin', enabled: false, isAdmin: true });
    });
});

test('buildViewContext', async t => {
    const request = overrides =>
        Object.assign(
            {
                auth: { isAuthenticated: false },
                app: { cspNonce: 'nonce-1', locale: 'de', licenseInfo: { active: true, details: {} } },
                state: {}
            },
            overrides
        );

    await t.test('reads its settings in one call and builds every key', async t => {
        const reads = [];
        stub(t, settings, {
            async getMulti(...keys) {
                reads.push(keys);
                return {
                    tract: 1,
                    serviceUrl: 'https://ee.example.com',
                    language: 'en',
                    timezone: 'UTC',
                    locale: 'et',
                    pageBrandName: 'Brand',
                    notificationBaseUrl: 'https://n.example.com',
                    templateHeader: '<b>h</b>',
                    templateHtmlHead: '<meta>'
                };
            },
            get: async () => null
        });
        stub(t, oauth2Apps, { listAuthFlags: async () => [] });

        const context = await buildViewContext(request({ payload: { a: 1 }, error: { details: { f: 'e' } } }));
        assert.deepEqual(reads, [CONTEXT_SETTINGS]);
        assert.deepEqual(Object.keys(context), [
            'cspNonce',
            'pageBrandName',
            'values',
            'errors',
            'pendingMessages',
            'licenseInfo',
            'licenseDetails',
            'trialPossible',
            'authData',
            'isAuthenticated',
            'showDashboardLink',
            'packageData',
            'systemAlerts',
            'embeddedTemplateHeader',
            'embeddedTemplateHtmlHead',
            'currentYear',
            'documentStoreRemoved',
            'lastDocumentStoreVersion',
            'updateBrowserInfo',
            'hideLicenseWarning',
            'disableAuthWarning',
            'mainServiceUrl',
            'notificationBaseUrl',
            'userLocale',
            'userTimezone',
            'templateLocale'
        ]);
        assert.equal(context.cspNonce, 'nonce-1');
        assert.equal(context.pageBrandName, 'Brand');
        assert.deepEqual(context.values, { a: 1 });
        assert.deepEqual(context.errors, { f: 'e' });
        assert.equal(context.trialPossible, false);
        assert.equal(context.showDashboardLink, true, 'no admin login, so the dashboard is linked');
        assert.equal(context.embeddedTemplateHeader, '<b>h</b>');
        assert.equal(context.updateBrowserInfo, false);
        assert.equal(context.mainServiceUrl, 'https://ee.example.com');
        assert.equal(context.userLocale, 'et');
        assert.equal(context.userTimezone, 'UTC');
        assert.equal(context.templateLocale, 'de');
        assert.equal(context.lastDocumentStoreVersion, LAST_DOCUMENT_STORE_VERSION);
    });

    await t.test('defaults for an unconfigured instance', async t => {
        stub(t, settings, { getMulti: async () => ({}), get: async () => ({ user: 'admin', password: 'x' }) });
        stub(t, oauth2Apps, { listAuthFlags: async () => [] });

        const context = await buildViewContext(request());
        assert.equal(context.pageBrandName, 'EmailEngine');
        assert.deepEqual(context.values, {});
        assert.deepEqual(context.errors, {});
        assert.equal(context.trialPossible, true);
        assert.equal(context.updateBrowserInfo, true);
        assert.equal(context.showDashboardLink, false, 'an admin login exists and the requester has no session');
        assert.equal(context.isAuthenticated, false);
    });

    await t.test('a failure to read the OAuth2 auth flags does not take the page down', async t => {
        const errors = [];
        stub(t, settings, { getMulti: async () => ({}), get: async () => null });
        stub(t, oauth2Apps, {
            listAuthFlags: async () => {
                throw new Error('Redis gone');
            }
        });
        stub(t, logger, { error: entry => errors.push(entry.msg) });

        const context = await buildViewContext(request());
        assert.deepEqual(context.systemAlerts, []);
        assert.deepEqual(errors, ['Failed to list OAuth2 app auth flags']);
    });

    await t.test('EENGINE_DISABLE_SETUP_WARNINGS hides the setup banners', async t => {
        stub(t, settings, { getMulti: async () => ({ disableTokens: true }), get: async () => null });
        stub(t, oauth2Apps, { listAuthFlags: async () => [] });

        const previous = process.env.EENGINE_DISABLE_SETUP_WARNINGS;
        process.env.EENGINE_DISABLE_SETUP_WARNINGS = 'true';
        t.after(() => {
            if (previous === undefined) {
                delete process.env.EENGINE_DISABLE_SETUP_WARNINGS;
            } else {
                process.env.EENGINE_DISABLE_SETUP_WARNINGS = previous;
            }
        });

        const context = await buildViewContext(request());
        assert.deepEqual(context.systemAlerts, []);
        assert.equal(context.hideLicenseWarning, true);
        assert.equal(context.disableAuthWarning, true);
    });
});
