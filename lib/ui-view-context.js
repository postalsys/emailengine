'use strict';

// The view context every server-rendered page receives (the `context` option of server.views() in
// workers/api.js). Moved out of the API worker, which a test cannot load, so the context and the
// system alerts it carries are tested directly.

const logger = require('./logger');
const settings = require('./settings');
const packageData = require('../package.json');
const { redis } = require('./db');
const { oauth2Apps } = require('./oauth2-apps');
const { isSuspended } = require('./license-subscription');
const { flash, hasEnvValue, readEnvValue, getBoolean } = require('./tools');
const { LAST_DOCUMENT_STORE_VERSION } = require('./consts');

const DAY_MS = 24 * 3600 * 1000;

// The settings the context reads on every render
const CONTEXT_SETTINGS = [
    'upgrade',
    'webhookErrorFlag',
    'webhooksEnabled',
    'disableTokens',
    'tract',
    'templateHeader',
    'templateHtmlHead',
    'documentStoreEnabled',
    'serviceUrl',
    'language',
    'locale',
    'timezone',
    'pageBrandName',
    'notificationBaseUrl'
];

// How a single sign-on session's profile is shown as the signed-in user. SSO users never manage
// the local password, hence isAdmin: false
const SSO_AUTH_DISPLAY = {
    okta: profile => ({
        user: profile.username,
        name:
            []
                .concat(profile.firstName || [])
                .concat(profile.lastName || [])
                .join(' ') || profile.username,
        enabled: !!profile.username,
        isAdmin: false
    }),
    oidc: profile => ({
        user: profile.username,
        name: profile.displayName || profile.username,
        enabled: !!profile.username,
        isAdmin: false
    })
};

/**
 * The signed-in user as the page header shows it: the SSO profile for an SSO session, otherwise
 * the local admin account, or a disabled placeholder when no admin password is set.
 *
 * @param {Object} [artifacts] - request.auth.artifacts
 * @returns {Promise<Object>} `{ user, name, enabled, isAdmin }`
 */
async function resolveAuthDisplay(artifacts) {
    let provider = artifacts && artifacts.provider;
    if (provider && Object.hasOwn(SSO_AUTH_DISPLAY, provider)) {
        return SSO_AUTH_DISPLAY[provider](artifacts.profile || {});
    }

    let authData = await settings.get('authData');
    if (authData) {
        authData.name = authData.user;
        authData.enabled = true;
        authData.isAdmin = true;
        return authData;
    }

    return {
        name: 'admin',
        user: 'admin',
        enabled: false,
        isAdmin: true
    };
}

/**
 * The license details shown on the page, with the whole days left until a set expiry.
 *
 * @param {Object} [licenseInfo] - request.app.licenseInfo
 * @param {number} now - current time in milliseconds
 * @returns {Object} a copy of the details, plus `expiresDays` when they carry an expiry
 */
function licenseDetailsView(licenseInfo, now) {
    let licenseDetails = Object.assign({}, (licenseInfo && licenseInfo.details) || {});

    if (licenseDetails.expires) {
        let delayMs = new Date(licenseDetails.expires) - now;
        licenseDetails.expiresDays = Math.max(Math.ceil(delayMs / DAY_MS), 0);
    }

    return licenseDetails;
}

const plural = count => (count !== 1 ? 's' : '');

// The banners above every admin page, in display order. Each rule returns an alert, a list of
// them, or nothing
const ALERT_RULES = [
    ({ settingsValues }) => {
        let upgradeInfo = settingsValues.upgrade;
        if (upgradeInfo && upgradeInfo.canUpgrade) {
            return {
                url: '/admin/upgrade',
                level: 'info',
                icon: 'icon-[tabler--alert-triangle]',
                message: `An update is available: Emailengine v${upgradeInfo.available}`
            };
        }
    },

    // The subscription behind the license (lib/license-subscription.js): paused, or a date it pauses on
    ({ licenseInfo }) => {
        if (isSuspended(licenseInfo)) {
            return {
                url: '/admin/config/license',
                level: 'danger',
                icon: 'icon-[tabler--player-pause]',
                message: 'EmailEngine is paused: the subscription behind the license key is not in good standing'
            };
        }
        let licenseSubscription = licenseInfo && licenseInfo.subscription;
        if (licenseSubscription) {
            return {
                url: '/admin/config/license',
                level: 'danger',
                icon: 'icon-[tabler--alert-triangle]',
                message: `Subscription payment overdue: EmailEngine pauses in ${licenseSubscription.days} day${plural(licenseSubscription.days)} unless it is paid`
            };
        }
    },

    // OAuth2 apps whose token requests are being refused (setFlag() writes the failure
    // into app meta). Shown on every admin page: the accounts on such an app sit
    // disconnected until the operator acts, so the OAuth config page alone is not enough.
    ({ oauthAuthFlags }) =>
        oauthAuthFlags.map(({ app, authFlag }) => ({
            url: authFlag.url || `/admin/config/oauth/app/${encodeURIComponent(app)}`,
            level: 'danger',
            icon: 'icon-[tabler--lock-open]',
            message: authFlag.message
        })),

    ({ settingsValues }) => {
        let webhookErrorFlag = settingsValues.webhookErrorFlag;
        if (settingsValues.webhooksEnabled && webhookErrorFlag && webhookErrorFlag.message) {
            return {
                url: '/admin/config/webhooks',
                level: 'danger',
                icon: 'icon-[tabler--link]',
                message: 'Webhook delivery is failing'
            };
        }
    },

    // a paused license is still registered, and the alert above says why it is not active
    ({ licenseInfo }) => {
        if (!licenseInfo || (!licenseInfo.active && !licenseInfo.details)) {
            return {
                url: '/admin/config/license',
                level: 'warning',
                icon: 'icon-[tabler--key]',
                message: 'No license key registered'
            };
        }
    },

    ({ licenseDetails }) => {
        if (licenseDetails.expires && licenseDetails.expiresDays < 31) {
            return {
                url: '/admin/config/license',
                level: 'warning',
                icon: 'icon-[tabler--key]',
                message: `Your ${licenseDetails.trial ? `trial ` : ''}license key will expire in ${licenseDetails.expiresDays} day${plural(
                    licenseDetails.expiresDays
                )}`
            };
        }
    },

    ({ settingsValues }) => {
        if (settingsValues.disableTokens) {
            return {
                url: '/admin/config/security',
                level: 'warning',
                icon: 'icon-[tabler--key]',
                message: `Access tokens are disabled for API requests`
            };
        }
    },

    // The Document Store was removed in 2.82.0. The setting that switched it on is read raw off
    // the settings hash (it is no longer in the settings schema), so an instance upgraded with the
    // feature still on is told where it went instead of losing it quietly
    ({ settingsValues }) => {
        if (settingsValues.documentStoreEnabled) {
            return {
                url: '/admin',
                level: 'danger',
                icon: 'icon-[tabler--database]',
                message: `The Document Store has been removed from EmailEngine. Downgrade to v${LAST_DOCUMENT_STORE_VERSION} if you still need it.`
            };
        }
    }
];

/**
 * The banners shown above every admin page.
 *
 * @param {Object} state
 * @param {Object} state.settingsValues - the CONTEXT_SETTINGS values
 * @param {Object} [state.licenseInfo] - request.app.licenseInfo
 * @param {Object} state.licenseDetails - licenseDetailsView() output
 * @param {Array} state.oauthAuthFlags - `{ app, authFlag }` per OAuth2 app whose token requests fail
 * @param {boolean} state.disableSetupWarnings - keep only the danger level alerts
 * @returns {Array<Object>} `{ url, level, icon, message }` per alert, in display order
 */
function buildSystemAlerts(state) {
    let systemAlerts = ALERT_RULES.flatMap(rule => [].concat(rule(state) || []));

    if (state.disableSetupWarnings) {
        // Keep only critical (danger) alerts, suppress info/warning level
        systemAlerts = systemAlerts.filter(alert => alert.level === 'danger');
    }

    return systemAlerts;
}

/**
 * The view context of a rendered page.
 *
 * @param {Object} request - the hapi request being rendered
 * @returns {Promise<Object>}
 */
async function buildViewContext(request) {
    // The three reads are independent, and this runs on every admin page render. The
    // OAuth2 auth flags are best-effort - a failure to read them must not take the page
    // down with it.
    const [pendingMessages, settingsValues, oauthAuthFlags] = await Promise.all([
        flash(redis, request),
        settings.getMulti(...CONTEXT_SETTINGS),
        oauth2Apps.listAuthFlags().catch(err => {
            logger.error({ msg: 'Failed to list OAuth2 app auth flags', err });
            return [];
        })
    ]);

    const {
        tract,
        templateHeader: embeddedTemplateHeader,
        templateHtmlHead: embeddedTemplateHtmlHead,
        documentStoreEnabled: documentStoreRemoved,
        serviceUrl,
        language,
        locale,
        timezone,
        pageBrandName,
        notificationBaseUrl
    } = settingsValues;

    let authData = await resolveAuthDisplay(request.auth.artifacts);

    let licenseDetails = licenseDetailsView(request.app.licenseInfo, Date.now());

    // Check if setup warnings should be disabled (for documentation screenshots, CI, etc.)
    const disableSetupWarnings = hasEnvValue('EENGINE_DISABLE_SETUP_WARNINGS') ? getBoolean(readEnvValue('EENGINE_DISABLE_SETUP_WARNINGS')) : false;

    let systemAlerts = buildSystemAlerts({
        settingsValues,
        licenseInfo: request.app.licenseInfo,
        licenseDetails,
        oauthAuthFlags,
        disableSetupWarnings
    });

    // Whether the requester holds a session at all, so a public page (the hosted form's
    // error page, for one) can tell a mailbox owner from an admin without reading
    // authData, which describes the instance rather than the requester
    const isAuthenticated = !!(request.auth && request.auth.isAuthenticated);

    return {
        // the per-request CSP nonce every inline <script> carries (lib/security-headers.js)
        cspNonce: request.app.cspNonce,
        pageBrandName: pageBrandName || 'EmailEngine',
        values: request.payload || {},
        errors: (request.error && request.error.details) || {},
        pendingMessages,
        licenseInfo: request.app.licenseInfo,
        licenseDetails,
        trialPossible: !tract,
        authData,
        isAuthenticated,
        // The dashboard is an admin destination: a link to it belongs on a page only for
        // a requester who holds an admin session, or on an instance with no admin login
        showDashboardLink: isAuthenticated || !(authData && authData.enabled),
        packageData,
        systemAlerts,
        embeddedTemplateHeader,
        embeddedTemplateHtmlHead,
        currentYear: new Date().getFullYear(),
        documentStoreRemoved,
        lastDocumentStoreVersion: LAST_DOCUMENT_STORE_VERSION,
        updateBrowserInfo: !serviceUrl || !language || !timezone,

        // Suppress large banner warnings when EENGINE_DISABLE_SETUP_WARNINGS is set
        hideLicenseWarning: disableSetupWarnings,
        disableAuthWarning: disableSetupWarnings,

        mainServiceUrl: serviceUrl,
        notificationBaseUrl,

        userLocale: locale,
        userTimezone: timezone,

        templateLocale: request.app.locale
    };
}

module.exports = { buildViewContext, buildSystemAlerts, resolveAuthDisplay, licenseDetailsView, CONTEXT_SETTINGS };
