'use strict';

// The hosted setup form's answer to autodiscovery recognizing a Gmail or Microsoft mailbox on the
// IMAP path: which OAuth2 applications can sign that mailbox in instead of a password, and the page
// that offers them.

const { oauth2Apps, oauth2ProviderData } = require('../oauth2-apps');
const { autodetectImapSettings, isConsumerMailbox } = require('../autodetect-imap-settings');

// Outlook application authorities that can sign in a personal (Outlook.com) account. A tenant id
// or `organizations` signs in work accounts only, `consumers` personal ones only.
const CONSUMER_AUTHORITIES = new Set(['common', 'consumers']);

// What autodiscovery found for an address, kept while the sign-in page is open so that choosing
// "Continue with IMAP" there does not run the whole lookup again. Keyed by the setup link's nonce
// and the address, so one link's answer never reaches another link. Bounded and short-lived: a
// cosmetic shortcut, and a miss simply runs the lookup.
const DISCOVERY_CACHE = new Map();
const DISCOVERY_CACHE_TTL = 10 * 60 * 1000;
const DISCOVERY_CACHE_MAX_ENTRIES = 1000;

const discoveryKey = (nonce, email) => (nonce ? `${nonce}:${String(email).trim().toLowerCase()}` : null);

function rememberDiscovery(key, serverSettings) {
    if (!key) {
        return;
    }
    DISCOVERY_CACHE.delete(key);
    if (DISCOVERY_CACHE.size >= DISCOVERY_CACHE_MAX_ENTRIES) {
        DISCOVERY_CACHE.delete(DISCOVERY_CACHE.keys().next().value);
    }
    DISCOVERY_CACHE.set(key, { serverSettings, expires: Date.now() + DISCOVERY_CACHE_TTL });
}

function recallDiscovery(key) {
    const entry = key && DISCOVERY_CACHE.get(key);
    if (!entry) {
        return null;
    }
    DISCOVERY_CACHE.delete(key);
    return entry.expires > Date.now() ? entry.serverSettings : null;
}

/**
 * Discovers the server settings for the address the visitor typed. A visitor coming back from the
 * sign-in page reuses what was found a moment ago for the same link instead of a second lookup.
 *
 * The password is passed along because hosted Exchange refuses to answer autodiscovery
 * anonymously; it only ever reaches the autodiscovery host named by the address domain's own DNS,
 * and only after that host has asked for it.
 *
 * @param {Object} request - The POST /accounts/new/imap request
 * @param {Object} data - Its parsed signed blob
 * @returns {Promise<Object|undefined>} The autodiscovery result, undefined when nothing was found
 */
async function discoverServerSettings(request, data) {
    const { email, password, skipSignIn } = request.payload;
    const cached = skipSignIn ? recallDiscovery(discoveryKey(data.n, email)) : null;
    if (cached) {
        return cached;
    }
    try {
        return await autodetectImapSettings(email, request.app.gt, { user: email, pass: password });
    } catch (err) {
        request.logger.debug({ msg: 'Failed to resolve email server settings', email, err });
    }
}

/**
 * Whether an Outlook application can sign in the mailbox. A personal address needs an application
 * open to personal accounts; an organization's address needs one that is not limited to them. An
 * application pinned to one tenant stays in for any organization, since DNS does not say which
 * tenant a domain belongs to.
 */
function outlookAuthorityFits(app, consumer) {
    const authority = String(app.authority || 'common').toLowerCase();
    return consumer ? CONSUMER_AUTHORITIES.has(authority) : authority !== 'consumers';
}

/**
 * The applications to offer for a mailbox autodiscovery identified as `provider`, in the order the
 * provider picker lists them: listed (which is enabled), interactive (no Pub/Sub), and for Outlook
 * able to sign in this kind of account.
 *
 * When more than one is offered, each needs a name the visitor can tell apart, so an application
 * without a display title shows its name instead. A single one keeps the picker's look: no title.
 *
 * @param {Object[]} apps - Applications as `oauth2Apps.list()` returns them
 * @param {string} provider - `gmail` or `outlook`, from the autodiscovery result
 * @param {string} email - The address being set up
 * @returns {Object[]} The applications to offer, each with `providerData` and `displayTitle`
 */
function pickSignInApps(apps, provider, email) {
    const consumer = isConsumerMailbox(email);
    const picked = (apps || []).filter(
        app =>
            app &&
            app.provider === provider &&
            app.includeInListing &&
            app.baseScopes !== 'pubsub' &&
            (provider !== 'outlook' || outlookAuthorityFits(app, consumer))
    );

    return picked.map(app =>
        Object.assign({}, app, {
            providerData: oauth2ProviderData(app.provider, app.cloud),
            displayTitle: app.title || (picked.length > 1 ? app.name : null)
        })
    );
}

/**
 * Lists the applications to offer, see pickSignInApps().
 *
 * @returns {Promise<Object[]>}
 */
async function listSignInApps(provider, email) {
    if (!provider) {
        return [];
    }
    return pickSignInApps((await oauth2Apps.list(0, 100)).apps, provider, email);
}

/**
 * Shown on the IMAP path when autodiscovery recognized a Gmail or Microsoft mailbox and an OAuth2
 * application can sign it in: the visitor picked "Standard IMAP" for a mailbox that signs in better
 * (for Microsoft, only) through the provider.
 *
 * @param {Object} request - The POST /accounts/new/imap request
 * @param {Object} h - Response toolkit
 * @param {Object} [serverSettings] - Autodiscovery result
 * @param {Object} values - The page's form values (name, email, password, data, sig)
 * @param {string} [nonce] - The setup link's nonce, to remember the discovery under
 * @returns {Promise<Object>} `{ response }` to render the page, or `{ apps }` (the applications
 *   looked at, possibly none) to go on with the IMAP flow: the visitor chose IMAP already (or the
 *   link was minted for it), or no application fits
 */
async function renderProviderSignIn(request, h, serverSettings, values, nonce) {
    const provider = serverSettings && serverSettings.provider;
    if (!provider || request.payload.skipSignIn) {
        return { apps: null };
    }

    const apps = await listSignInApps(provider, values.email);
    if (!apps.length) {
        // The operator is the one who can fix this, and nothing else tells them it happens
        request.logger.info({ msg: 'No OAuth2 application can sign in this mailbox, continuing with IMAP', provider, domain: values.email.split('@').pop() });
        return { apps };
    }

    rememberDiscovery(discoveryKey(nonce, values.email), serverSettings);

    const response = h.view(
        'accounts/register/provider-signin',
        {
            pageTitleFull: request.app.gt.gettext('Email Account Setup'),
            isMicrosoft: provider === 'outlook',
            apps,
            values: { name: values.name, email: values.email, password: values.password, data: values.data, sig: values.sig }
        },
        { layout: 'public' }
    );
    return { response };
}

/**
 * The notice the server settings form opens with for a Microsoft mailbox, which will not accept the
 * password over IMAP. Read off the app-password hint the form already carries for such a mailbox
 * (server-derived, see applyAppPasswordHint), so every render of the form agrees.
 *
 * @param {Object} values - Settings form values
 * @param {Object[]} [knownApps] - Outlook applications already looked up for this request
 * @returns {Promise<Object|null>} `{ noApp }`, or null when the mailbox is not a Microsoft one
 */
async function microsoftSignInNotice(values, knownApps) {
    if (!values || values.appPassword_provider !== 'Microsoft' || !values.email) {
        return null;
    }
    const apps = knownApps || (await listSignInApps('outlook', values.email).catch(() => []));
    return { noApp: !apps.length };
}

module.exports = { pickSignInApps, listSignInApps, renderProviderSignIn, microsoftSignInNotice, discoverServerSettings };
