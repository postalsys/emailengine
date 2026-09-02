'use strict';

// Admin UI auth + user-profile routes: /admin/login (password + OKTA OAuth + generic
// OIDC SSO), /admin/logout, /admin/totp (TOTP two-factor), /admin/account/{security,
// tfa/{enable,disable},logout-all,passkeys/{register/options,register/verify,delete},
// password}, and /admin/passkey/auth/* (WebAuthn). Extracted verbatim from
// lib/routes-ui.js. The OKTA_OAUTH2_* env consts and USE_OKTA_AUTH are kept local to
// this module (only the auth routes use them); the generic OIDC config and helpers live
// in lib/sso.js because workers/api.js needs them too.

const Joi = require('joi');
const crypto = require('crypto');
const { parentPort } = require('worker_threads');
const pbkdf2 = require('@phc/pbkdf2');
const QRCode = require('qrcode');
const { generateTotpSeed, verifyTotp, generateTotpUrl } = require('../totp');
const {
    generateRegistrationOptions,
    verifyRegistrationResponse,
    generateAuthenticationOptions,
    verifyAuthenticationResponse
} = require('@simplewebauthn/server');

const settings = require('../settings');
const consts = require('../consts');
const { readEnvValue, setAdminSession } = require('../tools');
const passkeys = require('../passkeys');
const sso = require('../sso');

const { LOGIN_PERIOD_TTL, TOTP_WINDOW_SIZE, PDKDF2_ITERATIONS, PDKDF2_SALT_SIZE, PDKDF2_DIGEST } = consts;

const OKTA_OAUTH2_ISSUER = readEnvValue('OKTA_OAUTH2_ISSUER');
const OKTA_OAUTH2_CLIENT_ID = readEnvValue('OKTA_OAUTH2_CLIENT_ID');
const OKTA_OAUTH2_CLIENT_SECRET = readEnvValue('OKTA_OAUTH2_CLIENT_SECRET');
const USE_OKTA_AUTH = !!(OKTA_OAUTH2_ISSUER && OKTA_OAUTH2_CLIENT_ID && OKTA_OAUTH2_CLIENT_SECRET);

// SSO providers exposed to the login/security views. Each entry is falsy when the
// provider is not configured/usable; `any` is true when at least one is, letting the
// views render a single divider/status without per-provider guards.
// validateOktaConfig/validateOidcConfig are only decorated when the respective provider
// is enabled, so the ternaries must guard the calls.
async function ssoProviders(h) {
    let [okta, oidcUsable] = await Promise.all([USE_OKTA_AUTH ? h.validateOktaConfig() : false, sso.USE_OIDC_AUTH ? h.validateOidcConfig() : false]);
    let oidc = oidcUsable ? { name: sso.OIDC_PROVIDER_NAME } : false;
    return { okta, oidc, any: !!(okta || oidc) };
}

// Forced SSO is active only while OIDC is configured AND currently usable (discovery
// succeeded, serviceUrl origin unchanged); otherwise local sign-in stays available as an
// emergency fallback. validateOidcConfig is only decorated when USE_OIDC_AUTH is set, so
// the `&&` short-circuit must guard the call.
async function oidcForcedActive(h) {
    return !!(sso.OIDC_FORCED && sso.USE_OIDC_AUTH && (await h.validateOidcConfig()));
}

// Authenticator transports recorded at registration, turned into the wording and icon the
// passkey list shows for each entry. 'internal' outranks 'hybrid' because a platform
// authenticator that can additionally be driven from a phone is still, to the person
// reading the list, the passkey living on that computer. The icon class is emitted whole
// and safelisted in app.tailwind.css with the other server-driven icons - this file is not
// scanned by Tailwind - so that the wording and the icon stay one mapping in one place.
const SECURITY_KEY_TRANSPORTS = ['usb', 'nfc', 'ble'];

function describePasskeyDevice(transports) {
    let list = Array.isArray(transports) ? transports : [];

    if (list.includes('internal')) {
        return { label: 'Built-in authenticator', icon: 'icon-[tabler--fingerprint]' };
    }
    if (list.includes('hybrid')) {
        return { label: 'Phone or tablet', icon: 'icon-[tabler--device-mobile]' };
    }
    if (list.some(transport => SECURITY_KEY_TRANSPORTS.includes(transport))) {
        return { label: 'Security key', icon: 'icon-[tabler--usb]' };
    }
    return { label: 'Passkey', icon: 'icon-[tabler--key]' };
}

// Normalizes a stored timestamp into the ISO string the client-side .relative-time
// formatter parses. A value that does not parse becomes null so the cell renders as
// "unknown" rather than as an empty gap.
function passkeyTimestamp(value) {
    let date = value ? new Date(value) : null;
    return date && !isNaN(date.getTime()) ? date.toISOString() : null;
}

// Single place that knows how a failed password check is interpreted: an absent password and a
// verify() that throws (which happens only on a malformed stored hash, never on a wrong password)
// are both failures, never a pass. Sign-in, the password change and both passkey registration
// steps all come through here, so a change to how the account password is checked - a KDF swap,
// a dummy verify to flatten timing - lands in one place.
async function verifyAdminPassword(hash, password, logger) {
    if (!password) {
        return false;
    }
    try {
        return await pbkdf2.verify(hash, password);
    } catch (err) {
        logger.error({ msg: 'Failed to verify password hash', err });
        return false;
    }
}

// The current-password check behind the security page's step-down actions (the password change
// and switching the second factor off). A live session alone is not supposed to reveal the
// password, and unthrottled the field let a hijacked session guess it at full speed, so the
// check is rate limited the way the login form is: keyed on the account rather than the address
// because the caller is already authenticated as it, and with the login form's per-username
// budget. Owns the limiter and the warn logs; the caller decides how to report the failure.
//
// @returns {Promise<{ ok: true } | { ok: false, reason: 'rateLimited' | 'invalid' }>}
async function verifyCurrentPassword(request, h, authData, password) {
    let rateLimit = await h.checkRateLimit(`password:verify:${authData.user || 'admin'}`, 1, 10, 60);
    if (!rateLimit.success) {
        request.logger.warn({ msg: 'Rate limited', rateLimit, remoteAddress: request.app.ip });
        return { ok: false, reason: 'rateLimited' };
    }

    if (!(await verifyAdminPassword(authData.password, password, request.logger))) {
        request.logger.warn({ msg: 'Invalid current password', remoteAddress: request.app.ip });
        return { ok: false, reason: 'invalid' };
    }

    return { ok: true };
}

// View model for the security page's passkey list. Only the fields the list renders are
// exposed - the stored credential also carries the public key, the signature counter and
// the owning user, none of which belong in a template context.
async function listPasskeysForView(username) {
    let credentials = await passkeys.listCredentials(username);

    return credentials.map(credential => {
        let device = describePasskeyDevice(credential.transports);
        return {
            id: credential.id,
            name: credential.name,
            deviceLabel: device.label,
            deviceIcon: device.icon,
            createdAt: passkeyTimestamp(credential.createdAt),
            lastUsedAt: passkeyTimestamp(credential.lastUsedAt)
        };
    });
}

function init(args) {
    const { server } = args;

    server.route({
        method: 'GET',
        path: '/admin/login',
        async handler(request, h) {
            if (request.query.next && request.query.next.indexOf('/admin/login') === 0) {
                // prevent loops where successful login ends up back in the login page
                request.query.next = false;
            }

            // if authenticated and do not have to ask for TOTP, redirect directly to the admin page
            if (request.auth.isAuthenticated && !(request.auth.artifacts && request.auth.artifacts.requireTotp)) {
                return h.redirect(request.query.next || '/admin');
            }

            let providers = await ssoProviders(h);

            // Forced SSO: when OIDC is configured, usable, and OIDC_FORCED is set, skip the
            // local login screen and go straight to the provider. Suppressed while showing a
            // denial or logout notice (which would otherwise loop straight back into the flow),
            // and naturally inactive when OIDC is unusable (providers.oidc is false after a
            // discovery failure) so the local form remains as an emergency fallback.
            let forceLogin = sso.OIDC_FORCED && !!providers.oidc;
            if (forceLogin && !request.query.sso_denied && !request.query.loggedout) {
                return h.redirect('/admin/login/oidc');
            }

            let passkeysAvailable = await passkeys.hasPasskeys();

            return h.view(
                'account/login',
                {
                    pageTitle: 'Login',
                    menuLogin: true,
                    values: {
                        username: '',
                        next: request.query.next
                    },
                    providers,
                    forceLogin,
                    loggedOut: !!request.query.loggedout,
                    passkeysAvailable
                },
                {
                    layout: 'login'
                }
            );
        },
        options: {
            auth: {
                strategy: 'session',
                mode: 'try'
            },
            plugins: {
                cookie: {
                    redirectTo: false
                }
            },

            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                async failAction(request, h, err) {
                    request.logger.debug({ msg: 'Failed to validate login arguments', err });
                    return h.redirect('/admin/login').takeover();
                },

                query: Joi.object({
                    next: Joi.string()
                        .empty('')
                        .uri({ relativeOnly: true })
                        .pattern(/^\/(?!\/)/)
                        .label('NextUrl'),
                    sso_denied: Joi.boolean().truthy('1').falsy('0').empty('').default(false).label('SsoDenied'),
                    loggedout: Joi.boolean().truthy('1').falsy('0').empty('').default(false).label('LoggedOut')
                })
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/admin/logout',
        async handler(request, h) {
            let artifacts = request.auth && request.auth.artifacts;
            let user = request.auth && request.auth.credentials && request.auth.credentials.user;
            if (user) {
                request.logger.info({ msg: 'Admin logout', user, method: 'session', remoteAddress: request.app.ip });
            }

            // RP-initiated logout for OIDC sessions (OIDC_LOGOUT): terminate the IdP session
            // too, otherwise a forced instance would silently sign the user right back in.
            let logoutUrl = null;
            if (sso.USE_OIDC_AUTH && sso.OIDC_LOGOUT && artifacts && artifacts.provider === 'oidc') {
                logoutUrl = await h.oidcLogoutUrl(artifacts.idToken);
            }

            if (request.cookieAuth) {
                request.cookieAuth.clear();
            }

            if (logoutUrl) {
                return h.redirect(logoutUrl);
            }

            await request.flash({ type: 'info', message: `User logged out` });
            return h.redirect('/');
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/login',
        async handler(request, h) {
            // Forced SSO: local password sign-in is disabled while OIDC is usable. (If OIDC is
            // unusable - discovery failed - this is false, leaving password as an emergency path.)
            if (await oidcForcedActive(h)) {
                request.logger.warn({ msg: 'Password login refused: OIDC_FORCED', remoteAddress: request.app.ip });
                return h.redirect('/admin/login');
            }
            try {
                let ipRateLimit = await h.checkRateLimit(`login:ip:${request.app.ip}`, 1, 30, 60);
                if (!ipRateLimit.success) {
                    request.logger.warn({ msg: 'Rate limited', ipRateLimit, remoteAddress: request.app.ip });
                    let err = new Error('Rate limited, please wait and try again');
                    err.responseText = err.message;
                    throw err;
                }

                let rateLimit = await h.checkRateLimit(`login:${request.payload.username}`, 1, 10, 60);
                if (!rateLimit.success) {
                    request.logger.warn({ msg: 'Rate limited', rateLimit, remoteAddress: request.app.ip });
                    let err = new Error('Rate limited, please wait and try again');
                    err.responseText = err.message;
                    throw err;
                }

                let authData = await settings.get('authData');
                let totpEnabled = (await settings.get('totpEnabled')) || false;

                if (authData && authData.user && authData.user !== request.payload.username) {
                    request.logger.warn({ msg: 'Invalid username', username: request.payload.username, method: 'password', remoteAddress: request.app.ip });
                    let err = new Error('Failed to authenticate');
                    err.details = { password: err.message };
                    throw err;
                }

                if (authData && authData.password) {
                    let valid = await verifyAdminPassword(authData.password, request.payload.password, request.logger);
                    if (!valid) {
                        request.logger.warn({ msg: 'Invalid password', user: request.payload.username, method: 'password', remoteAddress: request.app.ip });
                        let err = new Error('Failed to authenticate');
                        err.details = { password: err.message };
                        throw err;
                    }

                    setAdminSession(request, {
                        user: authData.user,
                        requireTotp: totpEnabled,
                        passwordVersion: authData.passwordVersion || 0,
                        remember: request.payload.remember
                    });

                    if (request.payload.remember) {
                        request.cookieAuth.ttl(LOGIN_PERIOD_TTL);
                    }
                }

                request.logger.info({ msg: 'Admin login successful', user: authData.user, method: 'password', remoteAddress: request.app.ip });

                if (totpEnabled) {
                    let url = new URL(`admin/totp`, 'http://localhost');

                    if (request.payload.next) {
                        url.searchParams.append('next', request.payload.next);
                    }

                    return h.redirect(url.pathname + url.search);
                }

                await request.flash({ type: 'info', message: `Authentication successful` });

                if (request.payload.next) {
                    return h.redirect(request.payload.next);
                } else {
                    return h.redirect('/admin');
                }
            } catch (err) {
                await request.flash({ type: 'danger', message: err.responseText || `Could not sign in. Check your password and try again.` });
                request.logger.warn({ msg: 'Failed to authenticate', err, user: request.payload.username, method: 'password', remoteAddress: request.app.ip });

                let errors = err.details;

                return h.view(
                    'account/login',
                    {
                        pageTitle: 'Login',
                        menuLogin: true,
                        errors,
                        values: {
                            username: request.payload.username,
                            next: request.payload.next
                        },
                        providers: await ssoProviders(h),
                        passkeysAvailable: await passkeys.hasPasskeys()
                    },
                    {
                        layout: 'login'
                    }
                );
            }
        },
        options: {
            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                async failAction(request, h, err) {
                    let errors = {};

                    if (err.details) {
                        err.details.forEach(detail => {
                            if (!errors[detail.path]) {
                                errors[detail.path] = detail.message;
                            }
                        });
                    }

                    await request.flash({ type: 'danger', message: `Could not sign in. Check your password and try again.` });
                    request.logger.debug({ msg: 'Failed to authenticate', err, method: 'password', remoteAddress: request.app.ip });

                    return h
                        .view(
                            'account/login',
                            {
                                pageTitle: 'Login',
                                menuLogin: true,
                                errors,
                                values: {
                                    username: request.payload.username,
                                    next: request.payload.next
                                },
                                providers: await ssoProviders(h),
                                passkeysAvailable: await passkeys.hasPasskeys()
                            },
                            {
                                layout: 'login'
                            }
                        )
                        .takeover();
                },

                payload: Joi.object({
                    username: Joi.string().max(256).example('user').label('Username').description('Your account username'),
                    password: Joi.string().max(256).min(8).required().example('secret').label('Password').description('Your account password'),
                    remember: Joi.boolean().truthy('Y', 'true', '1', 'on').falsy('N', 'false', 0, '').default(false).description('Remember me'),
                    next: Joi.string()
                        .empty('')
                        .uri({ relativeOnly: true })
                        .pattern(/^\/(?!\/)/)
                        .label('NextUrl')
                })
            },

            auth: {
                strategy: 'session',
                mode: 'try'
            },
            plugins: {
                cookie: {
                    redirectTo: false
                }
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/admin/totp',
        async handler(request, h) {
            // No partial-auth (password-stage) session -> nothing to two-factor; send back to login
            // instead of dereferencing null credentials (which previously returned a 500).
            if (!(request.auth && request.auth.credentials && request.auth.credentials.user)) {
                return h.redirect('/admin/login');
            }

            return h.view(
                'account/totp',
                {
                    pageTitle: 'Login',
                    menuLogin: true,
                    values: {
                        username: request.auth.credentials.user,
                        next: request.query.next
                    }
                },
                {
                    layout: 'login'
                }
            );
        },
        options: {
            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                async failAction(request, h, err) {
                    request.logger.debug({ msg: 'Failed to validate login arguments', err });
                    return h.redirect('/admin/login').takeover();
                },

                query: Joi.object({
                    next: Joi.string()
                        .empty('')
                        .uri({ relativeOnly: true })
                        .pattern(/^\/(?!\/)/)
                        .label('NextUrl')
                })
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/totp',
        async handler(request, h) {
            try {
                if (!request.auth || !request.auth.artifacts || !request.auth.artifacts.requireTotp) {
                    // TOTP not needed
                    let url = new URL(`admin/login`, 'http://localhost');

                    if (request.payload.next) {
                        url.searchParams.append('next', request.payload.next);
                    }

                    return h.redirect(url.pathname + url.search);
                }

                if (request.auth && request.auth.credentials && request.auth.credentials.user) {
                    // attempt limiter
                    let rateLimit = await h.checkRateLimit(`totp:attempt:${request.auth.credentials.user}`, 1, 10, 60);
                    if (!rateLimit.success) {
                        request.logger.warn({ msg: 'Rate limited', rateLimit });
                        let err = new Error('Rate limited, please wait and try again');
                        err.responseText = err.message;
                        throw err;
                    }
                }

                let totpSeed = await settings.get('totpSeed');
                if (!totpSeed) {
                    await request.flash({ type: 'danger', message: `Start two-factor auth setup first` });
                    return h.redirect(`/admin/login`);
                }

                let verified = verifyTotp(totpSeed, request.payload.code, { window: TOTP_WINDOW_SIZE });

                if (!verified) {
                    let err = new Error('Failed to verify login');
                    err.details = { code: 'Invalid or expired code' };
                    throw err;
                }

                // code re-use limiter
                let reUseLimit = await h.checkRateLimit(`totp:code:${request.payload.code}`, 1, 1, 12 * 60);
                if (!reUseLimit.success) {
                    request.logger.warn({ msg: 'TOTP code recently used', reUseLimit });
                    let err = new Error('This code has been already used, please wait and try another code');
                    err.responseText = err.message;
                    throw err;
                }

                request.cookieAuth.clear('requireTotp');

                if (request.auth && request.auth.artifacts && request.auth.artifacts.remember) {
                    request.cookieAuth.ttl(LOGIN_PERIOD_TTL);
                }

                request.logger.info({
                    msg: 'TOTP verification successful',
                    user: request.auth.credentials.user,
                    method: 'totp',
                    remoteAddress: request.app.ip
                });

                if (request.payload.next) {
                    return h.redirect(request.payload.next);
                } else {
                    return h.redirect('/admin');
                }
            } catch (err) {
                if (!err.details || !err.details.code) {
                    // skip error message if code is invalid
                    await request.flash({ type: 'danger', message: err.responseText || `Could not verify. Check your code and try again.` });
                }

                request.logger.warn({
                    msg: 'Failed to verify TOTP',
                    err,
                    user: request.auth && request.auth.credentials && request.auth.credentials.user,
                    method: 'totp',
                    remoteAddress: request.app.ip
                });

                let errors = err.details;

                return h.view(
                    'account/totp',
                    {
                        pageTitle: 'Login',
                        menuLogin: true,
                        errors,
                        // the hidden next input, so a retry still lands where the login started
                        values: { next: request.payload.next }
                    },
                    {
                        layout: 'login'
                    }
                );
            }
        },
        options: {
            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                async failAction(request, h, err) {
                    let errors = {};

                    if (err.details) {
                        err.details.forEach(detail => {
                            if (!errors[detail.path]) {
                                errors[detail.path] = detail.message;
                            }
                        });
                    }

                    await request.flash({ type: 'danger', message: `Could not verify. Check your code and try again.` });
                    request.logger.debug({ msg: 'Failed to verify login', err });

                    return h
                        .view(
                            'account/totp',
                            {
                                pageTitle: 'Login',
                                menuLogin: true,
                                errors,
                                values: { next: request.payload.next }
                            },
                            {
                                layout: 'login'
                            }
                        )
                        .takeover();
                },

                payload: Joi.object({
                    type: Joi.string().valid('totp').description('The type of the two-factor authentication method').required(),
                    code: Joi.string().min(6).max(6).description('6-digit TOTP code').required(),
                    next: Joi.string()
                        .empty('')
                        .uri({ relativeOnly: true })
                        .pattern(/^\/(?!\/)/)
                        .label('NextUrl')
                })
            },

            auth: {
                strategy: 'session',
                mode: 'try'
            },
            plugins: {
                cookie: {
                    redirectTo: false
                }
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/admin/account/security',
        async handler(request, h) {
            if (request.auth.artifacts && request.auth.artifacts.provider) {
                return h.redirect(`/admin`);
            }

            // Single read for everything the page renders from - serviceUrl feeds both the TOTP
            // label and the passkey registration gate
            let { totpEnabled, totpSeed, serviceUrl } = await settings.getMulti('totpEnabled', 'totpSeed', 'serviceUrl');

            let totp = {
                enabled: totpEnabled || false
            };

            let username = (request.auth && request.auth.credentials && request.auth.credentials.user) || 'admin';

            if (!totpSeed) {
                totpSeed = generateTotpSeed();
                await settings.set('totpSeed', totpSeed);
            }

            if (!totp.enabled) {
                // create QR code
                let otpauth_url = generateTotpUrl(totpSeed, {
                    label: (serviceUrl || '').replace(/^https?:\/\/|\/$/g, ''),
                    issuer: 'EmailEngine'
                });

                try {
                    totp.dataUrl = await QRCode.toDataURL(otpauth_url);
                } catch (err) {
                    request.logger.error({ msg: 'Failed to generate QR code', err });
                }
            }

            // A count, not the list: this page summarizes passkeys and links to the page that
            // manages them, so one SCARD replaces fetching every credential hash.
            let passkeyCount = await passkeys.countCredentials(username);

            return h.view(
                'account/security',
                {
                    pageTitle: 'Account Security',
                    menuAccountSecurity: true,
                    activePassword: false,
                    disableAuthWarning: true,

                    username,

                    totp,
                    passkeyCount,
                    serviceUrl,
                    providers: await ssoProviders(h),
                    okta: {
                        OKTA_OAUTH2_ISSUER,
                        OKTA_OAUTH2_CLIENT_ID,
                        OKTA_OAUTH2_CLIENT_SECRET: OKTA_OAUTH2_CLIENT_SECRET ? OKTA_OAUTH2_CLIENT_SECRET.substring(0, 6) + '…' : null
                    },
                    oidc: {
                        OIDC_ISSUER: sso.OIDC_ISSUER,
                        OIDC_CLIENT_ID: sso.OIDC_CLIENT_ID,
                        OIDC_CLIENT_SECRET: sso.OIDC_CLIENT_SECRET ? sso.OIDC_CLIENT_SECRET.substring(0, 6) + '…' : null,
                        OIDC_PROVIDER_NAME: sso.OIDC_PROVIDER_NAME,
                        OIDC_ALLOWED_USERS: sso.OIDC_ALLOWED_USERS,
                        OIDC_ALLOWED_GROUPS: sso.OIDC_ALLOWED_GROUPS,
                        OIDC_GROUPS_CLAIM: sso.OIDC_GROUPS_CLAIM,
                        OIDC_FORCED: sso.OIDC_FORCED,
                        OIDC_LOGOUT: sso.OIDC_LOGOUT,
                        OIDC_POST_LOGOUT_REDIRECT_URI: sso.OIDC_POST_LOGOUT_REDIRECT_URI
                    }
                },
                {
                    layout: 'app'
                }
            );
        }
    });

    // Passkeys get a page of their own, the way the password does: the security page above is an
    // inventory of ways into the account, and a credential list that grows to MAX_PASSKEYS_PER_USER
    // rows would take it over. Registering needs an account password, so an instance without one
    // has nothing to show here.
    server.route({
        method: 'GET',
        path: '/admin/account/passkeys',
        async handler(request, h) {
            if (request.auth.artifacts && request.auth.artifacts.provider) {
                return h.redirect(`/admin`);
            }

            let authData = await settings.get('authData');
            if (!authData || !authData.password) {
                return h.redirect('/admin/account/security');
            }

            let username = (request.auth && request.auth.credentials && request.auth.credentials.user) || 'admin';

            // The RP ID is what the page names as the hostname the passkeys are bound to: it is
            // derived from the Service URL on every ceremony, so a changed host silently strands
            // every registered passkey, and the page is where that gets explained
            let [registeredPasskeys, { rpId, origin: serviceUrl }] = await Promise.all([listPasskeysForView(username), passkeys.getRpConfig()]);

            // Both reasons registration would fail are known here, so the button is disabled with
            // the reason on it instead of letting the ceremony run into a server error.
            let passkeyBlockReason = null;
            if (!serviceUrl) {
                passkeyBlockReason = 'Set a Service URL in configuration before registering passkeys';
            } else if (registeredPasskeys.length >= consts.MAX_PASSKEYS_PER_USER) {
                passkeyBlockReason = `Maximum of ${consts.MAX_PASSKEYS_PER_USER} passkeys reached - remove one to register another`;
            }

            return h.view(
                'account/passkeys',
                {
                    pageTitle: 'Passkeys',
                    menuAccountSecurity: true,
                    activePassword: false,
                    disableAuthWarning: true,

                    passkeys: registeredPasskeys,
                    passkeyBlockReason,
                    serviceUrl,
                    rpId
                },
                {
                    layout: 'app'
                }
            );
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/account/tfa/enable',
        async handler(request, h) {
            if (request.auth.artifacts && request.auth.artifacts.provider) {
                return h.redirect(`/admin`);
            }

            try {
                let totpSeed = await settings.get('totpSeed');
                if (!totpSeed) {
                    await request.flash({ type: 'danger', message: `Start two-factor auth setup first` });
                    return h.redirect(`/admin/account/security`);
                }

                let verified = verifyTotp(totpSeed, request.payload.code, { window: TOTP_WINDOW_SIZE });

                if (!verified) {
                    await request.flash({ type: 'danger', message: `Invalid verification code` });
                    return h.redirect(`/admin/account/security`);
                }

                await settings.set('totpEnabled', true);

                let authData = await settings.get('authData');
                if (authData) {
                    authData.passwordVersion = Date.now();
                    await settings.set('authData', authData);
                    request.cookieAuth.set('passwordVersion', authData.passwordVersion);
                    if (request.auth && request.auth.artifacts && request.auth.artifacts.remember) {
                        request.cookieAuth.ttl(LOGIN_PERIOD_TTL);
                    }
                }

                await request.flash({ type: 'success', message: `Two-factor auth enabled` });
                return h.redirect(`/admin/account/security`);
            } catch (err) {
                await request.flash({ type: 'danger', message: `Couldn't enable two-factor auth. Try again.` });
                request.logger.error({ msg: 'Failed to enable 2FA', err, remoteAddress: request.app.ip });
                return h.redirect(`/admin/account/security`);
            }
        },
        options: {
            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                async failAction(request, h, err) {
                    await request.flash({ type: 'danger', message: `Couldn't enable two-factor auth. Try again.` });
                    request.logger.debug({ msg: 'Failed to enable 2FA', err });

                    return h.redirect('/admin').takeover();
                },

                payload: Joi.object({
                    type: Joi.string().valid('totp').description('The type of the two-factor authentication method').required(),
                    code: Joi.string().min(6).max(6).description('6-digit TOTP code').required()
                })
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/account/tfa/disable',
        async handler(request, h) {
            if (request.auth.artifacts && request.auth.artifacts.provider) {
                return h.redirect(`/admin`);
            }

            try {
                // Switching the second factor off is a step down that a live session alone should
                // not be able to take - the password change and passkey registration both ask for
                // the password again, and so does this, through the same rate-limited check as
                // the password change because it is the same guess-the-password surface.
                let authData = await settings.get('authData');
                if (authData && authData.password) {
                    let verified = await verifyCurrentPassword(request, h, authData, request.payload.password);
                    if (!verified.ok) {
                        await request.flash({
                            type: 'danger',
                            message: verified.reason === 'rateLimited' ? `Rate limited, please wait and try again` : `Invalid password`
                        });
                        return h.redirect(`/admin/account/security`);
                    }
                }

                await settings.set('totpEnabled', false);
                await settings.set('totpSeed', false);

                await request.flash({ type: 'info', message: `Two-factor auth disabled` });
                return h.redirect(`/admin/account/security`);
            } catch (err) {
                await request.flash({ type: 'danger', message: `Couldn't disable two-factor auth. Try again.` });
                request.logger.error({ msg: 'Failed to disable 2FA', err, remoteAddress: request.app.ip });
                return h.redirect(`/admin/account/security`);
            }
        },
        options: {
            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                async failAction(request, h, err) {
                    await request.flash({ type: 'danger', message: `Couldn't disable two-factor auth. Try again.` });
                    request.logger.error({ msg: 'Failed to disable 2FA', err });

                    return h.redirect('/admin/account/security').takeover();
                },

                payload: Joi.object({
                    type: Joi.string().valid('totp').description('The type of the two-factor authentication method').required(),
                    password: Joi.string().max(256).required().label('Current password')
                })
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/account/logout-all',
        async handler(request, h) {
            if (request.auth.artifacts && request.auth.artifacts.provider) {
                return h.redirect(`/admin`);
            }

            try {
                let authData = await settings.get('authData');
                if (authData) {
                    authData.passwordVersion = Date.now();
                    await settings.set('authData', authData);
                }
                if (request.cookieAuth) {
                    request.cookieAuth.clear();
                }
                await request.flash({ type: 'info', message: `User logged out` });
                return h.redirect('/');
            } catch (err) {
                await request.flash({ type: 'danger', message: `Could not sign out sessions. Try again.` });
                request.logger.error({ msg: 'Failed to log out user sessions', err, remoteAddress: request.app.ip });
                return h.redirect(`/admin/account/security`);
            }
        },
        options: {
            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                async failAction(request, h, err) {
                    await request.flash({ type: 'danger', message: `Could not sign out sessions. Try again.` });
                    request.logger.error({ msg: 'Failed to log out user sessions', err });

                    return h.redirect('/admin').takeover();
                }
            }
        }
    });

    // --- Passkey (WebAuthn) routes ---

    const passkeyCredentialSchema = Joi.object({
        id: Joi.string()
            .max(512)
            .pattern(/^[A-Za-z0-9_-]+$/)
            .required(),
        rawId: Joi.string()
            .max(512)
            .pattern(/^[A-Za-z0-9_-]+$/)
            .required(),
        response: Joi.object({
            clientDataJSON: Joi.string().max(16384).required(),
            attestationObject: Joi.string().max(65536),
            authenticatorData: Joi.string().max(8192),
            signature: Joi.string().max(2048),
            userHandle: Joi.string().max(512).allow(''),
            publicKey: Joi.string().max(4096),
            publicKeyAlgorithm: Joi.number().integer()
        }).required(),
        type: Joi.string().valid('public-key').required(),
        authenticatorAttachment: Joi.string().optional(),
        clientExtensionResults: Joi.object().optional()
    }).required();

    // Registration: generate options (authenticated)
    server.route({
        method: 'POST',
        path: '/admin/account/passkeys/register/options',
        async handler(request, h) {
            try {
                let rateLimit = await h.checkRateLimit(`passkey:register:${request.app.ip}`, 1, 10, 60);
                if (!rateLimit.success) {
                    return h.response({ error: 'Rate limited, please wait and try again' }).code(429);
                }

                let authData = await settings.get('authData');
                if (!authData || !authData.password) {
                    return h.response({ error: 'Account password must be configured before registering passkeys' }).code(403);
                }

                let { rpId, origin } = await passkeys.getRpConfig();
                if (!rpId || !origin) {
                    return h.response({ error: 'Service URL must be configured before registering passkeys' }).code(400);
                }

                let user = (request.auth && request.auth.credentials && request.auth.credentials.user) || 'admin';

                let existingCredentials = await passkeys.listCredentials(user);
                if (existingCredentials.length >= consts.MAX_PASSKEYS_PER_USER) {
                    return h.response({ error: 'Maximum number of passkeys reached' }).code(400);
                }

                // Last, because it is the expensive check: the request is refused for a missing
                // Service URL or a full list without paying for a PBKDF2 verification first
                if (!(await verifyAdminPassword(authData.password, request.payload.password, request.logger))) {
                    return h.response({ error: 'Invalid password' }).code(403);
                }

                let options = await generateRegistrationOptions({
                    rpName: 'EmailEngine',
                    rpID: rpId,
                    userName: user,
                    userID: Buffer.from(crypto.createHash('sha256').update(user).digest()),
                    attestationType: 'none',
                    excludeCredentials: existingCredentials.map(c => ({
                        id: c.id,
                        transports: c.transports
                    })),
                    authenticatorSelection: {
                        residentKey: 'preferred',
                        userVerification: 'required'
                    }
                });

                let challengeId = await passkeys.storeChallenge(options.challenge, passkeys.CHALLENGE_REGISTER);

                return h.response({ challengeId, options }).code(200);
            } catch (err) {
                request.logger.error({ msg: 'Failed to generate passkey registration options', err });
                return h.response({ error: 'Failed to generate registration options' }).code(500);
            }
        },
        options: {
            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },
                payload: Joi.object({
                    password: Joi.string().max(256).allow('', null).optional().label('Current password')
                })
            }
        }
    });

    // Registration: verify response (authenticated)
    server.route({
        method: 'POST',
        path: '/admin/account/passkeys/register/verify',
        async handler(request, h) {
            try {
                let rateLimit = await h.checkRateLimit(`passkey:register:${request.app.ip}`, 1, 10, 60);
                if (!rateLimit.success) {
                    return h.response({ error: 'Rate limited, please wait and try again' }).code(429);
                }

                let { rpId, origin } = await passkeys.getRpConfig();
                if (!rpId || !origin) {
                    return h.response({ error: 'Service URL must be configured' }).code(400);
                }

                let authData = await settings.get('authData');
                if (!authData || !authData.password) {
                    return h.response({ error: 'Account password must be configured before registering passkeys' }).code(403);
                }

                // The password is confirmed again here, not only when the options were issued:
                // this is the request that stores a permanent credential, and a check one hop
                // upstream is only as good as the binding between the two hops. Belt and braces
                // over the challenge namespacing - a future third way to obtain a registration
                // challenge would otherwise reopen the bypass. Checked before the challenge is
                // consumed, so a mistyped password does not burn the nonce and force the whole
                // ceremony to be repeated.
                if (!(await verifyAdminPassword(authData.password, request.payload.password, request.logger))) {
                    return h.response({ error: 'Invalid password' }).code(403);
                }

                let challenge = await passkeys.consumeChallenge(request.payload.challengeId, passkeys.CHALLENGE_REGISTER);
                if (!challenge) {
                    return h.response({ error: 'Challenge expired or invalid. Please try again.' }).code(400);
                }

                let verification = await verifyRegistrationResponse({
                    response: request.payload.credential,
                    expectedChallenge: challenge,
                    expectedOrigin: origin,
                    expectedRPID: rpId
                });

                if (!verification.verified || !verification.registrationInfo) {
                    return h.response({ error: 'Registration verification failed' }).code(400);
                }

                let { credential } = verification.registrationInfo;
                let user = (request.auth && request.auth.credentials && request.auth.credentials.user) || 'admin';

                let saved = await passkeys.saveCredentialIfUnderLimit(
                    {
                        id: credential.id,
                        publicKey: Buffer.from(credential.publicKey).toString('base64url'),
                        counter: credential.counter,
                        transports: credential.transports || [],
                        name: request.payload.name,
                        user
                    },
                    consts.MAX_PASSKEYS_PER_USER
                );

                if (!saved) {
                    return h.response({ error: 'Maximum number of passkeys reached' }).code(400);
                }

                request.logger.info({
                    msg: 'Passkey registered',
                    user,
                    name: request.payload.name,
                    method: 'passkey',
                    remoteAddress: request.app.ip
                });

                return h.response({ success: true }).code(200);
            } catch (err) {
                request.logger.error({ msg: 'Failed to verify passkey registration', err });
                return h.response({ error: 'Registration failed' }).code(500);
            }
        },
        options: {
            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },
                payload: Joi.object({
                    challengeId: Joi.string().hex().length(64).required(),
                    password: Joi.string().max(256).allow('', null).optional().label('Current password'),
                    name: Joi.string().max(100).empty('').default('Unnamed passkey'),
                    credential: passkeyCredentialSchema
                })
            }
        }
    });

    // Delete passkey (authenticated)
    server.route({
        method: 'POST',
        path: '/admin/account/passkeys/delete',
        async handler(request, h) {
            if (request.auth.artifacts && request.auth.artifacts.provider) {
                return h.redirect('/admin');
            }

            try {
                let user = (request.auth && request.auth.credentials && request.auth.credentials.user) || 'admin';
                let deleted = await passkeys.deleteCredential(request.payload.credentialId, user);
                if (deleted) {
                    request.logger.info({
                        msg: 'Passkey deleted',
                        user,
                        credentialId: request.payload.credentialId,
                        method: 'passkey',
                        remoteAddress: request.app.ip
                    });
                    await request.flash({ type: 'info', message: 'Passkey removed' });
                } else {
                    await request.flash({ type: 'danger', message: 'Passkey not found' });
                }
            } catch (err) {
                await request.flash({ type: 'danger', message: 'Failed to remove passkey' });
                request.logger.error({ msg: 'Failed to delete passkey', err });
            }
            return h.redirect('/admin/account/passkeys');
        },
        options: {
            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                async failAction(request, h, err) {
                    await request.flash({ type: 'danger', message: 'Failed to remove passkey' });
                    request.logger.debug({ msg: 'Failed to delete passkey', err });
                    return h.redirect('/admin/account/passkeys').takeover();
                },

                payload: Joi.object({
                    credentialId: Joi.string()
                        .max(512)
                        .pattern(/^[A-Za-z0-9_-]+$/)
                        .required()
                        .description('Credential ID to delete')
                })
            }
        }
    });

    // Authentication: generate options (unauthenticated)
    server.route({
        method: 'POST',
        path: '/admin/passkey/auth/options',
        async handler(request, h) {
            // Forced SSO: local passkey sign-in is disabled while OIDC is usable.
            if (await oidcForcedActive(h)) {
                return h.response({ error: 'sso_required' }).code(403);
            }
            try {
                let rateLimit = await h.checkRateLimit(`passkey:auth:options:${request.app.ip}`, 1, 10, 60);
                if (!rateLimit.success) {
                    return h.response({ error: 'Rate limited, please wait and try again' }).code(429);
                }

                let { rpId } = await passkeys.getRpConfig();
                if (!rpId) {
                    return h.response({ error: 'no_passkeys' }).code(400);
                }

                let allCredentials = await passkeys.getAllCredentials();
                if (!allCredentials.length) {
                    return h.response({ error: 'no_passkeys' }).code(400);
                }

                let options = await generateAuthenticationOptions({
                    rpID: rpId,
                    allowCredentials: allCredentials.map(c => ({
                        id: c.id,
                        transports: c.transports
                    })),
                    userVerification: 'required'
                });

                let challengeId = await passkeys.storeChallenge(options.challenge, passkeys.CHALLENGE_AUTH);

                return h.response({ challengeId, options }).code(200);
            } catch (err) {
                request.logger.error({ msg: 'Failed to generate passkey auth options', err });
                return h.response({ error: 'Failed to generate authentication options' }).code(500);
            }
        },
        options: {
            auth: {
                strategy: 'session',
                mode: 'try'
            },
            plugins: {
                cookie: {
                    redirectTo: false
                }
            },
            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },
                payload: Joi.object({})
            }
        }
    });

    // Authentication: verify response (unauthenticated)
    server.route({
        method: 'POST',
        path: '/admin/passkey/auth/verify',
        async handler(request, h) {
            // Forced SSO: local passkey sign-in is disabled while OIDC is usable.
            if (await oidcForcedActive(h)) {
                return h.response({ error: 'sso_required' }).code(403);
            }
            try {
                let rateLimit = await h.checkRateLimit(`passkey:auth:verify:${request.app.ip}`, 1, 10, 60);
                if (!rateLimit.success) {
                    return h.response({ error: 'Rate limited, please wait and try again' }).code(429);
                }

                let { rpId, origin } = await passkeys.getRpConfig();
                if (!rpId || !origin) {
                    request.logger.warn({ msg: 'Passkey auth failed: missing RP config', method: 'passkey', remoteAddress: request.app.ip });
                    return h.response({ success: false, error: 'Authentication failed' }).code(400);
                }

                let challenge = await passkeys.consumeChallenge(request.payload.challengeId, passkeys.CHALLENGE_AUTH);
                if (!challenge) {
                    request.logger.warn({ msg: 'Passkey auth failed: challenge expired or invalid', method: 'passkey', remoteAddress: request.app.ip });
                    return h.response({ success: false, error: 'Challenge expired or invalid. Please try again.' }).code(400);
                }

                let credentialId = request.payload.credential && request.payload.credential.id;
                let storedCredential = await passkeys.getCredential(credentialId);
                if (!storedCredential) {
                    request.logger.warn({ msg: 'Passkey auth failed: unknown credential', method: 'passkey', remoteAddress: request.app.ip });
                    return h.response({ success: false, error: 'Authentication failed' }).code(400);
                }

                let verification = await verifyAuthenticationResponse({
                    response: request.payload.credential,
                    expectedChallenge: challenge,
                    expectedOrigin: origin,
                    expectedRPID: rpId,
                    credential: {
                        id: storedCredential.id,
                        publicKey: Buffer.from(storedCredential.publicKey, 'base64url'),
                        counter: storedCredential.counter,
                        transports: storedCredential.transports
                    }
                });

                if (!verification.verified) {
                    request.logger.warn({ msg: 'Passkey auth failed: verification failed', method: 'passkey', remoteAddress: request.app.ip });
                    return h.response({ success: false, error: 'Authentication failed' }).code(400);
                }

                let user = storedCredential.user;
                let authData = await settings.get('authData');

                if (!authData || !authData.user || authData.user !== user) {
                    request.logger.warn({ msg: 'Passkey auth failed: user mismatch', method: 'passkey', remoteAddress: request.app.ip });
                    return h.response({ success: false, error: 'Authentication failed' }).code(400);
                }

                await passkeys.recordAuthentication(storedCredential.id, verification.authenticationInfo.newCounter);

                setAdminSession(request, {
                    user,
                    requireTotp: false,
                    passwordVersion: (authData && authData.passwordVersion) || 0,
                    remember: request.payload.remember || false
                });

                if (request.payload.remember) {
                    request.cookieAuth.ttl(LOGIN_PERIOD_TTL);
                }

                request.logger.info({ msg: 'Passkey authentication successful', user, method: 'passkey', remoteAddress: request.app.ip });

                return h.response({ success: true, redirect: request.payload.next || '/admin' }).code(200);
            } catch (err) {
                request.logger.error({ msg: 'Failed to verify passkey authentication', err, method: 'passkey', remoteAddress: request.app.ip });
                return h.response({ success: false, error: 'Authentication failed' }).code(400);
            }
        },
        options: {
            auth: {
                strategy: 'session',
                mode: 'try'
            },
            plugins: {
                cookie: {
                    redirectTo: false
                }
            },
            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },
                payload: Joi.object({
                    challengeId: Joi.string().hex().length(64).required(),
                    credential: passkeyCredentialSchema,
                    next: Joi.string()
                        .empty('')
                        .uri({ relativeOnly: true })
                        .pattern(/^\/(?!\/)/)
                        .label('NextUrl'),
                    remember: Joi.boolean().truthy('Y', 'true', '1', 'on').falsy('N', 'false', 0, '').default(false)
                })
            }
        }
    });

    // --- End of Passkey routes ---

    server.route({
        method: 'GET',
        path: '/admin/account/password',
        async handler(request, h) {
            if (request.auth.artifacts && request.auth.artifacts.provider) {
                return h.redirect(`/admin`);
            }

            let username = (request.auth && request.auth.credentials && request.auth.credentials.user) || 'admin';

            return h.view(
                'account/password',
                {
                    pageTitle: 'Account Security',
                    menuAccountSecurity: true,
                    activePassword: true,
                    disableAuthWarning: true,

                    username,
                    // the form warns that a password change removes these
                    passkeyCount: await passkeys.countCredentials(username)
                },
                {
                    layout: 'app'
                }
            );
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/account/password',
        async handler(request, h) {
            if (request.auth.artifacts && request.auth.artifacts.provider) {
                return h.redirect(`/admin`);
            }

            try {
                let authData = await settings.get('authData');
                let hasExistingPassword = !!(authData && authData.password);
                if (hasExistingPassword) {
                    let verified = await verifyCurrentPassword(request, h, authData, request.payload.password0);
                    if (!verified.ok) {
                        let err = new Error(
                            verified.reason === 'rateLimited' ? 'Rate limited, please wait and try again' : 'Failed to verify current password'
                        );
                        err.details = { password0: err.message };
                        throw err;
                    }
                }

                const passwordHash = await pbkdf2.hash(request.payload.password, {
                    iterations: PDKDF2_ITERATIONS,
                    saltSize: PDKDF2_SALT_SIZE,
                    digest: PDKDF2_DIGEST
                });

                authData = authData || {};
                authData.user = authData.user || 'admin';
                authData.password = passwordHash;
                authData.passwordVersion = Date.now();

                await settings.set('authData', authData);

                // Every passkey goes with the old password: registering one takes the password,
                // so a passkey that outlived a password change could be one registered by whoever
                // had the old password. The form warns about this while passkeys exist, and the
                // flash below says how many went.
                let clearedPasskeys = 0;
                try {
                    clearedPasskeys = await passkeys.deleteAllCredentials(authData.user || 'admin');
                    request.logger.info({ msg: 'All passkeys cleared after password change', user: authData.user || 'admin', cleared: clearedPasskeys });
                } catch (passkeyErr) {
                    request.logger.error({ msg: 'Failed to clear passkeys after password change', err: passkeyErr });
                }

                if (!server.auth.settings.default) {
                    server.auth.default('session');
                    setAdminSession(request, {
                        user: authData.user,
                        passwordVersion: authData.passwordVersion
                    });

                    // Only this API worker's server got the default strategy above. With
                    // EENGINE_WORKERS_API > 1 the other workers decided at boot that the instance
                    // is open (settings.isInstanceSecured() was false then) and would keep serving
                    // /admin without a login until restarted, so the same settings broadcast the
                    // network config page uses tells every API worker to apply it (workers/api.js
                    // handles the authData key). The value is a marker, not the credential.
                    if (parentPort) {
                        parentPort.postMessage({ cmd: 'settings', data: { authData: true } });
                    }
                } else {
                    request.cookieAuth.set('passwordVersion', authData.passwordVersion);
                }

                if (request.auth && request.auth.artifacts && request.auth.artifacts.remember) {
                    request.cookieAuth.ttl(LOGIN_PERIOD_TTL);
                }

                if (!hasExistingPassword) {
                    await request.flash({ type: 'info', message: `Password saved` });

                    return h.redirect('/admin');
                }

                await request.flash({
                    type: 'info',
                    message: clearedPasskeys
                        ? `Password updated and ${clearedPasskeys} registered passkey${clearedPasskeys === 1 ? '' : 's'} removed`
                        : `Password updated`
                });

                return h.redirect('/admin/account/password');
            } catch (err) {
                await request.flash({ type: 'danger', message: `Couldn't update password. Try again.` });
                request.logger.error({ msg: 'Failed to update password', err });

                let username = (request.auth && request.auth.credentials && request.auth.credentials.user) || 'admin';

                return h.view(
                    'account/password',
                    {
                        pageTitle: 'Account Security',
                        menuAccountSecurity: true,
                        activePassword: true,
                        disableAuthWarning: true,
                        errors: err.details,

                        username,
                        passkeyCount: await passkeys.countCredentials(username)
                    },
                    {
                        layout: 'app'
                    }
                );
            }
        },
        options: {
            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                async failAction(request, h, err) {
                    let errors = {};

                    if (err.details) {
                        err.details.forEach(detail => {
                            if (!errors[detail.path]) {
                                errors[detail.path] = detail.message;
                            }
                        });
                    }

                    await request.flash({ type: 'danger', message: `Couldn't update password. Try again.` });
                    request.logger.debug({ msg: 'Failed to update account password', err });

                    let username = (request.auth && request.auth.credentials && request.auth.credentials.user) || 'admin';

                    return h
                        .view(
                            'account/password',
                            {
                                pageTitle: 'Account Security',
                                menuAccountSecurity: true,
                                activePassword: true,
                                disableAuthWarning: true,
                                errors,

                                username
                            },
                            {
                                layout: 'app'
                            }
                        )
                        .takeover();
                },

                payload: Joi.object({
                    password0: Joi.string().max(256).min(8).example('secret').label('Current password').description('Current password'),
                    password: Joi.string().max(256).min(8).required().example('secret').label('New password').description('New password'),
                    password2: Joi.string()
                        .max(256)
                        .required()
                        .example('secret')
                        .label('Repeat password')
                        .description('Repeat password')
                        .valid(Joi.ref('password'))
                })
            }
        }
    });
}

module.exports = init;
