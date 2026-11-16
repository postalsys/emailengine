'use strict';

// The admin SSO strategies (Okta through @hapi/bell's built-in provider, generic OIDC through a
// custom bell provider built by lib/sso.js) and their callback routes. Moved out of workers/api.js,
// which cannot be required from a test, so that the bell registration can be exercised on a real
// hapi server (test/sso-routes-test.js). Everything the registration reads from the worker is
// passed in.

const sso = require('./sso');
const { setAdminSession } = require('./tools');

/**
 * @typedef {Object} SsoContext
 * @property {boolean} secureCookie Whether the cookies are marked Secure
 * @property {() => Promise<string>} getCookiePassword Password bell seals its state cookie with
 * @property {() => Promise<URL>} getServiceRedirectUrl The public base URL the callbacks live under
 * @property {() => Promise<number>} sessionPasswordVersion Stamped into the session, see workers/api.js
 * @property {Object} logger
 */

// A sign-in the IdP denied, or the user cancelled, comes back as an unauthenticated try-mode
// request. It gets the same flash-and-redirect the allow-list denial in the OIDC handler
// uses, so the user lands on the login form with a way to try again rather than on the
// generic error page with bell's raw message. The reason goes to the log only. ?sso_denied=1
// stops a forced instance from auto-redirecting straight back into the flow.
async function ssoFailureRedirect(request, h, method) {
    request.logger.warn({
        msg: 'SSO login failed',
        method,
        reason: (request.auth.error && request.auth.error.message) || 'unknown',
        remoteAddress: request.app.ip
    });
    await request.flash({ type: 'danger', message: 'Single sign-on failed or was cancelled. Please try again' });
    return h.redirect('/admin/login?sso_denied=1');
}

// The redirect URL is captured at strategy registration; the validators re-read it from settings
// so an origin change after startup (which would break the registered callback URL) disables the
// SSO button instead of failing mid-flow.
function originGuard(ctx, redirectUrl) {
    return async () => (await ctx.getServiceRedirectUrl()).origin === redirectUrl.origin;
}

/**
 * Registers the Okta strategy and its /admin/login/okta callback.
 *
 * @param {Object} server hapi server with @hapi/bell registered
 * @param {SsoContext} ctx
 * @param {{ baseUrl: string, clientId: string, clientSecret: string }} okta
 */
async function registerOktaAuth(server, ctx, okta) {
    let redirectUrl = await ctx.getServiceRedirectUrl();

    server.decorate('toolkit', 'validateOktaConfig', originGuard(ctx, redirectUrl));

    server.auth.strategy('okta', 'bell', {
        provider: 'okta',
        config: {
            uri: okta.baseUrl
        },
        password: await ctx.getCookiePassword(),
        isSecure: ctx.secureCookie,
        location: redirectUrl.origin,

        clientId: okta.clientId,
        clientSecret: okta.clientSecret
    });

    server.route({
        method: ['GET', 'POST'],
        path: '/admin/login/okta',
        async handler(request, h) {
            if (!request.auth.isAuthenticated) {
                return ssoFailureRedirect(request, h, 'okta');
            }

            let profile = (request.auth.credentials && request.auth.credentials.profile) || {};

            // The same minimal shape the OIDC branch below stores, for the same reasons: the
            // full bell credentials carry the access and refresh tokens, the callback query
            // and the raw userinfo document, none of which the session validator reads, and
            // all of which would sit in the browser's cookie for the life of the session.
            setAdminSession(request, {
                provider: 'okta',
                profile: {
                    id: profile.id,
                    username: profile.username,
                    displayName: profile.displayName,
                    email: profile.email
                },
                passwordVersion: await ctx.sessionPasswordVersion()
            });

            request.logger.info({ msg: 'Admin login successful', user: profile.username || 'unknown', method: 'okta', remoteAddress: request.app.ip });
            return h.redirect('/admin');
        },
        options: {
            auth: {
                mode: 'try',
                strategy: 'okta'
            }
        }
    });
}

/**
 * Registers the generic OIDC strategy and its /admin/login/oidc callback.
 *
 * @param {Object} server hapi server with @hapi/bell registered
 * @param {SsoContext} ctx
 * @param {Object} oidc
 * @param {Object} oidc.allowList parseAllowList() result
 * @param {Object} oidc.allowGroups parseGroupList() result
 * @param {() => Promise<Object>} [oidc.fetchDiscovery] Defaults to sso.fetchOidcDiscovery
 * @param {() => Promise<Object>} [oidc.retryDiscovery] Defaults to sso.retryDiscovery
 * @returns {Promise<{ retry: Promise<void>|null }>} The background retry, when the first discovery failed. Wrapped
 *   in an object because an async function returning the promise itself would hand the caller its result.
 */
async function registerOidcAuth(server, ctx, oidc) {
    let { logger } = ctx;
    let fetchDiscovery = oidc.fetchDiscovery || (() => sso.fetchOidcDiscovery());
    let retryDiscovery =
        oidc.retryDiscovery ||
        (() =>
            sso.retryDiscovery({
                onError: (err, attempt) => logger.debug({ msg: 'OIDC discovery retry failed', issuer: sso.OIDC_ISSUER, attempt, err })
            }));

    let redirectUrl = await ctx.getServiceRedirectUrl();
    let originUnchanged = originGuard(ctx, redirectUrl);

    // bell needs static auth/token URLs at strategy-registration time, so the
    // discovery document has to be in hand before the strategy and the callback
    // route that depends on it can be registered. A failure to fetch it (IdP outage
    // or misconfig) must NOT take EmailEngine down - password and passkey login plus
    // the REST API have to keep working - so SSO simply stays switched off until a
    // later attempt succeeds.
    //
    // Assigned from enableOidc()'s return value, so it can only be set once that
    // strategy and route exist and validateOidcConfig() can never advertise a login
    // button - or trigger OIDC_FORCED - for a route that is not registered.
    let oidcDiscovery = null;

    // Registered unconditionally so the login/security views can call it; returns
    // false when discovery failed or the serviceUrl origin drifted from startup.
    server.decorate('toolkit', 'validateOidcConfig', async () => !!oidcDiscovery && (await originUnchanged()));

    // RP-initiated logout URL for the /admin/logout handler. Returns null unless
    // OIDC_LOGOUT is enabled and the IdP advertised an end_session_endpoint.
    // post_logout_redirect_uri is only sent when OIDC_POST_LOGOUT_REDIRECT_URI is
    // configured (and registered at the IdP); otherwise the IdP shows its own
    // logged-out page, so logout needs no IdP-side configuration.
    server.decorate('toolkit', 'oidcLogoutUrl', idToken => {
        if (!sso.OIDC_LOGOUT || !oidcDiscovery || !oidcDiscovery.end_session_endpoint) {
            return null;
        }
        return sso.buildLogoutUrl(oidcDiscovery.end_session_endpoint, {
            idToken,
            clientId: sso.OIDC_CLIENT_ID,
            postLogoutRedirectUri: sso.OIDC_POST_LOGOUT_REDIRECT_URI || undefined
        });
    });

    const enableOidc = async discoveryDoc => {
        server.auth.strategy('oidc', 'bell', {
            provider: sso.buildOidcBellProvider(discoveryDoc),
            password: await ctx.getCookiePassword(),
            isSecure: ctx.secureCookie,
            location: redirectUrl.origin,

            clientId: sso.OIDC_CLIENT_ID,
            clientSecret: sso.OIDC_CLIENT_SECRET
        });

        server.route({
            method: ['GET', 'POST'],
            path: '/admin/login/oidc',
            async handler(request, h) {
                if (!request.auth.isAuthenticated) {
                    return ssoFailureRedirect(request, h, 'oidc');
                }

                let profile = (request.auth.credentials && request.auth.credentials.profile) || {};

                // Enforce the optional email/group allow-lists before establishing the session.
                if (!sso.isAuthorized(profile, oidc.allowList, oidc.allowGroups)) {
                    request.logger.warn({
                        msg: 'OIDC login denied by allow-list',
                        user: profile.username || profile.email || 'unknown',
                        groups: profile.groups,
                        method: 'oidc',
                        remoteAddress: request.app.ip
                    });
                    await request.flash({ type: 'danger', message: 'Your account is not authorized to access this admin panel' });
                    // ?sso_denied=1 stops a forced instance from auto-redirecting back into the
                    // OIDC flow before the user can see the error.
                    return h.redirect('/admin/login?sso_denied=1');
                }

                // Store only the minimal profile - not the full bell credentials. OIDC
                // access/refresh tokens (e.g. Keycloak JWTs) can push the iron-sealed
                // `ee` cookie past the ~4KB browser limit and cause a silent login loop.
                // Group names are kept so the per-request authorization re-check works;
                // the id_token is kept only as the logout id_token_hint (RP-initiated logout).
                const passwordVersion = await ctx.sessionPasswordVersion();
                setAdminSession(request, {
                    provider: 'oidc',
                    profile: {
                        id: profile.id,
                        username: profile.username,
                        displayName: profile.displayName,
                        email: profile.email,
                        // Carried so the per-request isAuthorized() re-check enforces email
                        // verification the same way the login gate above does.
                        emailVerified: profile.emailVerified,
                        groups: profile.groups
                    },
                    passwordVersion,
                    idToken: (request.auth.artifacts && request.auth.artifacts.id_token) || null
                });

                request.logger.info({ msg: 'Admin login successful', user: profile.username || 'unknown', method: 'oidc', remoteAddress: request.app.ip });
                return h.redirect('/admin');
            },
            options: {
                auth: {
                    mode: 'try',
                    strategy: 'oidc'
                }
            }
        });

        return discoveryDoc;
    };

    let startupDoc = await fetchDiscovery().catch(err => {
        logger.error({ msg: 'OIDC SSO disabled for now: discovery failed, retrying in the background', issuer: sso.OIDC_ISSUER, err });
        return null;
    });

    if (startupDoc) {
        // A registration failure here is deliberately fatal: a misconfiguration should
        // stop the worker at boot rather than come up quietly without SSO. The retry
        // path below is the opposite on purpose - it must not kill a serving process.
        oidcDiscovery = await enableOidc(startupDoc);
        return { retry: null };
    }

    // Deliberately not awaited by the caller - this runs for as long as the IdP is unreachable.
    // hapi accepts both a new auth strategy and a new route after the server has
    // started, so a later success brings SSO up in place, with no restart.
    let retry = retryDiscovery()
        .then(async retriedDoc => {
            oidcDiscovery = await enableOidc(retriedDoc);
            logger.info({ msg: 'OIDC SSO enabled after retrying discovery', issuer: sso.OIDC_ISSUER });
        })
        .catch(err => logger.error({ msg: 'OIDC SSO disabled: discovery retry failed', issuer: sso.OIDC_ISSUER, err }));
    return { retry };
}

module.exports = { registerOktaAuth, registerOidcAuth, ssoFailureRedirect };
