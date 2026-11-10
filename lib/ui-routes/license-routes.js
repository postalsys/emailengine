'use strict';

// The admin UI's license page (/admin/config/license): showing the license and the subscription
// behind it, registering and removing a key, requesting a trial, and "Check subscription now"
// (lib/license-subscription.js decides what an answer of the license server does).

const Joi = require('joi');
const os = require('os');
const packageData = require('../../package.json');
const { fetch: fetchCmd } = require('undici');
const settings = require('../settings');
const { failAction, httpAgent } = require('../tools');
const { isSubscriptionLicense, isSuspended } = require('../license-subscription');

const LICENSE_HOST = 'https://postalsys.com';

// A date as the license page prints it, "10 December 2026", in UTC so every admin reads the same day
const dayLabel = value => new Date(value).toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric', timeZone: 'UTC' });

/**
 * The license page's view context: the GET and the error paths of the POST render the same page
 * @param {Object|undefined} licenseInfo - the `license` command's answer
 * @param {Object} [extra] - errors and the like
 * @returns {Object}
 */
function licensePageContext(licenseInfo, extra) {
    let subscription = licenseInfo && licenseInfo.subscription;
    return Object.assign(
        {
            pageTitle: 'License',
            menuLicense: true,
            hideLicenseWarning: true,

            // what the license page says about the subscription behind the key
            licenseInfo,
            isSubscriptionLicense: !!(licenseInfo && isSubscriptionLicense(licenseInfo.details)),
            isPaused: isSuspended(licenseInfo),
            subscriptionSince: subscription && subscription.since ? dayLabel(subscription.since) : null,
            subscriptionUntil: subscription && subscription.until ? dayLabel(subscription.until) : null,
            expiresDays: subscription ? subscription.days : undefined,

            // a paused license is still registered, so the form to add one stays closed
            showLicenseText: !licenseInfo || !licenseInfo.details || !!licenseInfo.details.trial
        },
        extra
    );
}

function registerGetConfigLicense(server, args) {
    const { call } = args;

    server.route({
        method: 'GET',
        path: '/admin/config/license',
        async handler(request, h) {
            // the answer reflects the check, which can have changed the state the request started with
            let licenseInfo = (await call({ cmd: 'checkLicense' })) || request.app.licenseInfo;
            request.app.licenseInfo = licenseInfo;

            return h.view('config/license', licensePageContext(licenseInfo), {
                layout: 'app'
            });
        }
    });
}

function registerPostConfigLicense(server, args) {
    const { call } = args;

    server.route({
        method: 'POST',
        path: '/admin/config/license',
        async handler(request, h) {
            try {
                // update license
                const licenseInfo = await call({ cmd: 'updateLicense', license: request.payload.license });
                if (!licenseInfo) {
                    let err = new Error('Failed to update license. Check license file contents.');
                    err.statusCode = 403;
                    err.details = { license: err.message };
                    throw err;
                }

                if (licenseInfo.active) {
                    await request.flash({ type: 'info', message: `License activated` });
                }

                return h.redirect('/admin/config/license');
            } catch (err) {
                await request.flash({ type: 'danger', message: `Couldn't register license. Check the key and try again.` });
                request.logger.warn({ msg: 'Failed to register license key', err });

                let context = licensePageContext(request.app.licenseInfo, { errors: err.details });
                context.showLicenseText = context.showLicenseText || !!(err.details && err.details.license);
                return h.view('config/license', context, {
                    layout: 'app'
                });
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

                    await request.flash({ type: 'danger', message: `Couldn't register license. Check the key and try again.` });
                    request.logger.warn({ msg: 'Failed to register license key', err });

                    let context = licensePageContext(request.app.licenseInfo, { errors });
                    context.showLicenseText = context.showLicenseText || !!errors.license;
                    return h
                        .view('config/license', context, {
                            layout: 'app'
                        })
                        .takeover();
                },

                payload: Joi.object({
                    license: Joi.string()
                        .max(10 * 1024)
                        .required()
                        .example('-----BEGIN LICENSE-----\r\n...')
                        .description('License file')
                }).label('RegisterLicense')
            }
        }
    });
}

function registerPostConfigLicenseDelete(server, args) {
    const { call } = args;

    server.route({
        method: 'POST',
        path: '/admin/config/license/delete',
        async handler(request, h) {
            try {
                const licenseInfo = await call({ cmd: 'removeLicense' });
                if (!licenseInfo) {
                    let err = new Error('Failed to clear license info');
                    err.statusCode = 403;
                    throw err;
                } else {
                    await request.flash({ type: 'info', message: `License removed` });
                }

                return h.redirect('/admin/config/license');
            } catch (err) {
                await request.flash({ type: 'danger', message: `Couldn't remove license. Try again.` });
                request.logger.error({ msg: 'Failed to unregister license key', err, remoteAddress: request.app.ip });
                return h.redirect('/admin/config/license');
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
                    await request.flash({ type: 'danger', message: `Couldn't remove license. Try again.` });
                    request.logger.error({ msg: 'Failed to unregister license key', err });

                    return h.redirect('/admin/config/license').takeover();
                },

                payload: Joi.object({})
            }
        }
    });
}

// The flash after "Check subscription now", by what the forced check reported
const RECHECK_MESSAGES = {
    ok: { type: 'success', message: 'Subscription checked: it is in good standing' },
    refused: { type: 'warning', message: 'Subscription checked: the payment is still overdue' },
    unreachable: { type: 'danger', message: 'Could not reach postalsys.com. Try again in a minute.' },
    error: { type: 'danger', message: 'postalsys.com could not check the subscription. Try again in a minute.' },
    throttled: { type: 'info', message: 'The subscription was checked less than a minute ago. Try again shortly.' },
    busy: { type: 'info', message: 'A subscription check is already running. Reload the page in a moment.' },
    skipped: { type: 'info', message: 'This license does not depend on a subscription.' }
};

function registerPostConfigLicenseRecheck(server, args) {
    const { call } = args;

    server.route({
        method: 'POST',
        path: '/admin/config/license/recheck',
        async handler(request, h) {
            try {
                let wasPaused = isSuspended(request.app.licenseInfo);
                let result = await call({ cmd: 'checkLicense', force: true });
                let flash = RECHECK_MESSAGES[result && result.checkOutcome] || RECHECK_MESSAGES.error;
                if (result && result.checkOutcome === 'ok' && wasPaused) {
                    flash = { type: 'success', message: 'Subscription in good standing: EmailEngine has resumed' };
                }
                await request.flash(flash);
            } catch (err) {
                await request.flash({ type: 'danger', message: `Couldn't check the subscription. Try again.` });
                request.logger.error({ msg: 'Failed to check the subscription', err });
            }
            return h.redirect('/admin/config/license');
        },
        options: {
            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                async failAction(request, h, err) {
                    await request.flash({ type: 'danger', message: `Couldn't check the subscription. Try again.` });
                    request.logger.error({ msg: 'Failed to check the subscription', err });

                    return h.redirect('/admin/config/license').takeover();
                },

                payload: Joi.object({})
            }
        }
    });
}

function registerPostConfigLicenseTrial(server, args) {
    const { call } = args;

    server.route({
        method: 'POST',
        path: '/admin/config/license/trial',
        async handler(request) {
            try {
                // provision new trial license

                let headers = {
                    'Content-Type': 'application/json',
                    'User-Agent': `${packageData.name}/${packageData.version} (+${packageData.homepage})`
                };

                let res = await fetchCmd(`${LICENSE_HOST}/licenses/trial`, {
                    method: 'post',
                    body: JSON.stringify({
                        version: packageData.version,
                        app: '@postalsys/emailengine-app',
                        hostname: os.hostname() || 'localhost',
                        url: (await settings.get('serviceUrl')) || ''
                    }),
                    headers,
                    dispatcher: httpAgent.retry
                });

                if (!res.ok) {
                    let err = new Error(res.statusText || `Invalid response: ${res.status} ${res.statusText}`);
                    err.statusCode = res.status;

                    try {
                        err.response = await res.json();
                    } catch (err) {
                        // ignore
                    }

                    throw err;
                }

                const data = await res.json();

                let licenseFile = `-----BEGIN LICENSE-----
${Buffer.from(data.content, 'base64url').toString('base64')}
-----END LICENSE-----`;

                const licenseInfo = await call({ cmd: 'updateLicense', license: licenseFile });
                if (!licenseInfo) {
                    let err = new Error('Failed to update license. Check license file contents.');
                    err.statusCode = 403;
                    err.details = { license: err.message };
                    throw err;
                }

                if (licenseInfo.active) {
                    await request.flash({ type: 'info', message: `Trial activated` });
                    return { success: true, message: `Trial activated` };
                }

                throw new Error('Failed to activate provisioned trial license');
            } catch (err) {
                request.logger.error({ msg: 'Failed to provision a trial license key', err, remoteAddress: request.app.ip });
                return { success: false, error: (err.response && err.response.error) || err.message };
            }
        },
        options: {
            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                failAction
            }
        }
    });
}

module.exports = (server, args) => {
    registerGetConfigLicense(server, args);
    registerPostConfigLicense(server, args);
    registerPostConfigLicenseDelete(server, args);
    registerPostConfigLicenseRecheck(server, args);
    registerPostConfigLicenseTrial(server, args);
};
