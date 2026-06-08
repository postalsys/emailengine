'use strict';

// Admin UI routes for the SMTP deliverability test tool (the "Send a test email" feature
// on an account page). Extracted verbatim from lib/routes-ui.js. These two endpoints call
// the external Nodemailer test service (api.nodemailer.com) to send a probe message and
// then fetch its DKIM/SPF analysis.

const Joi = require('joi');
const { fetch: fetchCmd } = require('undici');
const { Account } = require('../account');
const { redis } = require('../db');
const getSecret = require('../get-secret');
const { failAction, httpAgent } = require('../tools');
const { accountIdSchema } = require('../schemas');
const { REDIS_PREFIX } = require('../consts');
const packageData = require('../../package.json');

const SMTP_TEST_HOST = 'https://api.nodemailer.com';

function init(args) {
    const { server, call } = args;

    server.route({
        method: 'POST',
        path: '/admin/smtp/create-test',
        async handler(request) {
            let account = request.payload.account;

            try {
                request.logger.info({ msg: 'Request SMTP test', account });

                let accountObject = new Account({ redis, account, call, secret: await getSecret() });

                let accountData;
                try {
                    accountData = await accountObject.loadAccountData();
                } catch (err) {
                    return {
                        error: err.message
                    };
                }

                let headers = {
                    'Content-Type': 'application/json',
                    'User-Agent': `${packageData.name}/${packageData.version} (+${packageData.homepage})`
                };

                let res = await fetchCmd(`${SMTP_TEST_HOST}/test-address`, {
                    method: 'post',
                    body: JSON.stringify({
                        version: packageData.version,
                        requestor: '@postalsys/emailengine-app'
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

                let testAccount = await res.json();
                if (!testAccount || !testAccount.user) {
                    let err = new Error(`Invalid test account`);
                    err.status = 500;

                    try {
                        err.response = testAccount;
                    } catch (err) {
                        // ignore
                    }

                    throw err;
                }

                try {
                    let now = new Date().toISOString();
                    let queueResponse = await accountObject.queueMessage(
                        {
                            account: accountData.account,
                            subject: `Delivery test ${now}`,
                            text: `Hello

This is an automated email to test deliverability settings. If you see this email, you can safely delete it.

${now}`,
                            html: `<p>Hello</p>
<p>This is an automated email to test deliverability settings. If you see this email, you can safely delete it.</p>
<p>${now}</p>`,

                            from: {
                                name: accountData.name,
                                address: accountData.email
                            },
                            to: [{ name: 'Delivery Test Server', address: testAccount.address }],
                            copy: false,
                            gateway: request.payload.gateway,
                            feedbackKey: `${REDIS_PREFIX}test-send:${testAccount.user}`,
                            deliveryAttempts: 1
                        },
                        { source: 'test' }
                    );

                    return Object.assign(testAccount, queueResponse || {});
                } catch (err) {
                    return {
                        error: err.message
                    };
                }
            } catch (err) {
                request.logger.error({ msg: 'Failed to request test account', err, account });
                return { success: false, error: err.message };
            }
        },
        options: {
            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                failAction,

                payload: Joi.object({
                    account: accountIdSchema.required(),
                    gateway: Joi.string().empty('').max(256).example('sendgun').description('Gateway ID')
                })
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/smtp/check-test',
        async handler(request) {
            let user = request.payload.user;

            try {
                request.logger.info({ msg: 'Request SMTP test response', user });

                let deliveryStatus = (await redis.hgetall(`${REDIS_PREFIX}test-send:${user}`)) || {};
                if (deliveryStatus.success === 'false') {
                    let err = new Error(`Failed to deliver email: ${deliveryStatus.error}`);
                    err.status = 500;
                    throw err;
                }

                let headers = {
                    'Content-Type': 'application/json',
                    'User-Agent': `${packageData.name}/${packageData.version} (+${packageData.homepage})`
                };

                let res = await fetchCmd(`${SMTP_TEST_HOST}/test-address/${user}`, {
                    method: 'get',
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

                let testResponse = await res.json();

                if (testResponse) {
                    let mainSig =
                        testResponse.dkim &&
                        testResponse.dkim.results &&
                        testResponse.dkim.results.find(entry => entry && entry.status && entry.status.result === 'pass' && entry.status.aligned);

                    if (!mainSig) {
                        mainSig =
                            testResponse.dkim &&
                            testResponse.dkim.results &&
                            testResponse.dkim.results.find(entry => entry && entry.status && entry.status.result === 'pass');
                    }

                    if (!mainSig) {
                        mainSig = testResponse.dkim && testResponse.dkim.results && testResponse.dkim.results[0];
                    }

                    testResponse.mainSig = mainSig || {
                        status: {
                            result: 'none'
                        }
                    };

                    if (testResponse.spf && testResponse.spf.status && testResponse.spf.status.comment) {
                        testResponse.spf.status.comment = testResponse.spf.status.comment.replace(/^[^:\s]+:s*/, '');
                    }
                }

                return testResponse;
            } catch (err) {
                request.logger.error({ msg: 'Failed to request test response', err, user });
                return { status: 'error', error: err.message };
            }
        },
        options: {
            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                failAction,

                payload: Joi.object({
                    user: Joi.string().guid().description('Test ID')
                })
            }
        }
    });
}

module.exports = init;
