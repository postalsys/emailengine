'use strict';

const Boom = require('@hapi/boom');
const Joi = require('joi');
const { fetch: fetchCmd } = require('undici');
const { redis } = require('../db');
const { Account } = require('../account');
const { Gateway } = require('../gateway');
const getSecret = require('../get-secret');
const { failAction, httpAgent } = require('../tools');
const { accountIdSchema } = require('../schemas');
const { REDIS_PREFIX } = require('../consts');
const packageData = require('../../package.json');

async function init(args) {
    const { server, call, CORS_CONFIG, SMTP_TEST_HOST } = args;

    server.route({
        method: 'POST',
        path: '/v1/delivery-test/account/{account}',
        async handler(request) {
            let accountObject = new Account({
                redis,
                account: request.params.account,
                call,
                secret: await getSecret(),
                timeout: request.headers['x-ee-timeout']
            });

            try {
                // throws if account does not exist
                let accountData = await accountObject.loadAccountData();

                request.logger.info({ msg: 'Requested SMTP delivery test', account: request.params.account });

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
                    let err = new Error(`Invalid response: ${res.status} ${res.statusText}`);
                    err.statusCode = res.status;

                    try {
                        err.details = await res.json();
                    } catch (err) {
                        // ignore
                    }

                    throw err;
                }

                let testAccount = await res.json();
                if (!testAccount || !testAccount.user) {
                    let err = new Error(`Invalid test account`);
                    err.statusCode = 500;

                    try {
                        err.details = testAccount;
                    } catch (err) {
                        // ignore
                    }

                    throw err;
                }

                if (request.payload.gateway) {
                    // try to load the gateway, throws if not set
                    let gatewayObject = new Gateway({ redis, gateway: request.payload.gateway, call, secret: await getSecret() });
                    await gatewayObject.loadGatewayData();
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

                    return {
                        success: !!queueResponse.queueId,
                        deliveryTest: testAccount.user
                    };
                } catch (err) {
                    return {
                        error: err.message
                    };
                }
            } catch (err) {
                request.logger.error({ msg: 'API request failed', err });
                if (Boom.isBoom(err)) {
                    throw err;
                }
                let error = Boom.boomify(err, { statusCode: err.statusCode || 500 });
                if (err.code) {
                    error.output.payload.code = err.code;
                }
                if (err.details) {
                    error.output.payload.details = err.details;
                }
                throw error;
            }
        },
        options: {
            description: 'Create delivery test',
            notes: 'Initiate a delivery test',
            tags: ['api', 'Delivery Test'],

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },
            cors: CORS_CONFIG,

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                params: Joi.object({
                    account: accountIdSchema.required()
                }),

                payload: Joi.object({
                    gateway: Joi.string().allow(false, null).empty('').max(256).example(false).description('Optional gateway ID').label('DeliveryTestGateway')
                }).label('DeliveryStartRequest')
            },

            response: {
                schema: Joi.object({
                    success: Joi.boolean()
                        .example(true)
                        .description('Was the test started. Not present if queueing the test message failed')
                        .label('ResponseDeliveryStartSuccess'),
                    deliveryTest: Joi.string()
                        .guid({
                            version: ['uuidv4', 'uuidv5']
                        })
                        .example('6420a6ad-7f82-4e4f-8112-82a9dad1f34d')
                        .description('Test ID. Not present if queueing the test message failed'),
                    error: Joi.string()
                        .example('Oops, something went wrong')
                        .description('Error message. Only present if queueing the test message failed - in that case success and deliveryTest are not set')
                        .label('ResponseDeliveryStartError')
                }).label('DeliveryStartResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/v1/delivery-test/check/{deliveryTest}',
        async handler(request) {
            try {
                request.logger.info({ msg: 'Requested SMTP delivery test check', deliveryTest: request.params.deliveryTest });

                let deliveryStatus = (await redis.hgetall(`${REDIS_PREFIX}test-send:${request.params.deliveryTest}`)) || {};
                if (deliveryStatus.success === 'false') {
                    let err = new Error(`Failed to deliver email`);
                    err.statusCode = 500;
                    err.details = deliveryStatus;
                    throw err;
                }

                let headers = {
                    'Content-Type': 'application/json',
                    'User-Agent': `${packageData.name}/${packageData.version} (+${packageData.homepage})`
                };

                let res = await fetchCmd(`${SMTP_TEST_HOST}/test-address/${request.params.deliveryTest}`, {
                    method: 'get',
                    headers,
                    dispatcher: httpAgent.retry
                });

                if (!res.ok) {
                    let err = new Error(`Invalid response: ${res.status} ${res.statusText}`);
                    err.statusCode = res.status;

                    try {
                        err.details = await res.json();
                    } catch (err) {
                        // ignore
                    }

                    throw err;
                }

                let testResponse = await res.json();

                let success = testResponse && testResponse.status === 'success'; //Default

                if (testResponse && success) {
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
                        testResponse.spf.status.comment = testResponse.spf.status.comment.replace(/^[^:\s]+:\s*/, '');
                    }
                }

                if (testResponse) {
                    if (testResponse.status === 'success') {
                        delete testResponse.status;
                    }
                    delete testResponse.user;
                }

                return Object.assign({ success }, testResponse || {});
            } catch (err) {
                request.logger.error({ msg: 'API request failed', err });
                if (Boom.isBoom(err)) {
                    throw err;
                }
                let error = Boom.boomify(err, { statusCode: err.statusCode || 500 });
                if (err.code) {
                    error.output.payload.code = err.code;
                }
                if (err.details) {
                    error.output.payload.details = err.details;
                }
                throw error;
            }
        },
        options: {
            description: 'Check test status',
            notes: 'Check delivery test status',
            tags: ['api', 'Delivery Test'],

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },
            cors: CORS_CONFIG,

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                params: Joi.object({
                    deliveryTest: Joi.string()
                        .guid({
                            version: ['uuidv4', 'uuidv5']
                        })
                        .example('6420a6ad-7f82-4e4f-8112-82a9dad1f34d')
                        .required()
                        .description('Test ID')
                }).label('DeliveryCheckParams')
            },

            response: {
                schema: Joi.object({
                    success: Joi.boolean().example(true).description('Was the test completed').label('ResponseDeliveryCheckSuccess'),
                    status: Joi.string()
                        .example('pending')
                        .description('Test status. Only present while the test message has not yet been received (success=false)')
                        .label('ResponseDeliveryCheckStatus'),
                    dkim: Joi.object().unknown().description('DKIM results').label('DkimResults'),
                    spf: Joi.object().unknown().description('SPF results').label('SpfResults'),
                    dmarc: Joi.object().unknown().description('DMARC results').label('DmarcResults'),
                    bimi: Joi.object().unknown().description('BIMI results').label('BimiResults'),
                    arc: Joi.object().unknown().description('ARC results').label('ArcResults'),
                    mainSig: Joi.object()
                        .unknown()
                        .description('Primary DKIM signature. `status.aligned` should be set, otherwise DKIM check should not be considered as passed.')
                        .label('MainSignature')
                })
                    .unknown()
                    .label('DeliveryCheckResponse'),
                failAction: 'log'
            }
        }
    });
}

module.exports = init;
