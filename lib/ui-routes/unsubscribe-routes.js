'use strict';

// Public (unauthenticated) subscription-management routes. These render the unsubscribe
// landing page reached from the List-Unsubscribe link in outgoing messages and process
// the subscribe/unsubscribe form submission. Extracted verbatim from lib/routes-ui.js.
// Both routes set `auth: false` and define their own validation failAction handlers.

const Joi = require('joi');
const Boom = require('@hapi/boom');
const { Account } = require('../account');
const { redis } = require('../db');
const { accountIdSchema } = require('../schemas');
const { REDIS_PREFIX } = require('../consts');

function init(args) {
    const { server, call } = args;

    server.route({
        method: 'GET',
        path: '/unsubscribe',
        async handler(request, h) {
            let data = Buffer.from(request.query.data, 'base64url').toString();
            // do not check signature, validate fields in the submit step

            data = JSON.parse(data);

            if (!data || typeof data !== 'object' || data.act !== 'unsub') {
                throw new Error(request.app.gt.gettext('Invalid input'));
            }

            // throws if account does not exist
            let accountObject = new Account({ redis, account: data.acc });
            await accountObject.loadAccountData();

            return h.view(
                'unsubscribe',
                {
                    pageTitleFull: request.app.gt.gettext('Subscription Management'),

                    unsubscribed: await redis.hexists(`${REDIS_PREFIX}lists:unsub:entries:${data.list}`, data.rcpt),
                    values: {
                        listId: data.list,
                        account: data.acc,
                        messageId: data.msg,
                        email: data.rcpt
                    }
                },
                {
                    layout: 'public'
                }
            );
        },
        options: {
            auth: false,

            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                async failAction(request, h, err) {
                    request.logger.error({ msg: 'Failed to validate request arguments', err });
                    let error = Boom.boomify(new Error(request.app.gt.gettext('Invalid request. Check your input and try again.')), { statusCode: 400 });
                    if (err.code) {
                        error.output.payload.code = err.code;
                    }
                    throw error;
                },

                query: Joi.object({
                    data: Joi.string().base64({ paddingRequired: false, urlSafe: true }).required(),
                    sig: Joi.string().base64({ paddingRequired: false, urlSafe: true })
                })
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/unsubscribe/address',
        async handler(request, h) {
            try {
                // throws if account does not exist
                let accountObject = new Account({ redis, account: request.payload.account });
                await accountObject.loadAccountData();

                let reSubscribed = false;

                switch (request.payload.action) {
                    case 'unsubscribe': {
                        let isNew = await redis.eeListAdd(
                            `${REDIS_PREFIX}lists:unsub:lists`,
                            `${REDIS_PREFIX}lists:unsub:entries:${request.payload.listId}`,
                            request.payload.listId,
                            request.payload.email.toLowerCase().trim(),
                            JSON.stringify({
                                recipient: request.payload.email,
                                account: request.payload.account,
                                source: 'form',
                                reason: 'unsubscribe',
                                messageId: request.payload.messageId,
                                remoteAddress: request.info.remoteAddress,
                                userAgent: request.headers['user-agent'],
                                created: new Date().toISOString()
                            })
                        );

                        if (isNew) {
                            await call({
                                cmd: 'unsubscribe',
                                account: request.payload.account,
                                payload: {
                                    recipient: request.payload.email,
                                    messageId: request.payload.messageId,
                                    listId: request.payload.listId,
                                    remoteAddress: request.info.remoteAddress,
                                    userAgent: request.headers['user-agent']
                                }
                            });
                        }
                        break;
                    }

                    case 'subscribe': {
                        let removed = await redis.eeListRemove(
                            `${REDIS_PREFIX}lists:unsub:lists`,
                            `${REDIS_PREFIX}lists:unsub:entries:${request.payload.listId}`,
                            request.payload.listId,
                            request.payload.email.toLowerCase().trim()
                        );

                        if (removed) {
                            await call({
                                cmd: 'subscribe',
                                account: request.payload.account,
                                payload: {
                                    recipient: request.payload.email,
                                    messageId: request.payload.messageId,
                                    listId: request.payload.listId,
                                    remoteAddress: request.info.remoteAddress,
                                    userAgent: request.headers['user-agent']
                                }
                            });
                        }

                        reSubscribed = true;
                        break;
                    }
                }

                return h.view(
                    'unsubscribe',
                    {
                        pageTitleFull: request.app.gt.gettext('Subscription Management'),

                        unsubscribed: await redis.hexists(`${REDIS_PREFIX}lists:unsub:entries:${request.payload.listId}`, request.payload.email),
                        values: request.payload,
                        reSubscribed
                    },
                    {
                        layout: 'public'
                    }
                );
            } catch (err) {
                await request.flash({ type: 'danger', message: request.app.gt.gettext("Couldn't process request. Try again.") });
                request.logger.error({ msg: 'Failed to process subscription request', err });

                return h.view(
                    'unsubscribe',
                    {
                        pageTitleFull: request.app.gt.gettext('Subscription Management'),
                        unsubscribed: await redis.hexists(`${REDIS_PREFIX}lists:unsub:entries:${request.payload.listId}`, request.payload.email)
                    },
                    {
                        layout: 'public'
                    }
                );
            }
        },
        options: {
            auth: false,
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

                    await request.flash({ type: 'danger', message: request.app.gt.gettext("Couldn't process request. Try again.") });
                    request.logger.error({ msg: 'Failed to process subscription request', err });

                    return h
                        .view(
                            'unsubscribe',
                            {
                                pageTitleFull: request.app.gt.gettext('Subscription Management'),
                                unsubscribed: await redis.hexists(`${REDIS_PREFIX}lists:unsub:entries:${request.payload.listId}`, request.payload.email),
                                errors
                            },
                            {
                                layout: 'public'
                            }
                        )
                        .takeover();
                },

                payload: Joi.object({
                    action: Joi.string().valid('subscribe', 'unsubscribe').required(),
                    account: accountIdSchema.required(),
                    listId: Joi.string().hostname().empty('').example('test-list').label('List ID').required(),
                    email: Joi.string().email().empty('').required().description('Email address').required(),
                    messageId: Joi.string().empty('').max(996).example('<test123@example.com>').description('Message ID')
                })
            }
        }
    });
}

module.exports = init;
