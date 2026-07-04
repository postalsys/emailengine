'use strict';

// Public (unauthenticated) subscription-management routes. These render the unsubscribe
// landing page reached from the List-Unsubscribe link in outgoing messages and process
// the subscribe/unsubscribe form submission. Extracted verbatim from lib/routes-ui.js.
// Both routes set `auth: false` and define their own validation failAction handlers.

const Joi = require('joi');
const Boom = require('@hapi/boom');
const { Account } = require('../account');
const { redis } = require('../db');
const { REDIS_PREFIX } = require('../consts');
const { parseSignedFormData } = require('../tools');
const { signedFormBlobFields } = require('../schemas');

function init(args) {
    const { server, call } = args;

    server.route({
        method: 'GET',
        path: '/unsubscribe',
        async handler(request, h) {
            // Verify the HMAC signature over the signed payload before acting on it, and read every
            // field from the signed data - never from unsigned query input (security review M7).
            let data = await parseSignedFormData(redis, { data: request.query.data, sig: request.query.sig }, request.app.gt);

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
                        email: data.rcpt,
                        // carry the signed payload through so the submit step can re-verify it (M7)
                        data: request.query.data,
                        sig: request.query.sig
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
                    ...signedFormBlobFields
                })
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/unsubscribe/address',
        async handler(request, h) {
            try {
                // Verify the signature and read account/list/recipient from the SIGNED payload -
                // never from client-supplied fields - so subscribe/unsubscribe cannot be forged (M7).
                let signed = await parseSignedFormData(redis, { data: request.payload.data, sig: request.payload.sig }, request.app.gt);

                if (!signed || typeof signed !== 'object' || signed.act !== 'unsub') {
                    throw Boom.boomify(new Error(request.app.gt.gettext('Invalid input')), { statusCode: 400 });
                }

                let account = signed.acc;
                let listId = signed.list;
                let email = signed.rcpt;
                let messageId = signed.msg;

                // throws if account does not exist
                let accountObject = new Account({ redis, account });
                await accountObject.loadAccountData();

                let reSubscribed = false;

                // Best-effort notify: the list state (eeListAdd/eeListRemove) is already committed, so a
                // failed dispatch must not fail the request. The outer catch would show a generic error and
                // the idempotent retry returns isNew/removed=false, so the event would be lost forever. Log
                // and continue (mirrors the one-click endpoint in workers/api.js).
                const dispatchListEvent = async cmd => {
                    try {
                        await call({
                            cmd,
                            account,
                            payload: {
                                recipient: email,
                                messageId,
                                listId,
                                remoteAddress: request.info.remoteAddress,
                                userAgent: request.headers['user-agent']
                            }
                        });
                    } catch (err) {
                        request.logger.error({ msg: `Failed to dispatch ${cmd} event`, account, listId, err });
                    }
                };

                switch (request.payload.action) {
                    case 'unsubscribe': {
                        let isNew = await redis.eeListAdd(
                            `${REDIS_PREFIX}lists:unsub:lists`,
                            `${REDIS_PREFIX}lists:unsub:entries:${listId}`,
                            listId,
                            email.toLowerCase().trim(),
                            JSON.stringify({
                                recipient: email,
                                account,
                                source: 'form',
                                reason: 'unsubscribe',
                                messageId,
                                remoteAddress: request.info.remoteAddress,
                                userAgent: request.headers['user-agent'],
                                created: new Date().toISOString()
                            })
                        );

                        if (isNew) {
                            await dispatchListEvent('unsubscribe');
                        }
                        break;
                    }

                    case 'subscribe': {
                        let removed = await redis.eeListRemove(
                            `${REDIS_PREFIX}lists:unsub:lists`,
                            `${REDIS_PREFIX}lists:unsub:entries:${listId}`,
                            listId,
                            email.toLowerCase().trim()
                        );

                        if (removed) {
                            await dispatchListEvent('subscribe');
                        }

                        reSubscribed = true;
                        break;
                    }
                }

                return h.view(
                    'unsubscribe',
                    {
                        pageTitleFull: request.app.gt.gettext('Subscription Management'),

                        unsubscribed: await redis.hexists(`${REDIS_PREFIX}lists:unsub:entries:${listId}`, email),
                        values: {
                            listId,
                            account,
                            messageId,
                            email,
                            // carry the signed payload through for the re-subscribe form (M7)
                            data: request.payload.data,
                            sig: request.payload.sig
                        },
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
                        pageTitleFull: request.app.gt.gettext('Subscription Management')
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
                    ...signedFormBlobFields
                })
            }
        }
    });
}

module.exports = init;
