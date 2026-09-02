'use strict';

// Public (unauthenticated) subscription-management routes. These render the unsubscribe
// landing page reached from the List-Unsubscribe link in outgoing messages and process
// the subscribe/unsubscribe form submission. Extracted verbatim from lib/routes-ui.js.
// Both routes set `auth: false` and define their own validation failAction handlers.

const Joi = require('joi');
const Boom = require('@hapi/boom');
const { Account } = require('../account');
const { redis } = require('../db');
const { lists } = require('../lists');
const { parseSignedFormData } = require('../tools');
const { isClientError } = require('./route-helpers');
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
                // A validly signed blob of another type is the client's problem, not a server
                // failure - the same 400 the submit handler answers with
                throw Boom.boomify(new Error(request.app.gt.gettext('Invalid input')), { statusCode: 400 });
            }

            // throws if account does not exist
            let accountObject = new Account({ redis, account: data.acc });
            await accountObject.loadAccountData();

            return h.view(
                'unsubscribe',
                {
                    pageTitleFull: request.app.gt.gettext('Subscription Management'),

                    unsubscribed: await lists.has(data.list, data.rcpt),
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
                    request.logger.debug({ msg: 'Failed to validate request arguments', err });
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
            // Declared outside the try so the error branch can re-render the form for a request
            // whose signature did verify and only failed later
            let signed;
            try {
                // Verify the signature and read account/list/recipient from the SIGNED payload -
                // never from client-supplied fields - so subscribe/unsubscribe cannot be forged (M7).
                signed = await parseSignedFormData(redis, { data: request.payload.data, sig: request.payload.sig }, request.app.gt);

                if (!signed || typeof signed !== 'object' || signed.act !== 'unsub') {
                    signed = null;
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
                        request.logger.error({ msg: 'Failed to dispatch list event', event: cmd, account, listId, err });
                    }
                };

                switch (request.payload.action) {
                    case 'unsubscribe': {
                        let isNew = await lists.add(listId, email, {
                            account,
                            source: 'form',
                            reason: 'unsubscribe',
                            messageId,
                            remoteAddress: request.info.remoteAddress,
                            userAgent: request.headers['user-agent']
                        });

                        if (isNew) {
                            await dispatchListEvent('unsubscribe');
                        }
                        break;
                    }

                    case 'subscribe': {
                        let removed = await lists.remove(listId, email);

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

                        unsubscribed: await lists.has(listId, email),
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
                // Boom 4xx (bad signature, unknown account) is client-caused traffic on a public
                // endpoint, not a server failure
                request.logger[isClientError(err) ? 'debug' : 'error']({ msg: 'Failed to process subscription request', err });

                // With a verified signature the form comes back filled in so the person can retry;
                // without one there is nothing trustworthy to show, and the view renders its
                // invalid-link state instead of an empty form
                return h.view(
                    'unsubscribe',
                    {
                        pageTitleFull: request.app.gt.gettext('Subscription Management'),
                        values: signed
                            ? {
                                  listId: signed.list,
                                  account: signed.acc,
                                  messageId: signed.msg,
                                  email: signed.rcpt,
                                  data: request.payload.data,
                                  sig: request.payload.sig
                              }
                            : {}
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
                    request.logger.debug({ msg: 'Failed to process subscription request', err });

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
