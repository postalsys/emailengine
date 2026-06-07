'use strict';

const Boom = require('@hapi/boom');
const Joi = require('joi');
const { redis } = require('../db');
const { Account } = require('../account');
const getSecret = require('../get-secret');
const { failAction } = require('../tools');
const { handleError } = require('./route-helpers');
const { accountIdSchema, mailboxesSchema } = require('../schemas');

async function init(args) {
    const { server, call, CORS_CONFIG, FLAG_SORT_ORDER } = args;

    server.route({
        method: 'GET',
        path: '/v1/account/{account}/mailboxes',

        async handler(request) {
            let accountObject = new Account({
                redis,
                account: request.params.account,
                call,
                secret: await getSecret(),
                timeout: request.headers['x-ee-timeout']
            });

            try {
                let mailboxes = await accountObject.getMailboxListing(request.query);

                if (mailboxes && Array.isArray(mailboxes)) {
                    mailboxes = mailboxes.sort((a, b) => {
                        if (a.specialUse && !b.specialUse) {
                            return -1;
                        }
                        if (!a.specialUse && b.specialUse) {
                            return 1;
                        }
                        if (a.specialUse && b.specialUse) {
                            return FLAG_SORT_ORDER.indexOf(a.specialUse) - FLAG_SORT_ORDER.indexOf(b.specialUse);
                        }

                        return a.path.localeCompare(b.path);
                    });
                }

                return { mailboxes };
            } catch (err) {
                handleError(request, err);
            }
        },

        options: {
            description: 'List mailboxes',
            notes: 'Lists all available mailboxes',
            tags: ['api', 'Mailbox'],

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

                query: Joi.object({
                    counters: Joi.boolean()
                        .truthy('Y', 'true', '1')
                        .falsy('N', 'false', 0)
                        .default(false)
                        .description('If true, then includes message counters in the response')
                        .label('MailboxCounters')
                }).label('MailboxListQuery')
            },

            response: {
                schema: Joi.object({
                    mailboxes: mailboxesSchema
                }).label('MailboxesFilterResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/v1/account/{account}/mailbox',

        async handler(request) {
            let accountObject = new Account({
                redis,
                account: request.params.account,
                call,
                secret: await getSecret(),
                timeout: request.headers['x-ee-timeout']
            });

            try {
                return await accountObject.createMailbox(request.payload.path);
            } catch (err) {
                request.logger.error({ msg: 'API request failed', err });
                if (Boom.isBoom(err)) {
                    throw err;
                }
                let error = Boom.boomify(err, { statusCode: err.statusCode || 500 });
                if (err.code) {
                    error.output.payload.code = err.code;
                }
                if (err.info) {
                    error.output.payload.details = err.info;
                }
                throw error;
            }
        },

        options: {
            description: 'Create mailbox',
            notes: 'Create new mailbox folder',
            tags: ['api', 'Mailbox'],

            plugins: {},

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
                    path: Joi.array()
                        .items(Joi.string().max(256))
                        .single()
                        .example(['Parent folder', 'Subfolder'])
                        .description('Mailbox path as an array or a string. If account is namespaced then namespace prefix is added by default.')
                        .label('MailboxPath')
                }).label('CreateMailbox')
            },

            response: {
                schema: Joi.object({
                    path: Joi.string().required().example('Kalender/S&APw-nnip&AOQ-evad').description('Full path to mailbox').label('MailboxPath'),
                    mailboxId: Joi.string().example('1439876283476').description('Mailbox ID (if server has support)').label('MailboxId'),
                    created: Joi.boolean().example(true).description('Was the mailbox created')
                }).label('CreateMailboxResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'PUT',
        path: '/v1/account/{account}/mailbox',

        async handler(request) {
            let accountObject = new Account({
                redis,
                account: request.params.account,
                call,
                secret: await getSecret(),
                timeout: request.headers['x-ee-timeout']
            });

            try {
                return await accountObject.modifyMailbox(request.payload.path, request.payload.newPath, request.payload.subscribed);
            } catch (err) {
                request.logger.error({ msg: 'API request failed', err });
                if (Boom.isBoom(err)) {
                    throw err;
                }
                let error = Boom.boomify(err, { statusCode: err.statusCode || 500 });
                if (err.code) {
                    error.output.payload.code = err.code;
                }
                if (err.info) {
                    error.output.payload.details = err.info;
                }
                throw error;
            }
        },

        options: {
            description: 'Modify mailbox',
            notes: 'Modify an existing mailbox folder (rename or change subscription status)',
            tags: ['api', 'Mailbox'],

            plugins: {},

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
                    path: Joi.string().required().example('Folder Name').description('Mailbox folder path to modify').label('ExistingMailboxPath'),
                    newPath: Joi.array()
                        .items(Joi.string().max(256))
                        .single()
                        .example(['Parent folder', 'Subfolder'])
                        .description('New mailbox path as an array or a string. If account is namespaced then namespace prefix is added by default. Optional.')
                        .label('TargetMailboxPath'),
                    subscribed: Joi.boolean()
                        .example(true)
                        .description('Change mailbox subscription status. Only applies to IMAP accounts, ignored for Gmail and Outlook.')
                        .label('SubscriptionStatus')
                })
                    .or('newPath', 'subscribed')
                    .label('ModifyMailbox')
            },

            response: {
                schema: Joi.object({
                    path: Joi.string().required().example('Mail').description('Mailbox folder path').label('ExistingMailboxPath'),
                    newPath: Joi.string().example('Kalender/S&APw-nnip&AOQ-evad').description('Full path to mailbox if renamed').label('NewMailboxPath'),
                    renamed: Joi.boolean().example(true).description('Was the mailbox renamed'),
                    subscribed: Joi.boolean().example(true).description('Subscription status after modification')
                }).label('ModifyMailboxResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'DELETE',
        path: '/v1/account/{account}/mailbox',

        async handler(request) {
            let accountObject = new Account({
                redis,
                account: request.params.account,
                call,
                secret: await getSecret(),
                timeout: request.headers['x-ee-timeout']
            });

            try {
                return await accountObject.deleteMailbox(request.query.path);
            } catch (err) {
                handleError(request, err);
            }
        },

        options: {
            description: 'Delete mailbox',
            notes: 'Delete existing mailbox folder',
            tags: ['api', 'Mailbox'],

            plugins: {},

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

                query: Joi.object({
                    path: Joi.string().required().example('My Outdated Mail').description('Mailbox folder path to delete').label('MailboxPath')
                }).label('DeleteMailbox')
            },

            response: {
                schema: Joi.object({
                    path: Joi.string().required().example('Kalender/S&APw-nnip&AOQ-evad').description('Full path to mailbox').label('MailboxPath'),
                    deleted: Joi.boolean().example(true).description('Was the mailbox deleted')
                }).label('DeleteMailboxResponse'),
                failAction: 'log'
            }
        }
    });
}

module.exports = init;
