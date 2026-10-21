'use strict';

const Boom = require('@hapi/boom');
const Joi = require('joi');
const { redis } = require('../db');
const { Account } = require('../account');
const getSecret = require('../get-secret');
const { failAction } = require('../tools');
const { handleError, logApiError } = require('./route-helpers');
const { accountIdSchema, mailboxesSchema, apiResponses, apiBoolean } = require('../schemas');
const { IMPACT } = require('./operation-impact');
const { FIELD_USAGE } = require('../field-usage');

// The create and modify routes publish err.info as `details`, which is the field their documented
// error schema declares, while the shared handleError publishes it as `info`. They keep their own
// envelope rather than fork the logging policy, so routing them through handleError would silently
// rename a published response field. Always throws, like handleError.
function throwMailboxError(request, err) {
    let statusCode = logApiError(request, err);

    if (Boom.isBoom(err)) {
        throw err;
    }

    let error = Boom.boomify(err, { statusCode });
    if (err.code) {
        error.output.payload.code = err.code;
    }
    if (err.info) {
        error.output.payload.details = err.info;
    }
    throw error;
}

function registerListMailboxes(server, args) {
    const { call, CORS_CONFIG, FLAG_SORT_ORDER } = args;

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
            notes: 'Lists every folder of the account with its path, special-use flag and subscription state, and optionally its message counters.',
            tags: ['api', 'Mailbox'],

            plugins: {
                mcp: {
                    name: 'list_mailboxes',
                    title: 'List mailboxes',
                    description:
                        'List the folders of an account with message counts and special-use roles (Inbox, Sent, Trash and so on). Folder paths from here are what list_messages, search_messages and move_message take.'
                },
                openapi: {
                    responses: apiResponses(
                        'Returns the account folder tree, including special-use designations and message counts.',
                        400,
                        401,
                        403,
                        404,
                        429,
                        500,
                        503
                    )
                }
            },

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
                    counters: apiBoolean().default(false).description('If true, then includes message counters in the response').label('MailboxCounters')
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
}

function registerCreateMailbox(server, args) {
    const { call, CORS_CONFIG } = args;

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
                throwMailboxError(request, err);
            }
        },

        options: {
            description: 'Create mailbox',
            notes: 'Creates a folder at the given path, a missing parent folder included. The path can be given as a list of names, which the server joins with its own separator.',
            tags: ['api', 'Mailbox'],

            plugins: {
                mcp: {
                    name: 'create_mailbox',
                    title: 'Create mailbox',
                    description:
                        'Create a folder. Give the path as a list of names from the top level down (["Projects", "2026"]) so the server joins them with its own separator; a missing parent is created too. The response carries the full path that list_messages and move_message take.'
                },
                openapi: {
                    responses: apiResponses('Returns the created folder and its path.', 400, 401, 403, 404, 429, 500, 503)
                }
            },

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
                        .required()
                        .example(['Parent folder', 'Subfolder'])
                        .description('Mailbox path as an array or a string. If account is namespaced then namespace prefix is added by default.')
                        .label('CreateMailboxPathInput')
                }).label('CreateMailbox')
            },

            response: {
                schema: Joi.object({
                    path: Joi.string().required().example('Kalender/S&APw-nnip&AOQ-evad').description('Full path to mailbox').label('CreatedMailboxPath'),
                    mailboxId: Joi.string().example('1439876283476').description('Mailbox ID (if server has support)').label('MailboxId'),
                    created: Joi.boolean().example(true).description('Was the mailbox created')
                }).label('CreateMailboxResponse'),
                failAction: 'log'
            }
        }
    });
}

function registerModifyMailbox(server, args) {
    const { call, CORS_CONFIG } = args;

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
                throwMailboxError(request, err);
            }
        },

        options: {
            description: 'Modify mailbox',
            notes: 'Modify an existing mailbox folder (rename or change subscription status)',
            tags: ['api', 'Mailbox'],

            plugins: {
                mcp: {
                    name: 'update_mailbox',
                    title: 'Rename or update mailbox',
                    description:
                        'Rename or move a folder (newPath, as a list of names from the top level down), or change whether it is subscribed. `path` is the current path from list_mailboxes. The messages move with the folder; list them again under the new path for their current ids.'
                },
                openapi: {
                    responses: apiResponses('Returns the renamed folder with its old and new paths.', 400, 401, 403, 404, 429, 500, 503)
                }
            },

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
                        .description('Change mailbox subscription status')
                        .meta({ usage: FIELD_USAGE.mailboxSubscribed })
                        .label('SubscriptionStatus')
                })
                    .or('newPath', 'subscribed')
                    .label('ModifyMailbox')
            },

            response: {
                schema: Joi.object({
                    path: Joi.string().example('Mail').description('Mailbox folder path').label('ExistingMailboxPath'),
                    newPath: Joi.string().example('Kalender/S&APw-nnip&AOQ-evad').description('Full path to mailbox if renamed').label('NewMailboxPath'),
                    mailboxId: Joi.string()
                        .example('1439876283476')
                        .description('Mailbox ID after the rename (Gmail API and MS Graph API accounts only)')
                        .label('ModifyMailboxId'),
                    renamed: Joi.boolean().example(true).description('Was the mailbox renamed'),
                    subscribed: Joi.boolean().example(true).description('Subscription status after modification')
                }).label('ModifyMailboxResponse'),
                failAction: 'log'
            }
        }
    });
}

function registerDeleteMailbox(server, args) {
    const { call, CORS_CONFIG } = args;

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
                // A delete the IMAP server refuses surfaces the same way a refused create or
                // rename does (code plus details), not through the generic handler's info shape
                throwMailboxError(request, err);
            }
        },

        options: {
            description: 'Delete mailbox',
            notes: 'Deletes a folder together with every message in it.',
            tags: ['api', 'Mailbox'],

            plugins: {
                mcp: {
                    name: 'delete_mailbox',
                    title: 'Delete mailbox',
                    description:
                        'Delete a folder by its path from list_mailboxes - confirm with the user before calling this. On an IMAP account the folder goes with every message in it, and nothing is kept in Trash. On a Gmail API account the label is removed and the messages stay in the mailbox under their other labels.'
                },
                openapi: {
                    'x-ee-impact': IMPACT.DESTRUCTIVE,
                    responses: apiResponses('Returns the deleted folder path.', 400, 401, 403, 404, 429, 500, 503)
                }
            },

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
                    mailboxId: Joi.string()
                        .example('1439876283476')
                        .description('ID of the deleted mailbox (Gmail API and MS Graph API accounts only)')
                        .label('DeleteMailboxId'),
                    deleted: Joi.boolean().example(true).description('Was the mailbox deleted')
                }).label('DeleteMailboxResponse'),
                failAction: 'log'
            }
        }
    });
}

async function init(args) {
    const { server } = args;

    registerListMailboxes(server, args);
    registerCreateMailbox(server, args);
    registerModifyMailbox(server, args);
    registerDeleteMailbox(server, args);
}

module.exports = init;
