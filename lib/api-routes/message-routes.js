'use strict';

const { redis } = require('../db');
const { Account } = require('../account');
const getSecret = require('../get-secret');
const settings = require('../settings');
const Boom = require('@hapi/boom');
const Joi = require('joi');
const { failAction } = require('../tools');

const {
    accountIdSchema,
    messageDetailsSchema,
    messageListSchema,
    documentStoreSchema,
    searchSchema,
    messageUpdateSchema,
    addressSchema,
    fromAddressSchema,
    messageReferenceSchema
} = require('../schemas');

const listMessageFolderPathDescription =
    'Mailbox folder path. Can use special use labels like "\\Sent". Special value "\\All" is available for Gmail IMAP, Gmail API, MS Graph API accounts.';

async function init(args) {
    const { server, call, CORS_CONFIG, MAX_ATTACHMENT_SIZE, MAX_BODY_SIZE, MAX_PAYLOAD_TIMEOUT } = args;

    // GET /v1/account/{account}/message/{message}/source - Download raw message
    server.route({
        method: 'GET',
        path: '/v1/account/{account}/message/{message}/source',

        async handler(request, h) {
            let accountObject = new Account({
                redis,
                account: request.params.account,
                call,
                secret: await getSecret(),
                timeout: request.headers['x-ee-timeout']
            });

            try {
                const response = await accountObject.getRawMessage(request.params.message);
                return h.response(response);
            } catch (err) {
                request.logger.error({ msg: 'API request failed', err });
                if (Boom.isBoom(err)) {
                    throw err;
                }
                let error = Boom.boomify(err, { statusCode: err.statusCode || 500 });
                if (err.code) {
                    error.output.payload.code = err.code;
                }
                throw error;
            }
        },
        options: {
            description: 'Download raw message',
            notes: 'Fetches raw message as a stream',
            tags: ['api', 'Message'],

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },
            cors: CORS_CONFIG,

            plugins: {
                'hapi-swagger': {
                    produces: ['message/rfc822']
                }
            },

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                params: Joi.object({
                    account: accountIdSchema.required(),
                    message: Joi.string().base64({ paddingRequired: false, urlSafe: true }).max(256).example('AAAAAQAACnA').required().description('Message ID')
                }).label('RawMessageRequest')
            }
        }
    });

    // GET /v1/account/{account}/message/{message} - Get message information
    server.route({
        method: 'GET',
        path: '/v1/account/{account}/message/{message}',

        async handler(request, h) {
            let accountObject = new Account({
                redis,
                account: request.params.account,
                call,
                secret: await getSecret(),
                esClient: await h.getESClient(request.logger),
                timeout: request.headers['x-ee-timeout']
            });

            try {
                return await accountObject.getMessage(request.params.message, request.query);
            } catch (err) {
                request.logger.error({ msg: 'API request failed', err });
                if (Boom.isBoom(err)) {
                    throw err;
                }
                let error = Boom.boomify(err, { statusCode: err.statusCode || 500 });
                if (err.code) {
                    error.output.payload.code = err.code;
                }
                throw error;
            }
        },
        options: {
            description: 'Get message information',
            notes: 'Returns details of a specific message. By default text content is not included, use textType value to force retrieving text',
            tags: ['api', 'Message'],

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

                query: Joi.object({
                    maxBytes: Joi.number()
                        .integer()
                        .min(0)
                        .max(1024 * 1024 * 1024)
                        .example(5 * 1025 * 1024)
                        .description('Max length of text content'),
                    textType: Joi.string()
                        .lowercase()
                        .valid('html', 'plain', '*')
                        .example('*')
                        .description('Which text content to return, use * for all. By default text content is not returned.'),

                    webSafeHtml: Joi.boolean()
                        .truthy('Y', 'true', '1')
                        .falsy('N', 'false', 0)
                        .default(false)
                        .description(
                            'Shorthand option to fetch and preprocess HTML and inline images. Overrides `textType`, `preProcessHtml`, and `embedAttachedImages` options.'
                        )
                        .label('WebSafeHtml'),

                    embedAttachedImages: Joi.boolean()
                        .truthy('Y', 'true', '1')
                        .falsy('N', 'false', 0)
                        .default(false)
                        .description('If true, then fetches attached images and embeds these in the HTML as data URIs')
                        .label('EmbedImages'),

                    preProcessHtml: Joi.boolean()
                        .truthy('Y', 'true', '1')
                        .falsy('N', 'false', 0)
                        .default(false)
                        .description('If true, then pre-processes HTML for compatibility')
                        .label('PreProcess'),

                    markAsSeen: Joi.boolean()
                        .truthy('Y', 'true', '1')
                        .falsy('N', 'false', 0)
                        .default(false)
                        .description('If true, then marks unseen email as seen while returning the message')
                        .label('MarkAsSeen'),

                    documentStore: documentStoreSchema.default(false)
                }),

                params: Joi.object({
                    account: accountIdSchema.required(),
                    message: Joi.string().base64({ paddingRequired: false, urlSafe: true }).max(256).required().example('AAAAAQAACnA').description('Message ID')
                })
            },

            response: {
                schema: messageDetailsSchema,
                failAction: 'log'
            }
        }
    });

    // POST /v1/account/{account}/message - Upload message
    server.route({
        method: 'POST',
        path: '/v1/account/{account}/message',

        async handler(request) {
            let accountObject = new Account({
                redis,
                account: request.params.account,
                call,
                secret: await getSecret(),
                timeout: request.headers['x-ee-timeout']
            });

            try {
                return await accountObject.uploadMessage(request.payload);
            } catch (err) {
                request.logger.error({ msg: 'API request failed', err });
                if (Boom.isBoom(err)) {
                    throw err;
                }
                let error = Boom.boomify(err, { statusCode: err.statusCode || 500 });
                if (err.code) {
                    error.output.payload.code = err.code;
                }
                throw error;
            }
        },
        options: {
            payload: {
                maxBytes: MAX_BODY_SIZE,
                timeout: MAX_PAYLOAD_TIMEOUT
            },

            description: 'Upload message',
            notes: 'Upload a message structure, compile it into an EML file and store it into selected mailbox.',
            tags: ['api', 'Message'],

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
                    path: Joi.string().required().example('INBOX').description('Target mailbox folder path'),

                    flags: Joi.array().items(Joi.string().max(128)).example(['\\Seen', '\\Draft']).default([]).description('Message flags').label('Flags'),
                    internalDate: Joi.date().iso().example('2021-07-08T07:06:34.336Z').description('Sets the internal date for this message'),

                    reference: messageReferenceSchema,

                    raw: Joi.string()
                        .base64()
                        .max(MAX_ATTACHMENT_SIZE)
                        .example('TUlNRS1WZXJzaW9uOiAxLjANClN1YmplY3Q6IGhlbGxvIHdvcmxkDQoNCkhlbGxvIQ0K')
                        .description(
                            'A Base64-encoded email message in RFC 822 format. If you provide other fields along with raw, those fields will override the corresponding values in the raw message.'
                        )
                        .label('RFC822Raw'),

                    from: fromAddressSchema,

                    to: Joi.array()
                        .items(addressSchema)
                        .single()
                        .description('List of addresses')
                        .example([{ address: 'recipient@example.com' }])
                        .label('AddressList'),

                    cc: Joi.array().items(addressSchema).single().description('List of addresses').label('AddressList'),

                    bcc: Joi.array().items(addressSchema).single().description('List of addresses').label('AddressList'),

                    subject: Joi.string()
                        .allow('')
                        .max(10 * 1024)
                        .example('What a wonderful message')
                        .description('Message subject'),

                    text: Joi.string().max(MAX_ATTACHMENT_SIZE).example('Hello from myself!').description('Message Text'),

                    html: Joi.string().max(MAX_ATTACHMENT_SIZE).example('<p>Hello from myself!</p>').description('Message HTML'),

                    attachments: Joi.array()
                        .items(
                            Joi.object({
                                filename: Joi.string().max(256).example('transparent.gif'),
                                content: Joi.string()
                                    .base64()
                                    .max(MAX_ATTACHMENT_SIZE)
                                    .required()
                                    .example('R0lGODlhAQABAIAAAP///wAAACwAAAAAAQABAAACAkQBADs=')
                                    .description('Base64 formatted attachment file')
                                    .when('reference', {
                                        is: Joi.exist().not(false, null),
                                        then: Joi.forbidden(),
                                        otherwise: Joi.required()
                                    }),

                                contentType: Joi.string().lowercase().max(256).example('image/gif'),
                                contentDisposition: Joi.string().lowercase().valid('inline', 'attachment'),
                                cid: Joi.string().max(256).example('unique-image-id@localhost').description('Content-ID value for embedded images'),
                                encoding: Joi.string().valid('base64').default('base64'),

                                reference: Joi.string()
                                    .base64({ paddingRequired: false, urlSafe: true })
                                    .max(256)
                                    .allow(false, null)
                                    .example('AAAAAQAACnAcde')
                                    .description(
                                        'References an existing attachment by its ID instead of providing new attachment content. If this field is set, the `content` field must not be included. If not set, the `content` field is required.'
                                    )
                            }).label('UploadAttachment')
                        )
                        .description('List of attachments')
                        .label('UploadAttachmentList'),

                    messageId: Joi.string().max(996).example('<test123@example.com>').description('Message ID'),
                    headers: Joi.object().label('CustomHeaders').description('Custom Headers').unknown().example({
                        'X-My-Custom-Header': 'Custom header value'
                    }),

                    locale: Joi.string().empty('').max(100).example('fr').description('Optional locale'),
                    tz: Joi.string().empty('').max(100).example('Europe/Tallinn').description('Optional timezone')
                }).label('MessageUpload')
            },

            response: {
                schema: Joi.object({
                    id: Joi.string()
                        .example('AAAAAgAACrI')
                        .description(
                            'Unique identifier for the message. NB! This and other fields might not be present if server did not provide enough information'
                        )
                        .label('MessageAppendId'),
                    path: Joi.string().example('INBOX').description('Folder this message was uploaded to').label('MessageAppendPath'),
                    uid: Joi.number().integer().example(12345).description('UID of uploaded message'),
                    uidValidity: Joi.string().example('12345').description('UIDVALIDITY of the target folder. Numeric value cast as string.'),
                    seq: Joi.number().integer().example(12345).description('Sequence number of uploaded message'),

                    messageId: Joi.string().max(996).example('<test123@example.com>').description('Message ID'),

                    reference: Joi.object({
                        message: Joi.string()
                            .base64({ paddingRequired: false, urlSafe: true })
                            .max(256)
                            .required()
                            .example('AAAAAQAACnA')
                            .description('Referenced message ID'),
                        success: Joi.boolean().example(true).description('Was the referenced message processed').label('ResponseReferenceSuccess'),
                        documentStore: documentStoreSchema.default(false),
                        error: Joi.string().example('Referenced message was not found').description('An error message if referenced message processing failed')
                    })
                        .description('Reference info if referencing was requested')
                        .label('ResponseReference')
                }).label('MessageUploadResponse'),
                failAction: 'log'
            }
        }
    });

    // PUT /v1/account/{account}/message/{message} - Update message
    server.route({
        method: 'PUT',
        path: '/v1/account/{account}/message/{message}',

        async handler(request) {
            let accountObject = new Account({
                redis,
                account: request.params.account,
                call,
                secret: await getSecret(),
                timeout: request.headers['x-ee-timeout']
            });

            try {
                return await accountObject.updateMessage(request.params.message, request.payload);
            } catch (err) {
                request.logger.error({ msg: 'API request failed', err });
                if (Boom.isBoom(err)) {
                    throw err;
                }
                let error = Boom.boomify(err, { statusCode: err.statusCode || 500 });
                if (err.code) {
                    error.output.payload.code = err.code;
                }
                throw error;
            }
        },
        options: {
            description: 'Update message',
            notes: 'Update message information. Mainly this means changing message flag values',
            tags: ['api', 'Message'],

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
                    account: accountIdSchema.required(),
                    message: Joi.string().max(256).required().example('AAAAAQAACnA').description('Message ID')
                }),

                payload: messageUpdateSchema
            },
            response: {
                schema: Joi.object({
                    flags: Joi.object({
                        add: Joi.array().items(Joi.string()).example(['\\Seen', '\\Flagged']),
                        delete: Joi.array().items(Joi.string()).example(['\\Draft']),
                        set: Joi.array().items(Joi.string()).example(['\\Seen'])
                    }).label('FlagUpdateResponse'),
                    labels: Joi.object({
                        add: Joi.array().items(Joi.string()).example(['Label1', 'Label2']),
                        delete: Joi.array().items(Joi.string()).example(['Label3']),
                        set: Joi.array().items(Joi.string()).example(['Label1'])
                    }).label('LabelUpdateResponse')
                }).label('MessageUpdateResponse'),
                failAction: 'log'
            }
        }
    });

    // PUT /v1/account/{account}/messages - Update multiple messages
    server.route({
        method: 'PUT',
        path: '/v1/account/{account}/messages',

        async handler(request) {
            let accountObject = new Account({
                redis,
                account: request.params.account,
                call,
                secret: await getSecret(),
                timeout: request.headers['x-ee-timeout']
            });

            try {
                return await accountObject.updateMessages(request.query.path, request.payload.search, request.payload.update);
            } catch (err) {
                request.logger.error({ msg: 'API request failed', err });
                if (Boom.isBoom(err)) {
                    throw err;
                }
                let error = Boom.boomify(err, { statusCode: err.statusCode || 500 });
                if (err.code) {
                    error.output.payload.code = err.code;
                }
                throw error;
            }
        },
        options: {
            description: 'Update messages',
            notes: 'Update message information for matching emails',
            tags: ['api', 'Multi Message Actions'],

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
                    path: Joi.string().empty('').required().example('INBOX').description(listMessageFolderPathDescription)
                }).label('MessagesUpdateQuery'),

                payload: Joi.object({
                    search: searchSchema,
                    update: messageUpdateSchema
                }).label('MessagesUpdateRequest')
            },
            response: {
                schema: Joi.object({
                    flags: Joi.object({
                        add: Joi.array().items(Joi.string()).example(['\\Seen', '\\Flagged']),
                        delete: Joi.array().items(Joi.string()).example(['\\Draft']),
                        set: Joi.array().items(Joi.string()).example(['\\Seen'])
                    }).label('FlagUpdateResponse'),
                    labels: Joi.object({
                        add: Joi.array().items(Joi.string()).example(['Label1', 'Label2']),
                        delete: Joi.array().items(Joi.string()).example(['Label3']),
                        set: Joi.array().items(Joi.string()).example(['Label1'])
                    }).label('LabelUpdateResponse')
                }).label('MessageUpdateResponse'),
                failAction: 'log'
            }
        }
    });

    // PUT /v1/account/{account}/message/{message}/move - Move a message
    server.route({
        method: 'PUT',
        path: '/v1/account/{account}/message/{message}/move',

        async handler(request) {
            let accountObject = new Account({
                redis,
                account: request.params.account,
                call,
                secret: await getSecret(),
                timeout: request.headers['x-ee-timeout']
            });

            try {
                let sourceOption = null;
                if (request.payload.source) {
                    sourceOption = { path: request.payload.source };
                }
                return await accountObject.moveMessage(request.params.message, { path: request.payload.path }, { source: sourceOption });
            } catch (err) {
                request.logger.error({ msg: 'API request failed', err });
                if (Boom.isBoom(err)) {
                    throw err;
                }
                let error = Boom.boomify(err, { statusCode: err.statusCode || 500 });
                if (err.code) {
                    error.output.payload.code = err.code;
                }
                throw error;
            }
        },
        options: {
            description: 'Move a message to a specified folder',
            notes: 'Moves a message to a target folder',
            tags: ['api', 'Message'],

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
                    account: accountIdSchema.required(),
                    message: Joi.string().max(256).required().example('AAAAAQAACnA').description('Message ID')
                }),

                payload: Joi.object({
                    path: Joi.string().required().example('INBOX').description('Destination mailbox folder path'),
                    source: Joi.string()
                        .example('INBOX')
                        .description('Source mailbox folder path (Gmail API only). Needed to remove the label from the message.')
                })
                    .example({ path: 'Target/Folder' })
                    .label('MessageMove')
            },

            response: {
                schema: Joi.object({
                    path: Joi.string().required().example('INBOX').description('Destination mailbox folder path'),
                    id: Joi.string().max(256).example('AAAAAQAACnA').description('ID of the moved message. Only included if the server provides it.'),
                    uid: Joi.number()
                        .integer()
                        .example(12345)
                        .description('UID of the moved message, applies only to IMAP accounts. Only included if the server provides it.')
                }).label('MessageMoveResponse'),
                failAction: 'log'
            }
        }
    });

    // PUT /v1/account/{account}/messages/move - Move multiple messages
    server.route({
        method: 'PUT',
        path: '/v1/account/{account}/messages/move',

        async handler(request) {
            let accountObject = new Account({
                redis,
                account: request.params.account,
                call,
                secret: await getSecret(),
                timeout: request.headers['x-ee-timeout']
            });

            try {
                return await accountObject.moveMessages(request.query.path, request.payload.search, { path: request.payload.path });
            } catch (err) {
                request.logger.error({ msg: 'API request failed', err });
                if (Boom.isBoom(err)) {
                    throw err;
                }
                let error = Boom.boomify(err, { statusCode: err.statusCode || 500 });
                if (err.code) {
                    error.output.payload.code = err.code;
                }
                throw error;
            }
        },
        options: {
            description: 'Move messages',
            notes: 'Move messages matching to a search query to another folder',
            tags: ['api', 'Multi Message Actions'],

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
                    path: Joi.string().empty('').required().example('INBOX').description(listMessageFolderPathDescription)
                }).label('MessagesMoveQuery'),

                payload: Joi.object({
                    search: searchSchema,
                    path: Joi.string().required().example('INBOX').description('Target mailbox folder path')
                }).label('MessagesMoveRequest')
            },

            response: {
                schema: Joi.object({
                    path: Joi.string().required().example('INBOX').description('Target mailbox folder path'),

                    idMap: Joi.array()
                        .items(Joi.array().length(2).items(Joi.string().max(256).required().description('Message ID')).label('IdMapTuple'))
                        .example([['AAAAAQAACnA', 'AAAAAwAAAD4']])
                        .description('An optional map of source and target ID values, if the server provided this info')
                        .label('IdMapArray'),

                    emailIds: Joi.array()
                        .items(Joi.string().example('1278455344230334865'))
                        .description('An optional list of emailId values, if the server supports unique email IDs')
                        .label('EmailIdsArray')
                }).label('MessagesMoveResponse'),
                failAction: 'log'
            }
        }
    });

    // DELETE /v1/account/{account}/message/{message} - Delete message
    server.route({
        method: 'DELETE',
        path: '/v1/account/{account}/message/{message}',

        async handler(request) {
            let accountObject = new Account({
                redis,
                account: request.params.account,
                call,
                secret: await getSecret(),
                timeout: request.headers['x-ee-timeout']
            });

            try {
                return await accountObject.deleteMessage(request.params.message, request.query.force);
            } catch (err) {
                request.logger.error({ msg: 'API request failed', err });
                if (Boom.isBoom(err)) {
                    throw err;
                }
                let error = Boom.boomify(err, { statusCode: err.statusCode || 500 });
                if (err.code) {
                    error.output.payload.code = err.code;
                }
                throw error;
            }
        },
        options: {
            description: 'Delete message',
            notes: 'Move message to Trash or delete it if already in Trash',
            tags: ['api', 'Message'],

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

                query: Joi.object({
                    force: Joi.boolean()
                        .truthy('Y', 'true', '1')
                        .falsy('N', 'false', 0)
                        .default(false)
                        .description('Delete message even if not in Trash. Not supported for Gmail API accounts.')
                        .label('ForceDelete')
                }).label('MessageDeleteQuery'),

                params: Joi.object({
                    account: accountIdSchema.required(),
                    message: Joi.string().max(256).required().example('AAAAAQAACnA').description('Message ID')
                }).label('MessageDelete')
            },
            response: {
                schema: Joi.object({
                    deleted: Joi.boolean().example(false).description('Was the delete action executed'),
                    moved: Joi.object({
                        destination: Joi.string().required().example('Trash').description('Trash folder path').label('TrashPath'),
                        message: Joi.string().required().example('AAAAAwAAAWg').description('Message ID in Trash').label('TrashMessageId')
                    }).description('Present if message was moved to Trash')
                }).label('MessageDeleteResponse'),
                failAction: 'log'
            }
        }
    });

    // PUT /v1/account/{account}/messages/delete - Delete multiple messages
    server.route({
        method: 'PUT',
        path: '/v1/account/{account}/messages/delete',

        async handler(request) {
            let accountObject = new Account({
                redis,
                account: request.params.account,
                call,
                secret: await getSecret(),
                timeout: request.headers['x-ee-timeout']
            });

            try {
                return await accountObject.deleteMessages(request.query.path, request.payload.search, request.query.force);
            } catch (err) {
                request.logger.error({ msg: 'API request failed', err });
                if (Boom.isBoom(err)) {
                    throw err;
                }
                let error = Boom.boomify(err, { statusCode: err.statusCode || 500 });
                if (err.code) {
                    error.output.payload.code = err.code;
                }
                throw error;
            }
        },
        options: {
            description: 'Delete messages',
            notes: 'Move messages to Trash or delete these if already in Trash',
            tags: ['api', 'Multi Message Actions'],

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
                    path: Joi.string().empty('').required().example('INBOX').description(listMessageFolderPathDescription),
                    force: Joi.boolean()
                        .truthy('Y', 'true', '1')
                        .falsy('N', 'false', 0)
                        .default(false)
                        .description('Delete messages even if not in Trash')
                        .label('ForceDelete')
                }).label('MessagesDeleteQuery'),

                payload: Joi.object({
                    search: searchSchema
                }).label('MessagesDeleteRequest')
            },

            response: {
                schema: Joi.object({
                    deleted: Joi.boolean().example(false).description('Was the delete action executed'),
                    moved: Joi.object({
                        destination: Joi.string().required().example('Trash').description('Trash folder path').label('TrashPath'),

                        idMap: Joi.array()
                            .items(Joi.array().length(2).items(Joi.string().max(256).required().description('Message ID')).label('IdMapTuple'))
                            .example([['AAAAAQAACnA', 'AAAAAwAAAD4']])
                            .description('An optional map of source and target ID values, if the server provided this info')
                            .label('IdMapArray'),

                        emailIds: Joi.array()
                            .items(Joi.string().example('1278455344230334865'))
                            .description('An optional list of emailId values, if the server supports unique email IDs')
                            .label('EmailIdsArray')
                    })
                        .label('MessagesMovedToTrash')
                        .description('Value is present if messages were moved to Trash')
                }).label('MessagesDeleteResponse'),
                failAction: 'log'
            }
        }
    });

    // GET /v1/account/{account}/messages - List messages in a folder
    server.route({
        method: 'GET',
        path: '/v1/account/{account}/messages',

        async handler(request, h) {
            let accountObject = new Account({
                redis,
                account: request.params.account,
                call,
                secret: await getSecret(),
                esClient: await h.getESClient(request.logger),
                timeout: request.headers['x-ee-timeout']
            });

            try {
                return await accountObject.listMessages(request.query);
            } catch (err) {
                request.logger.error({ msg: 'API request failed', err });
                if (Boom.isBoom(err)) {
                    throw err;
                }
                let error = Boom.boomify(err, { statusCode: err.statusCode || 500 });
                if (err.code) {
                    error.output.payload.code = err.code;
                }
                throw error;
            }
        },
        options: {
            description: 'List messages in a folder',
            notes: 'Lists messages in a mailbox folder',
            tags: ['api', 'Message'],

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
                    account: accountIdSchema.required().label('AccountId')
                }),

                query: Joi.object({
                    path: Joi.string().required().example('INBOX').description(listMessageFolderPathDescription).label('SpecialPath'),

                    cursor: Joi.string()
                        .trim()
                        .empty('')
                        .max(1024 * 1024)
                        .example('imap_kcQIji3UobDDTxc')
                        .description('Paging cursor from `nextPageCursor` or `prevPageCursor` value')
                        .label('PageCursor'),
                    page: Joi.number()
                        .integer()
                        .min(0)
                        .max(1024 * 1024)
                        .default(0)
                        .example(0)
                        .description(
                            'Page number (zero-indexed, so use 0 for the first page). Only supported for IMAP accounts. Deprecated; use the paging cursor instead. If the page cursor value is provided, then the page number value is ignored.'
                        )
                        .label('PageNumber'),

                    pageSize: Joi.number().integer().min(1).max(1000).default(20).example(20).description('How many entries per page').label('PageSize'),
                    documentStore: documentStoreSchema.default(false)
                }).label('MessageQuery')
            },

            response: {
                schema: messageListSchema,
                failAction: 'log'
            }
        }
    });

    // POST /v1/account/{account}/search - Search for messages
    server.route({
        method: 'POST',
        path: '/v1/account/{account}/search',

        async handler(request, h) {
            let accountObject = new Account({
                redis,
                account: request.params.account,
                call,
                secret: await getSecret(),
                esClient: await h.getESClient(request.logger),
                timeout: request.headers['x-ee-timeout']
            });

            let extraValidationErrors = [];

            if (request.query.documentStore) {
                for (let key of ['seq', 'modseq']) {
                    if (request.payload.search && key in request.payload.search) {
                        extraValidationErrors.push({ message: 'Not available when using Document Store', context: { key } });
                    }
                }
            } else {
                for (let key of ['documentQuery']) {
                    if (key in request.payload) {
                        extraValidationErrors.push({ message: 'Requires Document Store to be enabled', context: { key } });
                    }
                }
            }

            if (extraValidationErrors.length) {
                let error = new Error('Input validation failed');
                error.details = extraValidationErrors;
                return failAction(request, h, error);
            }

            try {
                return await accountObject.searchMessages(Object.assign(request.query, request.payload));
            } catch (err) {
                request.logger.error({ msg: 'API request failed', err });
                if (Boom.isBoom(err)) {
                    throw err;
                }
                let error = Boom.boomify(err, { statusCode: err.statusCode || 500 });
                if (err.code) {
                    error.output.payload.code = err.code;
                }
                throw error;
            }
        },
        options: {
            description: 'Search for messages',
            notes: 'Filter messages from a mailbox folder by search options. Search is performed against a specific folder and not for the entire account.',
            tags: ['api', 'Message'],

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
                    path: Joi.string()
                        .when('documentStore', {
                            is: true,
                            then: Joi.optional(),
                            otherwise: Joi.required()
                        })
                        .example('INBOX')
                        .description(listMessageFolderPathDescription)
                        .label('Path'),

                    cursor: Joi.string()
                        .trim()
                        .empty('')
                        .max(1024 * 1024)
                        .example('imap_kcQIji3UobDDTxc')
                        .description('Paging cursor from `nextPageCursor` or `prevPageCursor` value')
                        .label('PageCursor'),
                    page: Joi.number()
                        .integer()
                        .min(0)
                        .max(1024 * 1024)
                        .default(0)
                        .example(0)
                        .description(
                            'Page number (zero-indexed, so use 0 for the first page). Only supported for IMAP accounts. Deprecated; use the paging cursor instead. If the page cursor value is provided, then the page number value is ignored.'
                        )
                        .label('PageNumber'),

                    pageSize: Joi.number().integer().min(1).max(1000).default(20).example(20).description('How many entries per page'),

                    useOutlookSearch: Joi.boolean()
                        .truthy('Y', 'true', '1')
                        .falsy('N', 'false', 0)
                        .description(
                            'MS Graph only. If enabled, uses the $search parameter for MS Graph search queries instead of $filter. This allows searching the "to", "cc", "bcc", "larger", "smaller", "body", "before", "sentBefore", "since", and the "sentSince" fields. Note that $search returns up to 1,000 results, does not indicate the total number of matching results or pages, and returns results sorted by relevance rather than date.'
                        )
                        .label('useOutlookSearch')
                        .optional(),

                    documentStore: documentStoreSchema.default(false).meta({ swaggerHidden: true }),
                    exposeQuery: Joi.boolean()
                        .truthy('Y', 'true', '1')
                        .falsy('N', 'false', 0)
                        .description('If enabled then returns the ElasticSearch query for debugging as part of the response')
                        .label('exposeQuery')
                        .when('documentStore', {
                            is: true,
                            then: Joi.optional(),
                            otherwise: Joi.forbidden()
                        })
                        .meta({ swaggerHidden: true })
                }),

                payload: Joi.object({
                    search: searchSchema,
                    documentQuery: Joi.object()
                        .min(1)
                        .description('Document Store query. Only allowed with `documentStore`.')
                        .label('DocumentQuery')
                        .unknown()
                        .meta({ swaggerHidden: true })
                })
                    .label('MessageSearchPayload')
                    .example({
                        search: {
                            unseen: true,
                            flagged: true,
                            from: 'nyan.cat@example.com',
                            body: 'Hello world',
                            subject: 'Hello world',
                            sentBefore: '2024-08-09',
                            sentSince: '2022-08-09',
                            emailId: '1278455344230334865',
                            threadId: '1266894439832287888',
                            header: {
                                'Message-ID': '<12345@example.com>'
                            },
                            gmailRaw: 'has:attachment in:unread'
                        }
                    })
            },

            response: {
                schema: messageListSchema,
                failAction: 'log'
            }
        }
    });

    // POST /v1/unified/search - Unified search for messages
    server.route({
        method: 'POST',
        path: '/v1/unified/search',

        async handler(request, h) {
            let accountObject = new Account({
                redis,
                call,
                secret: await getSecret(),
                esClient: await h.getESClient(request.logger),
                timeout: request.headers['x-ee-timeout']
            });

            let extraValidationErrors = [];

            for (let key of ['seq', 'modseq']) {
                if (request.payload.search && key in request.payload.search) {
                    extraValidationErrors.push({ message: 'Not available when using Document Store', context: { key } });
                }
            }

            if (extraValidationErrors.length) {
                let error = new Error('Input validation failed');
                error.details = extraValidationErrors;
                return failAction(request, h, error);
            }

            let documentStoreEnabled = await settings.get('documentStoreEnabled');
            if (!documentStoreEnabled) {
                let error = new Error('Document store not enabled');
                error.details = extraValidationErrors;
                return failAction(request, h, error);
            }

            try {
                return await accountObject.searchMessages(Object.assign({ documentStore: true }, request.query, request.payload), { unified: true });
            } catch (err) {
                request.logger.error({ msg: 'API request failed', err });
                if (Boom.isBoom(err)) {
                    throw err;
                }
                let error = Boom.boomify(err, { statusCode: err.statusCode || 500 });
                if (err.code) {
                    error.output.payload.code = err.code;
                }
                throw error;
            }
        },
        options: {
            description: 'Unified search for messages',
            notes: 'Filter messages from the Document Store for multiple accounts or paths. Document Store must be enabled for the unified search to work.',
            tags: ['Deprecated endpoints (Document Store)'],

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

                query: Joi.object({
                    page: Joi.number()
                        .integer()
                        .min(0)
                        .max(1024 * 1024)
                        .default(0)
                        .example(0)
                        .description('Page number (zero indexed, so use 0 for first page)'),
                    pageSize: Joi.number().integer().min(1).max(1000).default(20).example(20).description('How many entries per page'),
                    exposeQuery: Joi.boolean()
                        .truthy('Y', 'true', '1')
                        .falsy('N', 'false', 0)
                        .description('If enabled then returns the ElasticSearch query for debugging as part of the response')
                        .label('exposeQuery')
                        .optional()
                        .meta({ swaggerHidden: true })
                }),

                payload: Joi.object({
                    accounts: Joi.array()
                        .items(Joi.string().empty('').trim().max(256).example('example'))
                        .single()
                        .description('Optional list of account ID values')
                        .label('UnifiedSearchAccounts'),
                    paths: Joi.array()
                        .items(Joi.string().optional().example('INBOX'))
                        .single()
                        .description('Optional list of mailbox folder paths or specialUse flags')
                        .label('UnifiedSearchPaths'),
                    search: searchSchema,
                    documentQuery: Joi.object().min(1).description('Document Store query').label('DocumentQuery').unknown().meta({ swaggerHidden: true })
                }).label('UnifiedSearchQuery')
            },

            response: {
                schema: messageListSchema,
                failAction: 'log'
            }
        }
    });

    // GET /v1/account/{account}/text/{text} - Retrieve message text
    server.route({
        method: 'GET',
        path: '/v1/account/{account}/text/{text}',

        async handler(request, h) {
            let accountObject = new Account({
                redis,
                account: request.params.account,
                call,
                secret: await getSecret(),
                esClient: await h.getESClient(request.logger),
                timeout: request.headers['x-ee-timeout']
            });

            try {
                return await accountObject.getText(request.params.text, request.query);
            } catch (err) {
                request.logger.error({ msg: 'API request failed', err });
                if (Boom.isBoom(err)) {
                    throw err;
                }
                let error = Boom.boomify(err, { statusCode: err.statusCode || 500 });
                if (err.code) {
                    error.output.payload.code = err.code;
                }
                throw error;
            }
        },
        options: {
            description: 'Retrieve message text',
            notes: 'Retrieves message text',
            tags: ['api', 'Message'],

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

                query: Joi.object({
                    maxBytes: Joi.number()
                        .integer()
                        .min(0)
                        .max(1024 * 1024 * 1024)
                        .example(MAX_ATTACHMENT_SIZE)
                        .description('Max length of text content'),
                    textType: Joi.string()
                        .lowercase()
                        .valid('html', 'plain', '*')
                        .default('*')
                        .example('*')
                        .description('Which text content to return, use * for all. By default all contents are returned.'),
                    documentStore: documentStoreSchema.default(false)
                }),

                params: Joi.object({
                    account: accountIdSchema.required(),
                    text: Joi.string()
                        .base64({ paddingRequired: false, urlSafe: true })
                        .max(10 * 1024)
                        .required()
                        .example('AAAAAQAACnAcdfaaN')
                        .description('Message text ID')
                }).label('Text')
            },

            response: {
                schema: Joi.object({
                    plain: Joi.string().example('Hello world').description('Plaintext content'),
                    html: Joi.string().example('<p>Hello world</p>').description('HTML content'),
                    hasMore: Joi.boolean().example(false).description('Is the current text output capped or not')
                }).label('TextResponse'),
                failAction: 'log'
            }
        }
    });

    // GET /v1/account/{account}/attachment/{attachment} - Download attachment
    server.route({
        method: 'GET',
        path: '/v1/account/{account}/attachment/{attachment}',

        async handler(request) {
            let accountObject = new Account({
                redis,
                account: request.params.account,
                call,
                secret: await getSecret(),
                timeout: request.headers['x-ee-timeout']
            });

            try {
                return await accountObject.getAttachment(request.params.attachment);
            } catch (err) {
                request.logger.error({ msg: 'API request failed', err });
                if (Boom.isBoom(err)) {
                    throw err;
                }
                let error = Boom.boomify(err, { statusCode: err.statusCode || 500 });
                if (err.code) {
                    error.output.payload.code = err.code;
                }
                throw error;
            }
        },
        options: {
            description: 'Download attachment',
            notes: 'Fetches attachment file as a binary stream',
            tags: ['api', 'Message'],

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },
            cors: CORS_CONFIG,

            plugins: {
                'hapi-swagger': {
                    produces: ['application/octet-stream']
                }
            },

            validate: {
                options: {
                    stripUnknown: false,
                    abortEarly: false,
                    convert: true
                },
                failAction,

                params: Joi.object({
                    account: accountIdSchema.required(),
                    attachment: Joi.string()
                        .base64({ paddingRequired: false, urlSafe: true })
                        .max(2 * 1024)
                        .required()
                        .example('AAAAAQAACnAcde')
                        .description('Attachment ID')
                })
            }
        }
    });
}

module.exports = init;
