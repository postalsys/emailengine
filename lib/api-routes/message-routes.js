'use strict';

const { redis } = require('../db');
const { Account } = require('../account');
const getSecret = require('../get-secret');
const settings = require('../settings');
const Joi = require('joi');
const { failAction } = require('../tools');
const { handleError } = require('./route-helpers');
const BEHAVIOR = require('./behavior-notes');
const { IMPACT } = require('./operation-impact');
const { FIELD_USAGE } = require('../field-usage');
const { COLLAPSE_CLASS, MCP_MAX_PAGE_SIZE } = require('../consts');

// What the collapse marker means, said once because both body tools carry it. An agent that knows
// the class name can read the new part of a thread without the quoted copies of everything before
// it, which on a long thread is most of the tokens.
const COLLAPSE_MARKER_NOTE =
    `Quoted reply and forward history is wrapped in a <details class="${COLLAPSE_CLASS}"> element - what an email client hides behind a "show more" ` +
    'control - so everything outside it is what the sender wrote this time.';

// The body budgets of the two MCP tools that return a message body. Both are forced rather than
// offered: the route's own maxBytes tops out at a gigabyte, which is not a number to put in front
// of a model, and an unbounded ask is fetched, sanitized and serialized in full before the MCP
// layer truncates it - all of that work for bytes nobody sees.
//
// What `maxBytes` actually bounds is the input: it cuts each text part to this many CHARACTERS
// before the web-safe rendering runs, and that rendering reads both parts and can come out larger
// than either (inlined CSS, the collapse markup). So these are work bounds, not a promise about
// the size of the result - MAX_TOOL_RESULT_BYTES in lib/mcp/tools.js is the promise. They are set
// at a quarter and a half of it so the two multipliers between the units do not routinely push a
// normal message into that truncation, which costs the caller a JSON fragment it cannot parse.
// test/mcp-tools-test.js asserts the margin and the ordering.
//
// Read as tokens: get_message inlines about 8k of them so that reading one message is one call
// rather than two, and get_message_text returns twice that when the body did not fit.
const MCP_MESSAGE_BODY_MAX_BYTES = 32 * 1024;
const MCP_MESSAGE_TEXT_MAX_BYTES = 64 * 1024;

const {
    accountIdSchema,
    messageDetailsSchema,
    messageListSchema,
    messageEntrySchema,
    documentStoreSchema,
    documentStoreQuerySchema,
    searchSchema,
    messageUpdateSchema,
    addressSchema,
    fromAddressSchema,
    messageReferenceSchema,
    emailIdSchema,
    threadIdSchema,
    apiResponses,
    ENUM_DESCRIPTIONS
} = require('../schemas');

const listMessageFolderPathDescription =
    'Mailbox folder path. Can use special use labels like "\\Sent". Special value "\\All" is available for Gmail IMAP, Gmail API, MS Graph API accounts.';

// One entry of the array branch below. The operation's own example is a boolean for flags,
// so the array branch has nothing to inherit from and its entries used to document
// themselves as "string" - see the example coverage assertion in test/api-reference-test.js.
const UPDATE_OP_ENTRY_EXAMPLE = {
    flags: '\\Seen',
    labels: 'Label_971539351003152516'
};

// Response field for a flag or label update operation. IMAP accounts return a boolean (whether
// the operation succeeded), API-based accounts echo the requested values as an array.
const updateOpResultSchema = (op, noun, entryLabel, example, label) =>
    Joi.alternatives()
        .try(Joi.boolean(), Joi.array().items(Joi.string().label(entryLabel).example(UPDATE_OP_ENTRY_EXAMPLE[noun])))
        .example(example)
        .description(`Did the ${op} operation succeed (boolean, IMAP accounts) or the requested ${noun} (array, API-based accounts)`)
        .label(label);

// Source-to-target ID map for messages that were moved to another folder. Only the IMAP backend
// provides this info.
const idMapSchema = Joi.array()
    .items(Joi.array().length(2).items(Joi.string().max(256).required().description('Message ID')).label('IdMapTuple'))
    .example([['AAAAAQAACnA', 'AAAAAwAAAD4']])
    .description('An optional map of source and target ID values, if the server provided this info (IMAP accounts only)')
    .label('IdMapArray');

async function init(args) {
    const { server, call, CORS_CONFIG, MAX_ATTACHMENT_SIZE, MAX_BODY_SIZE, MAX_PAYLOAD_TIMEOUT, documentStoreFeatureEnabled } = args;

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
                handleError(request, err);
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
                openapi: {
                    produces: ['message/rfc822'],
                    responses: apiResponses('Returns the raw RFC822 message source.', 400, 401, 403, 404, 429, 500, 503)
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
                handleError(request, err);
            }
        },
        options: {
            description: 'Get message information',
            notes: 'Returns details of a specific message. By default text content is not included, use textType value to force retrieving text',
            tags: ['api', 'Message'],

            plugins: {
                mcp: {
                    name: 'get_message',
                    title: 'Get message',
                    description:
                        'Get one message: subject, addresses, date, flags, attachment list and the body. The body arrives in text.html as sanitized HTML, generated from the plaintext part when the message carries no HTML one, with no separate plaintext copy. ' +
                        `It is capped at ${MCP_MESSAGE_BODY_MAX_BYTES} characters - text.hasMore true means more of it is available from get_message_text. ` +
                        COLLAPSE_MARKER_NOTE,
                    // The rendering knobs are not the calling model's to choose. One canonical
                    // body shape is what an agent can reason about, and web-safe HTML is the one
                    // that exists for every message. Attached images stay out of it: an agent
                    // reads the body rather than displaying it, so inlining them as data URIs
                    // would multiply the size of a tool result that already carries the whole
                    // body, and the `cid:` references it keeps instead name the attachments
                    // get_attachment can fetch.
                    omit: ['textType', 'webSafeHtml', 'preProcessHtml', 'embedAttachedImages', 'maxBytes'],
                    force: { webSafeHtml: true, embedAttachedImages: false, maxBytes: MCP_MESSAGE_BODY_MAX_BYTES }
                },
                openapi: {
                    responses: apiResponses(
                        'Returns the message envelope and structure. Text content is only included when requested.',
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
                        .description('Which text content to return, use * for all. By default text content is not returned.')
                        .label('MessageTextType'),

                    webSafeHtml: Joi.boolean()
                        .truthy('Y', 'true', '1')
                        .falsy('N', 'false', 0)
                        .default(false)
                        .description('Shorthand option to fetch and preprocess HTML and inline images')
                        .meta({ usage: FIELD_USAGE.webSafeHtml })
                        .label('WebSafeHtml'),

                    // Deliberately no default: applyWebSafeHtmlOptions() has to tell "not asked
                    // for" from an explicit false, because an explicit false is what overrides
                    // the webSafeHtml shorthand. It resolves the tri-state to a boolean, so no
                    // consumer downstream sees the undefined.
                    embedAttachedImages: Joi.boolean()
                        .truthy('Y', 'true', '1')
                        .falsy('N', 'false', 0)
                        .description('If true, then fetches attached images and embeds these in the HTML as data URIs. Not set means false')
                        .meta({ usage: FIELD_USAGE.embedAttachedImages })
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
                handleError(request, err);
            }
        },
        options: {
            payload: {
                maxBytes: MAX_BODY_SIZE,
                timeout: MAX_PAYLOAD_TIMEOUT
            },

            description: 'Upload message',
            notes: ['Upload a message structure, compile it into an EML file and store it into selected mailbox.', BEHAVIOR.UPLOAD_DRAFTS_ONLY_GRAPH],
            tags: ['api', 'Message'],

            plugins: {
                mcp: {
                    name: 'create_draft',
                    title: 'Create draft',
                    description:
                        'Store a new message in a folder, typically a draft in the Drafts folder. Takes structured fields (from, to, subject, text, html). ' +
                        'It takes the same `reference` block as send_message, so a reply or a forward can be drafted for the user to look over first. ' +
                        'Nothing is sent - use send_message for that.',
                    // An allowlist for the same reason send_message uses one: the composed message
                    // is a small stable set, the route's payload is not, and a field added later
                    // should not join an agent-facing schema by default. Left out are `raw` (which
                    // replaces the structured fields this tool is made of), `messageId`/`headers`
                    // (headers EmailEngine derives), `internalDate` (backdates the stored copy)
                    // and `locale`/`tz` (rendering detail).
                    keep: ['account', 'path', 'flags', 'reference', 'from', 'to', 'cc', 'bcc', 'subject', 'text', 'html', 'attachments']
                },
                openapi: {
                    'x-ee-behavior': [BEHAVIOR.UPLOAD_DRAFTS_ONLY_GRAPH],
                    responses: apiResponses('Returns the uploaded message with the identifiers the provider assigned to it.', 400, 401, 403, 404, 429, 500, 503)
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
                    path: Joi.string().required().example('INBOX').description('Target mailbox folder path'),

                    flags: Joi.array().items(Joi.string().max(128)).example(['\\Seen', '\\Draft']).default([]).description('Message flags').label('Flags'),
                    internalDate: Joi.date().iso().example('2021-07-08T07:06:34.336Z').description('Sets the internal date for this message'),

                    reference: messageReferenceSchema,

                    raw: Joi.string()
                        .base64()
                        .max(MAX_ATTACHMENT_SIZE)
                        .example('TUlNRS1WZXJzaW9uOiAxLjANClN1YmplY3Q6IGhlbGxvIHdvcmxkDQoNCkhlbGxvIQ0K')
                        .description('A Base64-encoded email message in RFC 822 format')
                        .meta({ usage: FIELD_USAGE.messageRaw })
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
                                contentDisposition: Joi.string()
                                    .lowercase()
                                    .valid('inline', 'attachment')
                                    .meta({ enumDescriptions: ENUM_DESCRIPTIONS.messageUploadDisposition })
                                    .label('MsgUploadContentDisposition'),
                                cid: Joi.string().max(256).example('unique-image-id@localhost').description('Content-ID value for embedded images'),
                                encoding: Joi.string().valid('base64').default('base64').label('MsgUploadEncoding'),

                                reference: Joi.string()
                                    .base64({ paddingRequired: false, urlSafe: true })
                                    .max(256)
                                    .allow(false, null)
                                    .example('AAAAAQAACnAcde')
                                    .description('References an existing attachment by its ID instead of providing new attachment content')
                                    .meta({ usage: FIELD_USAGE.attachmentReference })
                                    .label('MsgUploadReference')
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
                    uid: Joi.number().integer().example(12345).description('UID of uploaded message (IMAP accounts only)'),
                    uidValidity: Joi.string()
                        .example('12345')
                        .description('UIDVALIDITY of the target folder. Numeric value cast as string. IMAP accounts only.'),
                    seq: Joi.number().integer().example(12345).description('Sequence number of uploaded message (IMAP accounts only)'),

                    messageId: Joi.string().max(996).example('<test123@example.com>').description('Message ID'),

                    reference: Joi.object({
                        message: Joi.string()
                            .base64({ paddingRequired: false, urlSafe: true })
                            .max(256)
                            .example('AAAAAQAACnA')
                            .description('Referenced message ID. Not present when only a thread ID was referenced'),
                        threadId: threadIdSchema.description('Referenced thread ID (Gmail API accounts only)').label('ResponseReferenceThreadId'),
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
                handleError(request, err);
            }
        },
        options: {
            description: 'Update message',
            notes: ['Update message information. Mainly this means changing message flag values', BEHAVIOR.NO_LABEL_SET_ON_GMAIL],
            tags: ['api', 'Message'],

            plugins: {
                mcp: {
                    name: 'update_message',
                    title: 'Update message flags',
                    description: 'Update the flags or labels of one message, e.g. add \\Seen to mark it read or \\Flagged to star it.'
                },
                openapi: {
                    'x-ee-behavior': [BEHAVIOR.NO_LABEL_SET_ON_GMAIL],
                    responses: apiResponses('Returns which flag and label changes were applied.', 400, 401, 403, 404, 429, 500, 503)
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
                    account: accountIdSchema.required(),
                    message: Joi.string().max(256).required().example('AAAAAQAACnA').description('Message ID')
                }),

                payload: messageUpdateSchema
            },
            response: {
                schema: Joi.object({
                    flags: Joi.object({
                        add: updateOpResultSchema('add', 'flags', 'FlagEntry', true, 'FlagAddResult'),
                        delete: updateOpResultSchema('delete', 'flags', 'FlagEntry', false, 'FlagDeleteResult'),
                        set: updateOpResultSchema('set', 'flags', 'FlagEntry', true, 'FlagSetResult'),
                        result: Joi.array()
                            .items(Joi.string().label('FlagEntry'))
                            .example(['\\Seen'])
                            .description('Resulting flag set after the update (Gmail API and MS Graph API accounts only)')
                            .label('FlagResultList')
                    }).label('FlagUpdateResponse'),
                    labels: Joi.object({
                        add: updateOpResultSchema('add', 'labels', 'LabelEntry', ['Label1', 'Label2'], 'LabelAddResult'),
                        delete: updateOpResultSchema('delete', 'labels', 'LabelEntry', ['Label3'], 'LabelDeleteResult'),
                        set: updateOpResultSchema('set', 'labels', 'LabelEntry', ['Label1'], 'LabelSetResult'),
                        result: Joi.array()
                            .items(Joi.string().label('LabelEntry'))
                            .example(['Label1'])
                            .description('Resulting label set after the update (Gmail API and MS Graph API accounts only)')
                            .label('LabelResultList')
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
                handleError(request, err);
            }
        },
        options: {
            description: 'Update messages',
            notes: ['Update message information for matching emails', BEHAVIOR.NO_LABEL_SET_ON_GMAIL],
            tags: ['api', 'Multi Message Actions'],

            plugins: {
                openapi: {
                    'x-ee-behavior': [BEHAVIOR.NO_LABEL_SET_ON_GMAIL],
                    responses: apiResponses('Returns which flag and label changes were applied to the matching messages.', 400, 401, 403, 404, 429, 500, 503)
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
                        add: updateOpResultSchema('add', 'flags', 'BulkFlagEntry', true, 'BulkFlagAddResult'),
                        delete: updateOpResultSchema('delete', 'flags', 'BulkFlagEntry', false, 'BulkFlagDeleteResult'),
                        set: updateOpResultSchema('set', 'flags', 'BulkFlagEntry', true, 'BulkFlagSetResult')
                    }).label('BulkFlagUpdateResponse'),
                    labels: Joi.object({
                        add: updateOpResultSchema('add', 'labels', 'BulkLabelEntry', ['Label1', 'Label2'], 'BulkLabelAddResult'),
                        delete: updateOpResultSchema('delete', 'labels', 'BulkLabelEntry', ['Label3'], 'BulkLabelDeleteResult'),
                        set: updateOpResultSchema('set', 'labels', 'BulkLabelEntry', ['Label1'], 'BulkLabelSetResult')
                    }).label('BulkLabelUpdateResponse'),
                    emailIds: Joi.array()
                        .items(emailIdSchema)
                        .description('List of updated email IDs (Gmail API and MS Graph API accounts only)')
                        .label('BulkUpdatedEmailIds')
                }).label('BulkMessageUpdateResponse'),
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
                handleError(request, err);
            }
        },
        options: {
            description: 'Move a message to a specified folder',
            notes: 'Moves a message to a target folder',
            tags: ['api', 'Message'],

            plugins: {
                mcp: {
                    name: 'move_message',
                    title: 'Move message',
                    description: 'Move one message to another folder. The target folder path comes from list_mailboxes.'
                },
                openapi: {
                    responses: apiResponses('Returns the message identifiers in the target folder.', 400, 401, 403, 404, 429, 500, 503)
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
                handleError(request, err);
            }
        },
        options: {
            description: 'Move messages',
            notes: 'Move messages matching to a search query to another folder',
            tags: ['api', 'Multi Message Actions'],

            plugins: {
                openapi: {
                    responses: apiResponses('Returns the number of messages moved.', 400, 401, 403, 404, 429, 500, 503)
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

                    idMap: idMapSchema,

                    emailIds: Joi.array()
                        .items(emailIdSchema)
                        .allow(null)
                        .description(
                            'An optional list of emailId values, if the server supports unique email IDs (Gmail API and MS Graph API accounts only). Null when no messages matched the search (Gmail API)'
                        )
                        .label('MovedEmailIdsArray')
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
                handleError(request, err);
            }
        },
        options: {
            description: 'Delete message',
            notes: ['Move message to Trash or delete it if already in Trash', BEHAVIOR.GMAIL_DELETE_IS_TRASH],
            tags: ['api', 'Message'],

            plugins: {
                mcp: {
                    name: 'delete_message',
                    title: 'Delete message',
                    description: 'Delete one message. It is moved to Trash when possible, and deleted permanently when it already is in Trash.'
                },
                openapi: {
                    'x-ee-impact': IMPACT.DESTRUCTIVE,
                    'x-ee-behavior': [BEHAVIOR.GMAIL_DELETE_IS_TRASH],
                    responses: apiResponses('Returns whether the message was moved to Trash or permanently deleted.', 400, 401, 403, 404, 429, 500, 503)
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
                    deleted: Joi.boolean()
                        .example(false)
                        .description(
                            'Was the message deleted permanently. IMAP accounts return false when the message was moved to Trash, Gmail API and MS Graph API accounts return true also for moves to Trash'
                        ),
                    moved: Joi.object({
                        destination: Joi.string()
                            .example('Trash')
                            .description('Trash folder path. Can be missing if the server did not provide the destination folder')
                            .label('TrashPath'),
                        message: Joi.string()
                            .example('AAAAAwAAAWg')
                            .description('Message ID in Trash. Can be missing if the server did not provide the new message ID')
                            .label('TrashMessageId')
                    })
                        .description('Present if message was moved to Trash')
                        .label('MessageMovedToTrash')
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
                handleError(request, err);
            }
        },
        options: {
            description: 'Delete messages',
            notes: ['Move messages to Trash or delete these if already in Trash', BEHAVIOR.GMAIL_DELETE_IS_TRASH],
            tags: ['api', 'Multi Message Actions'],

            plugins: {
                openapi: {
                    'x-ee-impact': IMPACT.DESTRUCTIVE,
                    'x-ee-behavior': [BEHAVIOR.GMAIL_DELETE_IS_TRASH],
                    responses: apiResponses('Returns the number of messages deleted.', 400, 401, 403, 404, 429, 500, 503)
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
                    path: Joi.string().empty('').required().example('INBOX').description(listMessageFolderPathDescription),
                    force: Joi.boolean()
                        .truthy('Y', 'true', '1')
                        .falsy('N', 'false', 0)
                        .default(false)
                        .description('Delete messages even if not in Trash. Not supported for Gmail API accounts (messages are always moved to Trash)')
                        .label('ForceDelete')
                }).label('MessagesDeleteQuery'),

                payload: Joi.object({
                    search: searchSchema
                }).label('MessagesDeleteRequest')
            },

            response: {
                schema: Joi.object({
                    deleted: Joi.boolean()
                        .example(false)
                        .description(
                            'Was the delete action executed. IMAP accounts return false when messages were moved to Trash, Gmail API and MS Graph API accounts return true also for moves to Trash'
                        ),
                    moved: Joi.object({
                        destination: Joi.string().required().example('Trash').description('Trash folder path').label('TrashPath'),

                        idMap: idMapSchema,

                        emailIds: Joi.array()
                            .items(emailIdSchema)
                            .description(
                                'An optional list of emailId values, if the server supports unique email IDs (Gmail API and MS Graph API accounts only)'
                            )
                            .label('TrashedEmailIdsArray')
                    })
                        .label('MessagesMovedToTrash')
                        .description('Value is present if messages were moved to Trash'),
                    deletedMessages: Joi.object({
                        emailIds: Joi.array()
                            .items(emailIdSchema)
                            .description('List of emailId values of the permanently deleted messages')
                            .label('DeletedEmailIdsArray')
                    })
                        .label('MessagesDeleted')
                        .description('Value is present if messages were deleted permanently (MS Graph API accounts only)')
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
                handleError(request, err);
            }
        },
        options: {
            description: 'List messages in a folder',
            notes: 'Lists messages in a mailbox folder',
            tags: ['api', 'Message'],

            plugins: {
                mcp: {
                    name: 'list_messages',
                    title: 'List messages',
                    description: 'List messages in one mailbox folder, newest first, paged. The folder path comes from list_mailboxes.',
                    bounds: { pageSize: MCP_MAX_PAGE_SIZE }
                },
                openapi: {
                    responses: apiResponses('Returns a page of messages from the folder, newest first.', 400, 401, 403, 404, 429, 500, 503)
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
                        .description('Page number (zero-indexed, so use 0 for the first page). Only supported for IMAP accounts')
                        .meta({ usage: FIELD_USAGE.messagePage })
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
                handleError(request, err);
            }
        },
        options: {
            description: 'Search for messages',
            notes: 'Filter messages from a mailbox folder by search options. Search is performed against a specific folder and not for the entire account.',
            tags: ['api', 'Message'],

            plugins: {
                mcp: {
                    name: 'search_messages',
                    title: 'Search messages',
                    description:
                        'Search for messages in one folder using structured criteria (from, to, subject, body, date ranges, flags). Searches a single folder, not the whole account.',
                    bounds: { pageSize: MCP_MAX_PAGE_SIZE }
                },
                openapi: {
                    'x-ee-impact': IMPACT.READONLY,
                    responses: apiResponses('Returns a page of matching messages, newest first.', 400, 401, 403, 404, 422, 429, 500, 503)
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
                        .description('Page number (zero-indexed, so use 0 for the first page). Only supported for IMAP accounts')
                        .meta({ usage: FIELD_USAGE.messagePage })
                        .label('PageNumber'),

                    pageSize: Joi.number().integer().min(1).max(1000).default(20).example(20).description('How many entries per page'),

                    useOutlookSearch: Joi.boolean()
                        .truthy('Y', 'true', '1')
                        .falsy('N', 'false', 0)
                        .description('MS Graph only. Use the $search parameter for search queries instead of $filter')
                        .meta({ usage: FIELD_USAGE.useOutlookSearch })
                        .label('useOutlookSearch')
                        .optional(),

                    documentStore: documentStoreSchema.default(false).meta({ swaggerHidden: true }),
                    exposeQuery: Joi.boolean()
                        .truthy('Y', 'true', '1')
                        .falsy('N', 'false', 0)
                        .description('If enabled then includes the combined query (as the documentStoreQuery field) in the response for debugging')
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
                            gmailRaw: 'has:attachment in:unread',
                            labels: {
                                has: ['Important'],
                                not: ['Horizon']
                            }
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
    // Deprecated Document Store feature: only register this endpoint when the feature is enabled,
    // otherwise it behaves like a regular 404.
    if (documentStoreFeatureEnabled) {
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
                    handleError(request, err);
                }
            },
            options: {
                description: 'Unified search for messages',
                notes: 'Filter messages from the Document Store for multiple accounts or paths. Document Store must be enabled for the unified search to work.',
                tags: ['api', 'Deprecated endpoints (Document Store)'],

                plugins: {
                    openapi: {
                        'x-ee-impact': IMPACT.READONLY,
                        responses: apiResponses('Returns matching messages across all indexed accounts.', 400, 401, 403, 429, 500)
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
                            .description('If enabled then includes the combined query (as the documentStoreQuery field) in the response for debugging')
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
                    schema: Joi.object({
                        total: Joi.number()
                            .integer()
                            .example(120)
                            .description('Total number of matching messages (capped at 10000 by the Document Store)')
                            .label('UnifiedTotalNumber'),
                        page: Joi.number().integer().example(0).description('Current page number (zero-based)').label('UnifiedPageNumber'),
                        pages: Joi.number().integer().example(24).description('Total number of pages available').label('UnifiedPagesNumber'),
                        accounts: Joi.array()
                            .items(Joi.string().example('example'))
                            .description('Account filter used for the search, if provided')
                            .label('UnifiedSearchAccountsEcho'),
                        paths: Joi.array()
                            .items(Joi.string().example('INBOX'))
                            .description('Path filter used for the search, if provided')
                            .label('UnifiedSearchPathsEcho'),
                        messages: Joi.array()
                            .items(
                                messageEntrySchema
                                    .keys({
                                        account: accountIdSchema.description('Account ID this message belongs to')
                                    })
                                    .unknown()
                                    .label('UnifiedMessageListEntry')
                            )
                            .label('UnifiedPageMessages'),
                        documentStoreQuery: documentStoreQuerySchema
                    }).label('UnifiedSearchResponse'),
                    failAction: 'log'
                }
            }
        });
    }

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
                handleError(request, err);
            }
        },
        options: {
            description: 'Retrieve message text',
            notes: 'Retrieves message text',
            tags: ['api', 'Message'],

            plugins: {
                mcp: {
                    name: 'get_message_text',
                    title: 'Get message text',
                    description:
                        'Fetch the body of a message as sanitized HTML, generated from the plaintext part when the message carries no HTML one. The text id comes from the text.id field of get_message or list_messages. ' +
                        `It is capped at ${MCP_MESSAGE_TEXT_MAX_BYTES} characters - hasMore true means the body is longer than that. ` +
                        COLLAPSE_MARKER_NOTE,
                    // Same single body shape get_message returns, for the same reason
                    omit: ['textType', 'webSafeHtml', 'maxBytes'],
                    force: { webSafeHtml: true, maxBytes: MCP_MESSAGE_TEXT_MAX_BYTES }
                },
                openapi: {
                    responses: apiResponses('Returns the message text content in the requested formats.', 400, 401, 403, 404, 429, 500, 503)
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
                        .description('Which text content to return, use * for all. By default all contents are returned.')
                        .label('TextSearchTextType'),

                    webSafeHtml: Joi.boolean()
                        .truthy('Y', 'true', '1')
                        .falsy('N', 'false', 0)
                        .default(false)
                        .description('If true, then returns a single sanitized HTML rendering of the body instead of the raw text parts')
                        .meta({ usage: FIELD_USAGE.webSafeText })
                        .label('WebSafeText'),

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
                    plain: Joi.string().example('Hello world').description('Plaintext content. Not returned when webSafeHtml was requested'),
                    html: Joi.string().example('<p>Hello world</p>').description('HTML content'),
                    webSafe: Joi.boolean()
                        .example(true)
                        .description('Whether the HTML content has been processed into a web-safe version (set when webSafeHtml was requested)'),
                    hasMore: Joi.boolean()
                        .example(false)
                        .description('Is the current text output capped or not. Always false for Gmail API and MS Graph API accounts')
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
                handleError(request, err);
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
                mcp: {
                    name: 'get_attachment',
                    title: 'Get attachment',
                    description:
                        'Download one attachment, returned inline as a base64 resource. The attachment id comes from the attachments list of get_message. Fails above 1 MB - larger files have to be fetched over the REST API.',
                    binary: true,
                    resourceUriTemplate: 'emailengine://account/{account}/attachment/{attachment}'
                },
                openapi: {
                    produces: ['application/octet-stream'],
                    responses: apiResponses('Returns the attachment content as a binary stream.', 400, 401, 403, 404, 429, 500, 503)
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
