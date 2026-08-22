'use strict';

const Joi = require('joi');
const { redis } = require('../db');
const { Account } = require('../account');
const getSecret = require('../get-secret');
const { failAction } = require('../tools');
const { handleError, assertNoNetworkOverride } = require('./route-helpers');
const BEHAVIOR = require('./behavior-notes');
const { IMPACT } = require('./operation-impact');
const { FIELD_USAGE } = require('../field-usage');
const {
    messageReferenceSchema,
    fromAddressSchema,
    addressSchema,
    idempotencyKeySchema,
    headerTimeoutSchema,
    accountIdSchema,
    templateSchemas,
    settingsSchema,
    ipSchema,
    threadIdSchema,
    apiResponses,
    ENUM_DESCRIPTIONS
} = require('../schemas');

// Schema fragments shared between the message submit and the draft submit routes. Joi schemas
// are immutable, so per-route variants are derived with .description()/.label() where needed.
const submitHeadersSchema = Joi.object({
    'x-ee-timeout': headerTimeoutSchema,
    'idempotency-key': idempotencyKeySchema
}).unknown();

const sendAtSchema = Joi.date().iso().example('2021-07-08T07:06:34.336Z').description('Send message at specified time');

const deliveryAttemptsSchema = Joi.number().integer().example(10).description('How many delivery attempts to make until message is considered as failed');

const gatewaySchema = Joi.string().max(256).example('example').description('Optional SMTP gateway ID for message routing').label('MessageGateway');

const dsnSchema = Joi.object({
    id: Joi.string()
        .trim()
        .empty('')
        .max(256)
        .example('order-4815-notify')
        .description('The envelope identifier that would be included in the response (ENVID)'),
    return: Joi.string()
        .trim()
        .empty('')
        .valid('headers', 'full')
        .required()
        .description('Specifies if only headers or the entire body of the message should be included in the response (RET)')
        .label('DsnReturn'),
    notify: Joi.array()
        .single()
        .items(Joi.string().valid('never', 'success', 'failure', 'delay').meta({ enumDescriptions: ENUM_DESCRIPTIONS.dsnNotify }).label('NotifyEntry'))
        .example(['failure', 'delay'])
        .description('Defines the conditions under which a DSN response should be sent')
        .label('DsnNotify'),
    recipient: Joi.string().trim().empty('').email().example('bounces@example.com').description('The email address the DSN should be sent (ORCPT)')
}).description('Request DSN notifications');

// Refused for a token that carries a `permissions` record, see assertNoNetworkOverride() - the
// override decides where a session carrying the account's SMTP credentials connects, so it is not
// something a narrowed credential may set. Said in the description because the alternative is a 403
// that reads as a permission bug.
const proxySchema = settingsSchema.proxyUrl.description(
    'Optional proxy URL to use when connecting to the SMTP server. A token with restricted permissions can not set this - it redirects a session that carries the account credentials'
);

const localAddressSchema = ipSchema.description('Optional local IP address to bind to when connecting to the SMTP server');

const idempotencyResponseSchema = Joi.object({
    key: idempotencyKeySchema.example('submit-12345').description('Idempotency key from the request').label('ResponseIdempotencyKey'),
    status: Joi.string()
        .valid('MISS', 'HIT')
        .example('MISS')
        .description('Whether this response was produced now or replayed from the idempotency cache')
        .meta({ enumDescriptions: ENUM_DESCRIPTIONS.idempotencyStatus })
})
    .description('Idempotency info, present when an Idempotency-Key header was used')
    .label('ResponseIdempotency');

async function init(args) {
    const { server, call, CORS_CONFIG, MAX_ATTACHMENT_SIZE, MAX_BODY_SIZE, MAX_PAYLOAD_TIMEOUT } = args;

    server.route({
        method: 'POST',
        path: '/v1/account/{account}/submit',

        async handler(request) {
            let accountObject = new Account({
                redis,
                account: request.params.account,
                call,
                secret: await getSecret(),
                timeout: request.headers['x-ee-timeout']
            });

            try {
                assertNoNetworkOverride(request);

                return await accountObject.queueMessage(request.payload, {
                    source: 'api',
                    idempotencyKey: request.headers['idempotency-key'],
                    useStructuredFormat: request.query.useStructuredFormat
                });
            } catch (err) {
                handleError(request, err);
            }
        },
        options: {
            payload: {
                maxBytes: MAX_BODY_SIZE,
                timeout: MAX_PAYLOAD_TIMEOUT
            },

            description: 'Submit message for delivery',
            notes: [
                'Submit message for delivery. If reference message ID is provided then EmailEngine adds all headers and flags required for a reply/forward automatically.',
                BEHAVIOR.QUEUED_DELIVERY,
                BEHAVIOR.SENT_FOLDER_UPLOAD
            ],
            tags: ['api', 'Submit'],

            plugins: {
                mcp: {
                    name: 'send_message',
                    title: 'Send message',
                    description:
                        'Send an email from the account to real recipients - confirm with the user before calling this. Takes structured fields (to, subject, text, html). ' +
                        'To answer or pass on a message the user is looking at, set `reference.message` to its id and `reference.action` to reply, reply-all or forward, ' +
                        'and write only the new text: the subject, the recipients (for a reply) and the threading headers come from the referenced message. ' +
                        'Add `reference.inline` to quote the original under it, and `reference.forwardAttachments` to carry its attachments along when forwarding. ' +
                        'Delivery is queued; the response carries the queue id for get_outbox.',
                    // `proxy` retargets where the session carrying the account's SMTP
                    // credentials connects; no agent has business setting it. `localAddress`
                    // is a host networking detail and `documentStore` is the deprecated
                    // Document Store flag - both are noise in an agent-facing schema.
                    omit: ['proxy', 'localAddress', 'documentStore']
                },
                openapi: {
                    'x-ee-impact': IMPACT.SENDS,
                    'x-ee-behavior': [BEHAVIOR.QUEUED_DELIVERY, BEHAVIOR.SENT_FOLDER_UPLOAD],
                    responses: apiResponses(
                        'Returns the queue ID the message was accepted under. Delivery happens asynchronously - a 200 means queued, not sent.',
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
                    documentStore: Joi.boolean()
                        .truthy('Y', 'true', '1')
                        .falsy('N', 'false', 0)
                        .default(false)
                        .description('If enabled then fetch email used as a reference template from the Document Store'),
                    useStructuredFormat: Joi.boolean()
                        .truthy('Y', 'true', '1')
                        .falsy('N', 'false', 0)
                        .default(false)
                        .description('For MS Graph accounts: send as structured JSON instead of raw MIME')
                        .meta({ usage: FIELD_USAGE.useStructuredFormat })
                }).label('SubmitQuery'),

                headers: submitHeadersSchema,

                payload: Joi.object({
                    reference: messageReferenceSchema,

                    envelope: Joi.object({
                        from: Joi.string().email().allow('').example('sender@example.com'),
                        to: Joi.array().items(Joi.string().email().required().example('recipient@example.com')).single().label('SmtpEnvelopeTo')
                    })
                        .description('An optional object specifying the SMTP envelope used during email transmission')
                        .meta({ usage: FIELD_USAGE.messageEnvelope })
                        .label('SMTPEnvelope')
                        .when('mailMerge', {
                            is: Joi.exist().not(false, null),
                            then: Joi.forbidden('y')
                        }),

                    raw: Joi.string()
                        .base64()
                        .max(MAX_ATTACHMENT_SIZE)
                        .example('TUlNRS1WZXJzaW9uOiAxLjANClN1YmplY3Q6IGhlbGxvIHdvcmxkDQoNCkhlbGxvIQ0K')
                        .description('A Base64-encoded email message in RFC 822 format')
                        .meta({ usage: FIELD_USAGE.messageRaw })
                        .label('RFC822Raw')
                        .when('mailMerge', {
                            is: Joi.exist().not(false, null),
                            then: Joi.forbidden('y')
                        }),

                    from: fromAddressSchema,

                    replyTo: Joi.array()
                        .items(addressSchema.label('ReplyToAddress'))
                        .single()
                        .example([{ name: 'From Me', address: 'sender@example.com' }])
                        .description('List of Reply-To addresses')
                        .label('ReplyTo'),

                    to: Joi.array()
                        .items(addressSchema.label('ToAddress'))
                        .single()
                        .example([{ address: 'recipient@example.com' }])
                        .description('List of recipient addresses')
                        .label('ToAddressList')
                        .when('mailMerge', {
                            is: Joi.exist().not(false, null),
                            then: Joi.forbidden('y')
                        }),

                    cc: Joi.array()
                        .items(addressSchema.label('CcAddress'))
                        .single()
                        .description('List of CC addresses')
                        .label('CcAddressList')
                        .when('mailMerge', {
                            is: Joi.exist().not(false, null),
                            then: Joi.forbidden('y')
                        }),

                    bcc: Joi.array()
                        .items(addressSchema.label('BccAddress'))
                        .single()
                        .description('List of BCC addresses')
                        .label('BccAddressList')
                        .when('mailMerge', {
                            is: Joi.exist().not(false, null),
                            then: Joi.forbidden('y')
                        }),

                    subject: templateSchemas.subject,
                    text: templateSchemas.text,
                    html: templateSchemas.html,
                    previewText: templateSchemas.previewText,

                    template: Joi.string().max(256).example('example').description('Stored template ID to load the email content from'),

                    render: Joi.object({
                        format: Joi.string()
                            .valid('html', 'markdown')
                            .default('html')
                            .description('Markup language the template is written in')
                            .meta({ enumDescriptions: ENUM_DESCRIPTIONS.renderFormat })
                            .label('RenderFormat'),
                        params: Joi.object()
                            .label('RenderValues')
                            .example({ firstName: 'Nyan', orderId: '4815' })
                            .description('An object of variables for the template renderer')
                    })
                        .allow(false)
                        .description('Template rendering options. Set to `false` to send the template as-is, without rendering it.')
                        .when('mailMerge', {
                            is: Joi.exist().not(false, null),
                            then: Joi.forbidden('y')
                        })
                        .label('TemplateRender'),

                    mailMerge: Joi.array()
                        .items(
                            Joi.object({
                                to: addressSchema.label('ToAddress').required(),
                                messageId: Joi.string().max(996).example('<test123@example.com>').description('Message ID'),
                                params: Joi.object()
                                    .label('RenderValues')
                                    .example({ firstName: 'Nyan', orderId: '4815' })
                                    .description('An object of variables for the template renderer'),
                                sendAt: Joi.date()
                                    .iso()
                                    .example('2021-07-08T07:06:34.336Z')
                                    .description('Send message at specified time. Overrides message level `sendAt` value.')
                            }).label('MailMergeListEntry')
                        )
                        .min(1)
                        .description('Mail merge options. A separate email is generated for each recipient')
                        .meta({ usage: FIELD_USAGE.mailMerge })
                        .label('MailMergeList'),

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
                                contentDisposition: Joi.string().lowercase().valid('inline', 'attachment').label('AttachmentContentDisposition'),
                                cid: Joi.string().max(256).example('unique-image-id@localhost').description('Content-ID value for embedded images'),
                                encoding: Joi.string().valid('base64').default('base64').label('AttachmentEncoding'),

                                reference: Joi.string()
                                    .base64({ paddingRequired: false, urlSafe: true })
                                    .max(256)
                                    .allow(false, null)
                                    .example('AAAAAQAACnAcde')
                                    .description('References an existing attachment by its ID instead of providing new attachment content')
                                    .meta({ usage: FIELD_USAGE.attachmentReference })
                                    .label('AttachmentReference')
                            }).label('UploadAttachment')
                        )
                        .description('List of attachments')
                        .label('UploadAttachmentList'),

                    messageId: Joi.string().max(996).example('<test123@example.com>').description('Message ID'),
                    headers: Joi.object().label('CustomHeaders').description('Custom Headers').unknown().example({
                        'X-My-Custom-Header': 'Custom header value'
                    }),

                    trackingEnabled: Joi.boolean()
                        .example(false)
                        .description('Should EmailEngine track clicks and opens for this message')
                        .meta({ swaggerHidden: true }),

                    trackOpens: Joi.boolean().example(false).description('Should EmailEngine track opens for this message'),
                    trackClicks: Joi.boolean().example(false).description('Should EmailEngine track clicks for this message'),

                    copy: Joi.boolean()
                        .allow(null)
                        .example(null)
                        .description("If set then either copies the message to the Sent Mail folder or not. If not set then uses the account's default setting")
                        .meta({ usage: FIELD_USAGE.messageCopy }),

                    sentMailPath: Joi.string()
                        .empty('')
                        .max(1024)
                        .example('Sent Mail')
                        .description("Upload sent message to this folder. By default the account's Sent Mail folder is used."),

                    locale: Joi.string().empty('').max(100).example('fr').description('Optional locale').label('MessageLocale'),
                    tz: Joi.string().empty('').max(100).example('Europe/Tallinn').description('Optional timezone'),

                    sendAt: sendAtSchema,
                    deliveryAttempts: deliveryAttemptsSchema,
                    gateway: gatewaySchema,

                    listId: Joi.string()
                        .hostname()
                        .example('test-list')
                        .description(
                            'List ID for Mail Merge. Must use a subdomain name format. Lists are registered ad-hoc, so a new identifier defines a new list.'
                        )
                        .label('ListID')
                        .when('mailMerge', {
                            is: Joi.exist().not(false, null),
                            then: Joi.optional(),
                            otherwise: Joi.forbidden()
                        }),

                    dsn: dsnSchema.label('DSN'),

                    baseUrl: Joi.string()
                        .trim()
                        .empty('')
                        .uri({
                            scheme: ['http', 'https'],
                            allowRelative: false
                        })
                        .example('https://customer123.myservice.com')
                        .description('Optional base URL for trackers. This URL must point to your EmailEngine instance.'),

                    proxy: proxySchema,
                    localAddress: localAddressSchema,

                    dryRun: Joi.boolean()
                        .truthy('Y', 'true', '1')
                        .falsy('N', 'false', 0)
                        .default(false)
                        .description(
                            'If true, then EmailEngine does not send the email and returns an RFC822 formatted email file. Tracking information is not added to the email.'
                        )
                        .label('Preview')
                })
                    .oxor('raw', 'html')
                    .oxor('raw', 'text')
                    .oxor('raw', 'text')
                    .oxor('raw', 'attachments')
                    .label('SubmitMessage')
                    .example({
                        to: [
                            {
                                name: 'Nyan Cat',
                                address: 'nyan.cat@example.com'
                            }
                        ],
                        subject: 'What a wonderful message!',
                        text: 'Hello from myself!',
                        html: '<p>Hello from myself!</p>',
                        attachments: [
                            {
                                filename: 'transparent.gif',
                                content: 'R0lGODlhAQABAIAAAP///wAAACwAAAAAAQABAAACAkQBADs=',
                                contentType: 'image/gif'
                            }
                        ]
                    })
            },

            response: {
                schema: Joi.object({
                    response: Joi.string().example('Queued for delivery'),
                    messageId: Joi.string()
                        .example('<a2184d08-a470-fec6-a493-fa211a3756e9@example.com>')
                        .description('Message-ID header value. Not present for bulk messages.'),
                    queueId: Joi.string().example('d41f0423195f271f').description('Queue identifier for scheduled email. Not present for bulk messages.'),
                    sendAt: Joi.date().example('2021-07-08T07:06:34.336Z').description('Scheduled send time'),

                    reference: Joi.object({
                        message: Joi.string()
                            .base64({ paddingRequired: false, urlSafe: true })
                            .max(256)
                            .example('AAAAAQAACnA')
                            .description('Referenced message ID. Not present when only a thread ID was referenced'),
                        threadId: threadIdSchema.description('Referenced thread ID (Gmail API accounts only)').label('SubmitResponseReferenceThreadId'),
                        documentStore: Joi.boolean()
                            .example(true)
                            .description('Was the message data loaded from the Document Store')
                            .label('ResponseDocumentStore')
                            .meta({ swaggerHidden: true }),
                        success: Joi.boolean().example(true).description('Was the referenced message processed successfully').label('ResponseReferenceSuccess'),
                        error: Joi.string().example('Referenced message was not found').description('An error message if referenced message processing failed')
                    })
                        .description('Reference info if referencing was requested')
                        .label('ResponseReference'),

                    preview: Joi.string()
                        .base64()
                        .example('Q29udGVudC1UeXBlOiBtdWx0aX...')
                        .description('Base64 encoded RFC822 email if a preview was requested. Not returned for mail-merge submissions.')
                        .label('ResponsePreview'),

                    idempotency: idempotencyResponseSchema,

                    mailMerge: Joi.array()
                        .items(
                            Joi.object({
                                success: Joi.boolean().example(true).description('Was the message queued successfully').label('ResponseReferenceSuccess'),
                                to: addressSchema.label('ToAddressSingle'),
                                messageId: Joi.string().max(996).example('<test123@example.com>').description('Message ID'),
                                queueId: Joi.string().example('d41f0423195f271f').description('Queue identifier for the scheduled email'),
                                sendAt: Joi.date().iso().example('2021-07-08T07:06:34.336Z').description('Scheduled send time for this recipient'),
                                error: Joi.string().example('Failed to queue message').description('Error message if queueing failed for this recipient'),
                                code: Joi.string().example('EENVELOPE').description('Error code if queueing failed for this recipient'),
                                statusCode: Joi.number()
                                    .integer()
                                    .allow(null)
                                    .example(500)
                                    .description('Error status code if queueing failed for this recipient'),
                                skipped: Joi.object({
                                    reason: Joi.string().example('unsubscribe').description('Why this message was skipped'),
                                    listId: Joi.string().example('test-list')
                                })
                                    .description('Info about skipped message. If this value is set, then the message was not sent')
                                    .label('SkippedMessageInfo')
                            })
                                .label('BulkResponseEntry')
                                .example({
                                    success: true,
                                    to: {
                                        name: 'Andris 2',
                                        address: 'andris@ethereal.email'
                                    },
                                    messageId: '<19b9c433-d428-f6d8-1d00-d666ebcadfc4@ekiri.ee>',
                                    queueId: '1812477338914c8372a',
                                    sendAt: '2021-07-08T07:06:34.336Z'
                                })
                                .unknown()
                        )
                        .label('BulkResponseList')
                        .description('Bulk message responses')
                }).label('SubmitMessageResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/v1/account/{account}/message/{message}/submit',

        async handler(request) {
            let accountObject = new Account({
                redis,
                account: request.params.account,
                call,
                secret: await getSecret(),
                timeout: request.headers['x-ee-timeout']
            });

            try {
                assertNoNetworkOverride(request);

                return await accountObject.queueMessage(request.payload || {}, {
                    source: 'api',
                    idempotencyKey: request.headers['idempotency-key'],
                    draft: { message: request.params.message }
                });
            } catch (err) {
                handleError(request, err);
            }
        },
        options: {
            description: 'Submit a stored draft for delivery',
            notes: [
                'Sends an existing draft message. The message must be a draft: stored in the Drafts folder or flagged as a draft (IMAP), carrying the DRAFT label (Gmail), or a draft message (MS Graph). Gmail and MS Graph accounts use the native draft-send call of the provider, which also files the message into the Sent Mail folder and removes the draft. For IMAP accounts the draft is downloaded, sent over SMTP, copied to the Sent Mail folder (unless disabled), and then removed from the Drafts folder.',
                BEHAVIOR.QUEUED_DELIVERY,
                BEHAVIOR.SENT_FOLDER_UPLOAD
            ],
            tags: ['api', 'Submit'],

            plugins: {
                openapi: {
                    'x-ee-impact': IMPACT.SENDS,
                    'x-ee-behavior': [BEHAVIOR.QUEUED_DELIVERY, BEHAVIOR.SENT_FOLDER_UPLOAD],

                    // Every property of this payload is an optional override, so a snippet
                    // synthesized from the schema shows an envelope, a DSN block and a proxy
                    // as if they were the request. The draft already carries its recipients
                    // and content; the call that matters is the empty one. Hand-written
                    // samples lead the tab strip on the reference page and reach every other
                    // consumer of /swagger.json through the standard extension.
                    'x-codeSamples': [
                        {
                            lang: 'bash',
                            label: 'Minimal',
                            source: [
                                `curl -X POST "$EMAILENGINE_URL/v1/account/example/message/AAAAAQAACnA/submit" \\`,
                                `    -H "Authorization: Bearer $EMAILENGINE_TOKEN" \\`,
                                `    -H "Content-Type: application/json" \\`,
                                `    -d '{}'`
                            ].join('\n')
                        }
                    ],

                    responses: apiResponses(
                        'Returns the queue ID the stored draft was accepted under. Delivery happens asynchronously - a 200 means queued, not sent.',
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
                    account: accountIdSchema.required(),
                    message: Joi.string().max(256).required().example('AAAAAQAACnA').description('Message ID of the draft')
                }),

                headers: submitHeadersSchema,

                payload: Joi.object({
                    envelope: Joi.object({
                        from: Joi.string().email().allow('').example('sender@example.com'),
                        to: Joi.array().items(Joi.string().email().required().example('recipient@example.com')).single().label('DraftSmtpEnvelopeTo')
                    })
                        .description(
                            'An optional object specifying the SMTP envelope used during email transmission. Only used when the message is delivered over SMTP'
                        )
                        .meta({ usage: FIELD_USAGE.messageEnvelope })
                        .label('DraftSMTPEnvelope'),

                    copy: Joi.boolean()
                        .allow(null)
                        .example(null)
                        .description("If set then either copies the message to the Sent Mail folder or not. If not set then uses the account's default setting")
                        .meta({ usage: FIELD_USAGE.messageCopy }),

                    sentMailPath: Joi.string()
                        .empty('')
                        .max(1024)
                        .example('Sent Mail')
                        .description("Upload sent message to this folder. By default the account's Sent Mail folder is used. Only applies to SMTP deliveries."),

                    sendAt: sendAtSchema,
                    deliveryAttempts: deliveryAttemptsSchema,
                    gateway: gatewaySchema,

                    dsn: dsnSchema.description('Request DSN notifications. Only used when the message is delivered over SMTP.').label('DraftDSN'),

                    proxy: proxySchema,
                    localAddress: localAddressSchema
                })
                    .allow(null)
                    .label('SubmitDraft')
            },

            response: {
                schema: Joi.object({
                    response: Joi.string().example('Queued for delivery'),
                    messageId: Joi.string().example('<a2184d08-a470-fec6-a493-fa211a3756e9@example.com>').description('Message-ID header value'),
                    queueId: Joi.string().example('d41f0423195f271f').description('Queue identifier for scheduled email'),
                    sendAt: Joi.date().example('2021-07-08T07:06:34.336Z').description('Scheduled send time'),

                    idempotency: idempotencyResponseSchema
                }).label('SubmitDraftResponse'),
                failAction: 'log'
            }
        }
    });
}

module.exports = init;
