'use strict';

const Boom = require('@hapi/boom');
const Joi = require('joi');
const { redis } = require('../db');
const { Account } = require('../account');
const getSecret = require('../get-secret');
const { failAction } = require('../tools');
const {
    messageReferenceSchema,
    fromAddressSchema,
    addressSchema,
    idempotencyKeySchema,
    headerTimeoutSchema,
    accountIdSchema,
    templateSchemas,
    settingsSchema,
    ipSchema
} = require('../schemas');

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
                return await accountObject.queueMessage(request.payload, {
                    source: 'api',
                    idempotencyKey: request.headers['idempotency-key'],
                    useStructuredFormat: request.query.useStructuredFormat
                });
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
                    error.output.payload.info = err.info;
                }
                throw error;
            }
        },
        options: {
            payload: {
                maxBytes: MAX_BODY_SIZE,
                timeout: MAX_PAYLOAD_TIMEOUT
            },

            description: 'Submit message for delivery',
            notes: 'Submit message for delivery. If reference message ID is provided then EmailEngine adds all headers and flags required for a reply/forward automatically.',
            tags: ['api', 'Submit'],

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
                    documentStore: Joi.boolean()
                        .truthy('Y', 'true', '1')
                        .falsy('N', 'false', 0)
                        .default(false)
                        .description('If enabled then fetch email used as a reference template from the Document Store'),
                    useStructuredFormat: Joi.boolean()
                        .truthy('Y', 'true', '1')
                        .falsy('N', 'false', 0)
                        .default(false)
                        .description(
                            'For MS Graph accounts: If true, uses structured JSON format (respects from field for shared mailboxes, breaks calendar invites and special MIME types). If false, sends as raw MIME (preserves calendar invites, ignores from field). Default is false (raw MIME).'
                        )
                }).label('SubmitQuery'),

                headers: Joi.object({
                    'x-ee-timeout': headerTimeoutSchema,
                    'idempotency-key': idempotencyKeySchema
                }).unknown(),

                payload: Joi.object({
                    reference: messageReferenceSchema,

                    envelope: Joi.object({
                        from: Joi.string().email().allow('').example('sender@example.com'),
                        to: Joi.array().items(Joi.string().email().required().example('recipient@example.com')).single().label('SmtpEnvelopeTo')
                    })
                        .description(
                            "An optional object specifying the SMTP envelope used during email transmission. If not provided, the envelope is automatically derived from the email's message headers. This is useful when you need the envelope addresses to differ from those in the email headers."
                        )
                        .label('SMTPEnvelope')
                        .when('mailMerge', {
                            is: Joi.exist().not(false, null),
                            then: Joi.forbidden('y')
                        }),

                    raw: Joi.string()
                        .base64()
                        .max(MAX_ATTACHMENT_SIZE)
                        .example('TUlNRS1WZXJzaW9uOiAxLjANClN1YmplY3Q6IGhlbGxvIHdvcmxkDQoNCkhlbGxvIQ0K')
                        .description(
                            'A Base64-encoded email message in RFC 822 format. If you provide other fields along with raw, those fields will override the corresponding values in the raw message.'
                        )
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
                            .description('Markup language for HTML ("html" or "markdown")')
                            .label('RenderFormat'),
                        params: Joi.object().label('RenderValues').description('An object of variables for the template renderer')
                    })
                        .allow(false)
                        .description('Template rendering options')
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
                                params: Joi.object().label('RenderValues').description('An object of variables for the template renderer'),
                                sendAt: Joi.date()
                                    .iso()
                                    .example('2021-07-08T07:06:34.336Z')
                                    .description('Send message at specified time. Overrides message level `sendAt` value.')
                            }).label('MailMergeListEntry')
                        )
                        .min(1)
                        .description(
                            'Mail merge options. A separate email is generated for each recipient. Using mail merge disables `messageId`, `envelope`, `to`, `cc`, `bcc`, `render` keys for the message root.'
                        )
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
                                    .description(
                                        'References an existing attachment by its ID instead of providing new attachment content. If this field is set, the `content` field must not be included. If not set, the `content` field is required.'
                                    )
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
                        .description(
                            "If set then either copies the message to the Sent Mail folder or not. If not set then uses the account's default setting."
                        ),

                    sentMailPath: Joi.string()
                        .empty('')
                        .max(1024)
                        .example('Sent Mail')
                        .description("Upload sent message to this folder. By default the account's Sent Mail folder is used."),

                    locale: Joi.string().empty('').max(100).example('fr').description('Optional locale').label('MessageLocale'),
                    tz: Joi.string().empty('').max(100).example('Europe/Tallinn').description('Optional timezone'),

                    sendAt: Joi.date().iso().example('2021-07-08T07:06:34.336Z').description('Send message at specified time'),
                    deliveryAttempts: Joi.number()
                        .integer()
                        .example(10)
                        .description('How many delivery attempts to make until message is considered as failed'),
                    gateway: Joi.string().max(256).example('example').description('Optional SMTP gateway ID for message routing').label('MessageGateway'),

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

                    dsn: Joi.object({
                        id: Joi.string().trim().empty('').max(256).description('The envelope identifier that would be included in the response (ENVID)'),
                        return: Joi.string()
                            .trim()
                            .empty('')
                            .valid('headers', 'full')
                            .required()
                            .description('Specifies if only headers or the entire body of the message should be included in the response (RET)')
                            .label('DsnReturn'),
                        notify: Joi.array()
                            .single()
                            .items(Joi.string().valid('never', 'success', 'failure', 'delay').label('NotifyEntry'))
                            .description('Defines the conditions under which a DSN response should be sent')
                            .label('DsnNotify'),
                        recipient: Joi.string().trim().empty('').email().description('The email address the DSN should be sent (ORCPT)')
                    })
                        .description('Request DSN notifications')
                        .label('DSN'),

                    baseUrl: Joi.string()
                        .trim()
                        .empty('')
                        .uri({
                            scheme: ['http', 'https'],
                            allowRelative: false
                        })
                        .example('https://customer123.myservice.com')
                        .description('Optional base URL for trackers. This URL must point to your EmailEngine instance.'),

                    proxy: settingsSchema.proxyUrl.description('Optional proxy URL to use when connecting to the SMTP server'),
                    localAddress: ipSchema.description('Optional local IP address to bind to when connecting to the SMTP server'),

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
                            .required()
                            .example('AAAAAQAACnA')
                            .description('Referenced message ID'),
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
                        .description('Base64 encoded RFC822 email if a preview was requested')
                        .label('ResponsePreview'),

                    mailMerge: Joi.array()
                        .items(
                            Joi.object({
                                success: Joi.boolean()
                                    .example(true)
                                    .description('Was the referenced message processed successfully')
                                    .label('ResponseReferenceSuccess'),
                                to: addressSchema.label('ToAddressSingle'),
                                messageId: Joi.string().max(996).example('<test123@example.com>').description('Message ID'),
                                queueId: Joi.string()
                                    .example('d41f0423195f271f')
                                    .description('Queue identifier for scheduled email. Not present for bulk messages.'),
                                reference: Joi.object({
                                    message: Joi.string()
                                        .base64({ paddingRequired: false, urlSafe: true })
                                        .max(256)
                                        .required()
                                        .example('AAAAAQAACnA')
                                        .description('Referenced message ID'),
                                    documentStore: Joi.boolean()
                                        .example(true)
                                        .description('Was the message data loaded from the Document Store')
                                        .label('ResponseDocumentStore')
                                        .meta({ swaggerHidden: true }),
                                    success: Joi.boolean()
                                        .example(true)
                                        .description('Was the referenced message processed successfully')
                                        .label('ResponseReferenceSuccess'),
                                    error: Joi.string()
                                        .example('Referenced message was not found')
                                        .description('An error message if referenced message processing failed')
                                })
                                    .description('Reference info if referencing was requested')
                                    .label('ResponseReference'),
                                sendAt: Joi.date()
                                    .iso()
                                    .example('2021-07-08T07:06:34.336Z')
                                    .description('Send message at specified time. Overrides message level `sendAt` value.'),
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
                                    reference: {
                                        message: 'AAAAAQAACnA',
                                        success: true
                                    },
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
}

module.exports = init;
