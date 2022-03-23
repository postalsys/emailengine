'use strict';

const Joi = require('joi');

const RESYNC_DELAY = 15 * 60;

const ADDRESS_STRATEGIES = [
    { key: 'default', title: 'Default' },
    { key: 'dedicated', title: 'Dedicated' },
    { key: 'random', title: 'Random' }
];

// allowed configuration keys
const settingsSchema = {
    webhooksEnabled: Joi.boolean().truthy('Y', 'true', '1').falsy('N', 'false', 0).description('If false then do not emit webhooks'),

    webhooks: Joi.string()
        .uri({
            scheme: ['http', 'https'],
            allowRelative: false
        })
        .allow('')
        .example('https://myservice.com/imap/webhooks')
        .description('Webhook URL'),

    webhookEvents: Joi.array().items(Joi.string().max(256).example('messageNew')),

    notifyHeaders: Joi.array().items(Joi.string().max(256).example('List-ID')),

    serviceUrl: Joi.string()
        .uri({
            scheme: ['http', 'https'],
            allowRelative: false
        })
        .allow('')
        .example('https://emailengine.example.com')
        .description('Base URL of EmailEngine')
        .label('ServiceURL'),

    trackSentMessages: Joi.boolean()
        .truthy('Y', 'true', '1', 'on')
        .falsy('N', 'false', 0, '')
        .description('If true, then rewrite html links in sent emails to track opens and clicks'),

    serviceSecret: Joi.string().allow('').example('verysecr8t').description('HMAC secret for signing public requests').label('ServiceSecret'),

    authServer: Joi.string()
        .uri({
            scheme: ['http', 'https'],
            allowRelative: false
        })
        .allow('')
        .example('https://myservice.com/authentication')
        .description('URL to fetch authentication data from')
        .label('AuthServer'),

    proxyEnabled: Joi.boolean().truthy('Y', 'true', '1', 'on').falsy('N', 'false', 0, '').description('Is the global proxy enabled or not'),
    proxyUrl: Joi.string()
        .uri({
            scheme: ['http', 'https', 'socks', 'scoks4', 'socks5'],
            allowRelative: false
        })
        .allow('')
        .example('socks://proxy.example.com:1080')
        .description('Proxy URL')
        .label('ProxyURL'),

    notifyText: Joi.boolean().truthy('Y', 'true', '1', 'on').falsy('N', 'false', 0, '').description('Include message text in webhook notification'),

    notifyTextSize: Joi.number().min(0),

    gmailEnabled: Joi.boolean().truthy('Y', 'true', '1').falsy('N', 'false', 0).description('If true then do not show Gmail account option'),
    gmailClientId: Joi.string().allow('').max(256).description('Gmail OAuth2 Client ID'),
    gmailClientSecret: Joi.string().empty('').max(256).description('Gmail OAuth2 Client Secret'),
    gmailRedirectUrl: Joi.string()
        .allow('')
        .uri({ scheme: ['http', 'https'], allowRelative: false })
        .description('Gmail OAuth2 Callback URL'),

    outlookEnabled: Joi.boolean().truthy('Y', 'true', '1').falsy('N', 'false', 0).description('If true then do not show Outlook account option'),
    outlookClientId: Joi.string().allow('').max(256).description('Outlook OAuth2 Client ID'),
    outlookClientSecret: Joi.string().empty('').max(256).description('Outlook OAuth2 Client Secret'),
    outlookRedirectUrl: Joi.string()
        .allow('')
        .uri({ scheme: ['http', 'https'], allowRelative: false })
        .description('Outlook OAuth2 Callback URL'),
    outlookAuthority: Joi.string().empty('').allow('consumers', 'organizations', 'common').example('consumers'),

    serviceClient: Joi.string().trim().allow('').max(256).description('OAuth2 Service Client ID'),
    serviceKey: Joi.string()
        .trim()
        .empty('')
        .max(100 * 1024)
        .description('OAuth2 Secret Service Key'),

    logs: Joi.object({
        all: Joi.boolean().truthy('Y', 'true', '1').falsy('N', 'false', 0).default(false).description('Enable logs for all accounts'),
        maxLogLines: Joi.number().min(0).max(1000000).default(10000)
    }).label('LogSettings'),

    imapStrategy: Joi.string()
        .empty('')
        .valid(...ADDRESS_STRATEGIES.map(entry => entry.key))
        .description('How to select local IP address for IMAP connections'),
    smtpStrategy: Joi.string()
        .empty('')
        .valid(...ADDRESS_STRATEGIES.map(entry => entry.key))
        .description('How to select local IP address for SMTP connections'),
    localAddresses: Joi.array()
        .items(
            Joi.string().ip({
                version: ['ipv4', 'ipv6'],
                cidr: 'forbidden'
            })
        )
        .single()
        .description('A list of pooled local IP addresses that can be used for IMAP and SMTP connections'),

    smtpServerEnabled: Joi.boolean().truthy('Y', 'true', '1', 'on').falsy('N', 'false', 0, '').description('Enable SMTP Server'),
    smtpServerPort: Joi.number()
        .min(0)
        .max(64 * 1024)
        .empty('')
        .description('SMTP Server Port'),
    smtpServerHost: Joi.string()
        .ip({
            version: ['ipv4', 'ipv6'],
            cidr: 'forbidden'
        })
        .empty('')
        .description('SMTP Host to bind to'),
    smtpServerProxy: Joi.boolean().truthy('Y', 'true', '1', 'on').falsy('N', 'false', 0, '').description('Enable PROXY Protocol for SMTP server'),
    smtpServerAuthEnabled: Joi.boolean().truthy('Y', 'true', '1', 'on').falsy('N', 'false', 0, '').description('Enable SMTP authentication'),
    smtpServerPassword: Joi.string().empty('').max(1024).description('SMTP client password'),

    queueKeep: Joi.number().empty('').min(0).description('How many completed or failed queue entries to keep'),

    templateHeader: Joi.string()
        .empty('')
        .trim()
        .max(1024 * 1024)
        .description('HTML code displayed on the top of public pages like the hosted authentication form'),

    enableApiProxy: Joi.boolean().truthy('Y', 'true', '1', 'on').falsy('N', 'false', 0, '').description('Enable support for reverse proxies')
};

const addressSchema = Joi.object({
    name: Joi.string().max(256).example('Some Name'),
    address: Joi.string()
        .email({
            ignoreLength: false
        })
        .example('user@example.com')
        .required()
}).label('Address');

// generate a list of boolean values
const settingsQuerySchema = Object.fromEntries(
    Object.keys(Object.assign({ eventTypes: true }, settingsSchema)).map(key => [
        key,
        Joi.boolean().truthy('Y', 'true', '1').falsy('N', 'false', 0).default(false)
    ])
);

const imapSchema = {
    auth: Joi.object({
        user: Joi.string().max(256).required().example('myuser@gmail.com').description('Account username'),
        pass: Joi.string().max(256).example('verysecret').description('Account password'),
        accessToken: Joi.string()
            .max(4 * 4096)
            .description('Access token for OAuth2')
    })
        .xor('pass', 'accessToken')
        .description('Authentication info')
        .label('Authentication'),

    useAuthServer: Joi.boolean().example(false).description('Set to true to use authentication server instead of username/password'),

    host: Joi.string().hostname().required().example('imap.gmail.com').description('Hostname to connect to'),
    port: Joi.number()
        .min(1)
        .max(64 * 1024)
        .required()
        .example(993)
        .description('Service port number'),
    secure: Joi.boolean().default(false).example(true).description('Should connection use TLS. Usually true for port 993'),
    tls: Joi.object({
        rejectUnauthorized: Joi.boolean().default(true).example(true).description('How to treat invalid certificates'),
        minVersion: Joi.string().max(256).example('TLSv1.2').description('Minimal TLS version')
    })
        .description('Optional TLS configuration')
        .label('TLS'),
    resyncDelay: Joi.number().example(RESYNC_DELAY).description('Full resync delay in seconds').default(RESYNC_DELAY)
};

const smtpSchema = {
    auth: Joi.object({
        user: Joi.string().max(256).required().example('myuser@gmail.com').description('Account username'),
        pass: Joi.string().max(256).example('verysecret').description('Account password'),
        accessToken: Joi.string()
            .max(4 * 4096)
            .description('Access token for OAuth2')
    })
        .allow(false)
        .xor('pass', 'accessToken')
        .description('Authentication info')
        .label('Authentication'),

    useAuthServer: Joi.boolean().example(false).description('Set to true to use authentication server instead of username/password'),

    host: Joi.string().hostname().required().example('smtp.gmail.com').description('Hostname to connect to'),
    port: Joi.number()
        .min(1)
        .max(64 * 1024)
        .required()
        .example(587)
        .description('Service port number'),
    secure: Joi.boolean().default(false).example(false).description('Should connection use TLS. Usually true for port 465'),
    tls: Joi.object({
        rejectUnauthorized: Joi.boolean().default(true).example(true).description('How to treat invalid certificates'),
        minVersion: Joi.string().max(256).example('TLSv1.2').description('Minimal TLS version')
    })
        .description('Optional TLS configuration')
        .label('TLS')
};

const oauth2Schema = {
    authorize: Joi.boolean().example(true).description('Return a redirect link to the OAuth2 consent screen'),
    provider: Joi.string().empty('').valid('gmail', 'gmailService', 'outlook').description('OAuth provider'),

    auth: Joi.object({
        user: Joi.string().max(256).required().example('myuser@gmail.com').description('Account username')
    }),

    accessToken: Joi.string()
        .max(4 * 4096)
        .example('ya29.a0ARrdaM8a...'),
    refreshToken: Joi.string()
        .max(4 * 4096)
        .example('1//09Ie3CtORQYm...'),

    authority: Joi.any()
        .when('provider', {
            switch: [
                {
                    is: 'gmail',
                    then: Joi.string().empty('').forbidden()
                },
                {
                    is: 'gmailService',
                    then: Joi.string().empty('').forbidden()
                },

                {
                    is: 'outlook',
                    then: Joi.string().empty('').max(1024).allow('consumers', 'organizations', 'common').default('consumers').example('consumers')
                }
            ]
        })
        .label('SupportedAccountTypes'),
    expires: Joi.date().iso().example('2021-03-22T13:13:31.000Z').description('Token expiration date')
};

const imapUpdateSchema = {
    auth: Joi.object({
        user: Joi.string().max(256).example('myuser@gmail.com').description('Account username'),
        pass: Joi.string().max(256).example('verysecret').description('Account password'),
        accessToken: Joi.string()
            .max(4 * 4096)
            .description('Access token for OAuth2')
    })
        .xor('pass', 'accessToken')
        .description('Authentication info')
        .label('Authentication'),

    useAuthServer: Joi.boolean().example(false).description('Set to true to use authentication server instead of username/password'),

    host: Joi.string().hostname().example('imap.gmail.com').description('Hostname to connect to'),
    port: Joi.number()
        .min(1)
        .max(64 * 1024)
        .example(993)
        .description('Service port number'),
    secure: Joi.boolean().example(true).description('Should connection use TLS. Usually true for port 993'),
    tls: Joi.object({
        rejectUnauthorized: Joi.boolean().example(true).description('How to treat invalid certificates'),
        minVersion: Joi.string().max(256).example('TLSv1.2').description('Minimal TLS version')
    })
        .description('Optional TLS configuration')
        .label('TLS'),
    resyncDelay: Joi.number().example(RESYNC_DELAY).description('Full resync delay in seconds'),
    partial: Joi.boolean().example(false).description('Update only listed keys in the imap config').default(false)
};

const smtpUpdateSchema = {
    auth: Joi.object({
        user: Joi.string().max(256).example('myuser@gmail.com').description('Account username'),
        pass: Joi.string().max(256).example('verysecret').description('Account password'),
        accessToken: Joi.string()
            .max(4 * 4096)
            .description('Access token for OAuth2')
    })
        .allow(false)
        .xor('pass', 'accessToken')
        .description('Authentication info')
        .label('Authentication'),

    useAuthServer: Joi.boolean().example(false).description('Set to true to use authentication server instead of username/password'),

    host: Joi.string().hostname().example('smtp.gmail.com').description('Hostname to connect to'),
    port: Joi.number()
        .min(1)
        .max(64 * 1024)
        .example(587)
        .description('Service port number'),
    secure: Joi.boolean().example(false).description('Should connection use TLS. Usually true for port 465'),
    tls: Joi.object({
        rejectUnauthorized: Joi.boolean().example(true).description('How to treat invalid certificates'),
        minVersion: Joi.string().max(256).example('TLSv1.2').description('Minimal TLS version')
    })
        .description('Optional TLS configuration')
        .label('TLS'),
    partial: Joi.boolean().example(false).description('Update only listed keys in the smtp config').default(false)
};

const oauth2UpdateSchema = {
    authorize: Joi.boolean().example(true).description('Return a redirect link to the OAuth2 consent screen'),
    provider: Joi.string().empty('').valid('gmail', 'gmailService', 'outlook').description('OAuth provider'),

    auth: Joi.object({
        user: Joi.string().max(256).example('myuser@gmail.com').description('Account username')
    }),
    accessToken: Joi.string()
        .max(4 * 4096)
        .example('ya29.a0ARrdaM8a...'),
    refreshToken: Joi.string()
        .max(4 * 4096)
        .example('1//09Ie3CtORQYm...'),
    authority: Joi.any()
        .when('provider', {
            switch: [
                {
                    is: 'gmail',
                    then: Joi.string().empty('').forbidden()
                },

                {
                    is: 'gmailService',
                    then: Joi.string().empty('').forbidden()
                },

                {
                    is: 'outlook',
                    then: Joi.string().empty('').max(1024).allow('consumers', 'organizations', 'common').default('consumers').example('consumers')
                }
            ]
        })
        .label('SupportedAccountTypes'),
    expires: Joi.date().iso().example('2021-03-22T13:13:31.000Z').description('Token expiration date'),
    partial: Joi.boolean().example(false).description('Update only listed keys in the oauth2 config').default(false)
};

const attachmentSchema = Joi.object({
    id: Joi.string().example('AAAAAgAACrIyLjI').description('Attachment ID').label('AttachmentId'),
    contentType: Joi.string().example('image/gif').description('Mime type of the attachment'),
    encodedSize: Joi.number().example(48).description('Encoded size of the attachment. Actual file size is usually smaller depending on the encoding'),
    embedded: Joi.boolean().example(true).description('Is this image used in HTML img tag'),
    inline: Joi.boolean().example(true).description('Should this file be included in the message preview somehow'),
    contentId: Joi.string().example('<unique-image-id@localhost>').description('Usually used only for embedded images')
});

const messageEntrySchema = Joi.object({
    id: Joi.string().example('AAAAAgAACrI').description('Message ID').label('MessageEntryId'),
    uid: Joi.number().example(12345).description('UID of the message').label('MessageUid'),
    emailId: Joi.string().example('1694937972638499881').description('Globally unique ID (if server supports it)').label('MessageEmailId'),
    threadId: Joi.string().example('1694936993596975454').description('Thread ID (if server supports it)').label('MessageThreadId'),
    date: Joi.date().iso().example('2021-03-22T13:13:31.000Z').description('Date (internal)'),
    draft: Joi.boolean().example(false).description('Is this message marked as a draft'),
    unseen: Joi.boolean().example(true).description('Is this message unseen'),
    flagged: Joi.boolean().example(true).description('Is this message marked as flagged'),
    size: Joi.number().example(1040).description('Message size in bytes'),
    subject: Joi.string().example('What a wonderful message').description('Message subject (decoded into unicode, applies to other string values as well)'),

    from: addressSchema.example({ name: 'From Me', address: 'sender@example.com' }),

    to: Joi.array()
        .items(addressSchema)
        .description('List of addresses')
        .example([{ address: 'recipient@example.com' }])
        .label('AddressList'),

    cc: Joi.array().items(addressSchema).description('List of addresses').label('AddressList'),

    bcc: Joi.array().items(addressSchema).description('List of addresses').label('AddressList'),
    messageId: Joi.string().example('<test123@example.com>').description('Message ID'),
    inReplyTo: Joi.string().example('<7JBUMt0WOn+_==MOkaCOQ@mail.gmail.com>').description('Replied Message ID'),

    labels: Joi.array().items(Joi.string().example('\\Important')).description('Gmail labels').label('LabelList'),

    attachments: Joi.array().items(attachmentSchema).description('List of attachments').label('AttachmentList'),

    text: Joi.object({
        id: Joi.string().example('AAAAAgAACqiTkaExkaEykA').description('Pointer to message text content'),
        encodedSize: Joi.object({
            plain: Joi.number().example(1013).description('How many bytes for plain text'),
            html: Joi.number().example(1013).description('How many bytes for html content')
        }).description('Encoded message part sizes')
    }).label('TextInfo')
}).label('MessageListEntry');

const messageDetailsSchema = Joi.object({
    id: Joi.string().example('AAAAAgAACrI').description('Message ID').label('MessageEntryId'),
    uid: Joi.number().example(12345).description('UID of the message').label('MessageUid'),
    emailId: Joi.string().example('1694937972638499881').description('Globally unique ID (if server supports it)').label('MessageEmailId'),
    threadId: Joi.string().example('1694936993596975454').description('Thread ID (if server supports it)').label('MessageThreadId'),
    date: Joi.date().iso().example('2021-03-22T13:13:31.000Z').description('Date (internal)'),
    draft: Joi.boolean().example(false).description('Is this message marked as a draft'),
    unseen: Joi.boolean().example(true).description('Is this message unseen'),
    flagged: Joi.boolean().example(true).description('Is this message marked as flagged'),
    size: Joi.number().example(1040).description('Message size in bytes'),
    subject: Joi.string().example('What a wonderful message').description('Message subject (decoded into unicode, applies to other string values as well)'),

    from: addressSchema.example({ name: 'From Me', address: 'sender@example.com' }),
    sender: addressSchema.example({ name: 'From Me', address: 'sender@example.com' }),

    to: Joi.array()
        .items(addressSchema)
        .description('List of addresses')
        .example([{ address: 'recipient@example.com' }])
        .label('AddressList'),

    cc: Joi.array().items(addressSchema).description('List of addresses').label('AddressList'),

    bcc: Joi.array().items(addressSchema).description('List of addresses').label('AddressList'),
    messageId: Joi.string().example('<test123@example.com>').description('Message ID'),
    inReplyTo: Joi.string().example('<7JBUMt0WOn+_==MOkaCOQ@mail.gmail.com>').description('Replied Message ID'),

    flags: Joi.array().items(Joi.string().example('\\Seen')).description('IMAP flags').label('FlagList'),
    labels: Joi.array().items(Joi.string().example('\\Important')).description('Gmail labels').label('LabelList'),

    attachments: Joi.array().items(attachmentSchema).description('List of attachments').label('AttachmentList'),

    headers: Joi.object()
        .example({ from: ['From Me <sender@example.com>'], subject: ['What a wonderful message'] })
        .description('Object where header key is object key and value is an array'),

    text: Joi.object({
        id: Joi.string().example('AAAAAgAACqiTkaExkaEykA').description('Pointer to message text content'),
        encodedSize: Joi.object({
            plain: Joi.number().example(1013).description('How many bytes for plain text'),
            html: Joi.number().example(1013).description('How many bytes for html content')
        }).description('Encoded message part sizes'),
        plain: Joi.string().example('Hello from myself!').description('Plaintext content of the message'),
        html: Joi.string().example('<p>Hello from myself!</p>').description('HTML content of the message'),
        hasMore: Joi.boolean()
            .example(false)
            .description('If partial message content was requested then this value indicates if it includes all the content or there is more')
    }).label('TextInfo'),

    bounces: Joi.array()
        .items(
            Joi.object({
                message: Joi.string().max(256).required().example('AAAAAQAACnA').description('Bounce email ID'),
                recipient: Joi.string().email().example('recipient@example.com'),
                action: Joi.string().example('failed'),
                response: Joi.object({
                    message: Joi.string().example('550 5.1.1 No such user'),
                    status: Joi.string().example('5.1.1')
                }).label('BounceResponse'),
                date: Joi.date().iso().example('2021-03-22T13:13:31.000Z').description('Time the bounce was registered by EmailEngine')
            }).label('BounceEntry')
        )
        .label('BounceList')
}).label('MessageListEntry');

const messageListSchema = Joi.object({
    total: Joi.number().example(120).description('How many matching entries').label('TotalNumber'),
    page: Joi.number().example(0).description('Current page (0-based index)').label('PageNumber'),
    pages: Joi.number().example(24).description('Total page count').label('PagesNumber'),
    messages: Joi.array().items(messageEntrySchema).label('PageMessages')
}).label('MessageList');

const mailboxesSchema = Joi.array().items(
    Joi.object({
        path: Joi.string().required().example('Kalender/S&APw-nnip&AOQ-evad').description('Full path to mailbox').label('MailboxPath'),
        delimiter: Joi.string().example('/'),
        parentPath: Joi.string().required().example('Kalender').description('Full path to parent mailbox').label('MailboxParentPath'),
        name: Joi.string().required().example('Sünnipäevad').description('Maibox name').label('MailboxName'),
        listed: Joi.boolean().example(true).description('Was the mailbox found from the output of LIST command').label('MailboxListed'),
        subscribed: Joi.boolean().example(true).description('Was the mailbox found from the output of LSUB command').label('MailboxSubscribed'),
        specialUse: Joi.string()
            .example('\\Sent')
            .valid('\\All', '\\Archive', '\\Drafts', '\\Flagged', '\\Junk', '\\Sent', '\\Trash', '\\Inbox')
            .description('Special use flag of the mailbox if set')
            .label('MailboxSpecialUse'),
        messages: Joi.number().example(120).description('Count of messages in mailbox').label('MailboxMessages'),
        uidNext: Joi.number().example(121).description('Next expected UID').label('MailboxMUidNext')
    }).label('MailboxResponseItem')
);

const shortMailboxesSchema = Joi.array().items(
    Joi.object({
        path: Joi.string().required().example('Kalender/S&APw-nnip&AOQ-evad').description('Full path to mailbox').label('MailboxPath'),
        delimiter: Joi.string().example('/'),
        parentPath: Joi.string().required().example('Kalender').description('Full path to parent mailbox').label('MailboxParentPath'),
        name: Joi.string().required().example('Sünnipäevad').description('Maibox name').label('MailboxName'),
        listed: Joi.boolean().example(true).description('Was the mailbox found from the output of LIST command').label('MailboxListed'),
        subscribed: Joi.boolean().example(true).description('Was the mailbox found from the output of LSUB command').label('MailboxSubscribed'),
        specialUse: Joi.string()
            .example('\\Sent')
            .valid('\\All', '\\Archive', '\\Drafts', '\\Flagged', '\\Junk', '\\Sent', '\\Trash', '\\Inbox')
            .description('Special use flag of the mailbox if set')
            .label('MailboxSpecialUse')
    }).label('MailboxResponseItem')
);

const licenseSchema = Joi.object({
    active: Joi.boolean().example(true).description('Is there an active license registered'),
    type: Joi.string().example('EmailEngine License').description('Active license type'),
    details: Joi.object({
        application: Joi.string().example('@postalsys/emailengine-app'),
        key: Joi.string().hex().example('1edf01e35e75ed3425808eba').description('License key'),
        licensedTo: Joi.string().hex().example('Kreata OÜ').description('Licensed to'),
        hostname: Joi.string().example('emailengine.example.com').description('Hostname or environment this license applies to'),
        created: Joi.date().example('2021-10-13T07:47:42.695Z').description('Time the license was provisioned')
    })
        .allow(false)
        .label('LicenseDetails'),
    suspended: Joi.boolean().example(false).description('Are email connections closed')
});

const lastErrorSchema = Joi.object({
    response: Joi.string().example('Token request failed'),
    serverResponseCode: Joi.string().example('OauthRenewError'),
    tokenRequest: Joi.object({
        grant: Joi.string().valid('refresh_token', 'authorization_code').example('refresh_token').description('Requested grant type'),
        provider: Joi.string().valid('gmail', 'outlook').description('OAuth2 provider'),
        status: Joi.number().example(400).description('HTTP status code for the OAuth2 request'),
        clientId: Joi.string()
            .example('1023289917884-h3nu00e9cb7h252e24c23sv19l8k57ah.apps.googleusercontent.com')
            .description('OAuth2 client ID used to authenticate this request'),
        scopes: Joi.array()
            .items(Joi.string().example('https://mail.google.com/').label('ScopeEntry').description('OAuth2 scope'))
            .description('List of requested OAuth2 scopes'),
        response: Joi.object()
            .example({
                error: 'invalid_grant',
                error_description: 'Bad Request'
            })
            .description('Server response')
    }).description('OAuth2 error info if token request failed')
}).label('AccountErrorEntry');

module.exports = {
    ADDRESS_STRATEGIES,

    settingsSchema,
    addressSchema,
    settingsQuerySchema,
    imapSchema,
    smtpSchema,
    oauth2Schema,
    imapUpdateSchema,
    smtpUpdateSchema,
    oauth2UpdateSchema,
    attachmentSchema,
    messageEntrySchema,
    messageDetailsSchema,
    messageListSchema,
    mailboxesSchema,
    shortMailboxesSchema,
    licenseSchema,
    lastErrorSchema
};
