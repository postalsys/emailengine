'use strict';

// Everything that describes the API document itself: the tag list and its order, the security
// scheme, external docs, the logo. The generator that consumes them lives in lib/openapi/.
//
// Kept separate from workers/api.js so the generated document can be reproduced outside a
// running server - test/helpers/build-openapi-spec.js registers the real route table and
// these options to build the same spec in-process. A copy in the test would silently drift,
// and `tags` is not cosmetic: it drives the tag ORDER and descriptions that the API
// reference navigation is built from (lib/api-reference/model.js).
//
// The remaining options (cors, info) stay in workers/api.js, where the values they depend on
// live.

module.exports = {
    // Everything about the document that does not change between installs. workers/api.js
    // merges in the one field that does - `version`, which it reads from package.json - so
    // this stays reproducible outside a running server and the tests can see all of it.
    //
    // The description has two renderers: every consumer of /swagger.json, and the admin
    // reference landing page, which shows it in place of prose of its own so those facts have
    // one source (lib/api-reference/model.js -> views/reference/index.hbs).
    //
    // That second renderer makes the FORMAT load-bearing. Paragraphs, `code spans` and
    // absolute links only - no headings, no lists, no raw HTML. formatDescription() in
    // lib/api-reference/format.js escapes first and adds back a closed tag set, so anything
    // outside that subset shows up as visible literal text. Links have to be absolute too:
    // the document is served from emailengine.dev and read by code generators, where an
    // /admin path points at nothing. The page carries its own buttons to the admin pages.
    info: {
        title: 'EmailEngine API',

        contact: {
            name: 'EmailEngine Support',
            url: 'https://learn.emailengine.app/docs/support',
            email: 'support@emailengine.app'
        },

        license: {
            name: 'EmailEngine License',
            url: 'https://emailengine.dev/LICENSE_EMAILENGINE.txt'
        },

        description: `EmailEngine provides a RESTful API for managing email accounts, sending messages, and processing email data across multiple providers.

Every request needs an access token, passed either as an \`Authorization: Bearer <token>\` header or an \`?access_token=\` query argument. Tokens are issued and revoked on the Access Tokens page of the EmailEngine admin interface.

Requests against the same email account are processed sequentially to keep its state consistent, so simultaneous calls for one account queue up behind each other. Long-running operations can be given more room with the \`x-ee-timeout\` header, in milliseconds.

Every failure returns the same JSON envelope: a numeric \`statusCode\`, a short \`error\` label and a human-readable \`message\`. Each endpoint therefore documents only which status codes it can return and what they mean.

Full documentation: https://learn.emailengine.app/`
    },

    externalDocs: {
        description: 'EmailEngine Documentation',
        url: 'https://learn.emailengine.app/'
    },

    securityDefinitions: {
        bearerAuth: {
            type: 'http',
            scheme: 'bearer',
            bearerFormat: 'JWT',
            description: 'Enter your access token'
        }
    },

    security: [{ bearerAuth: [] }],

    tags: [
        {
            name: 'Account',
            description: 'Manage email accounts, including IMAP/SMTP configuration, OAuth2 authentication, and account health monitoring'
        },
        {
            name: 'Mailbox',
            description: 'List, create, modify, and manage mailbox folders. Retrieve folder statistics and special-use designations'
        },
        {
            name: 'Message',
            description: 'Search, retrieve, update, and delete email messages. Manage flags, labels, and message content'
        },
        {
            name: 'Submit',
            description:
                'Send emails with attachments, reply to threads, forward messages, and upload to folders. Supports both immediate and scheduled sending',
            externalDocs: {
                description: 'Sending Emails Documentation',
                url: 'https://learn.emailengine.app/docs/sending'
            }
        },
        {
            name: 'Outbox',
            description: 'Monitor and manage the email sending queue. View pending messages, retry failed deliveries, and track sending progress'
        },
        {
            name: 'Delivery Test',
            description: 'Test email deliverability and authentication. Verify SPF, DKIM signatures, DMARC alignment, and analyze potential delivery issues'
        },
        {
            name: 'Access Tokens',
            description: 'Create and manage API access tokens with customizable permissions, IP restrictions, and rate limits'
        },
        {
            name: 'Settings',
            description: 'Configure EmailEngine runtime settings including webhooks, tracking, AI features, and email processing options'
        },
        {
            name: 'Templates',
            description: 'Create and manage reusable email templates with variable substitution, HTML/text content, and attachments',
            externalDocs: {
                description: 'Email Templates Documentation',
                url: 'https://learn.emailengine.app/docs/sending/templates'
            }
        },
        {
            name: 'Logs',
            description: 'Access system and account-level logs for debugging, monitoring, and audit purposes'
        },
        {
            name: 'Stats',
            description: 'Retrieve usage statistics, performance metrics, and account activity data',
            externalDocs: {
                description: 'Monitoring and Analytics',
                url: 'https://learn.emailengine.app/docs/advanced/monitoring'
            }
        },
        {
            name: 'License',
            description: 'Manage EmailEngine licensing, view license status, and handle license-related operations'
        },
        {
            name: 'Webhooks',
            description: 'Configure webhook endpoints, manage event subscriptions, and monitor webhook delivery status',
            externalDocs: {
                description: 'Webhooks Guide',
                url: 'https://learn.emailengine.app/docs/webhooks/overview'
            }
        },
        {
            name: 'OAuth2 Applications',
            description: 'Configure OAuth2 applications for Gmail, Outlook, and other providers. Manage client credentials and authentication flows',
            externalDocs: {
                description: 'OAuth2 Configuration Guide',
                url: 'https://learn.emailengine.app/docs/configuration/oauth2-configuration'
            }
        },
        {
            name: 'SMTP Gateway',
            description: 'Configure and manage the built-in SMTP server for receiving emails and integrating with external systems'
        },
        {
            name: 'Blocklists',
            description:
                'Manage suppression lists (blocklists) of addresses that must not receive further emails. The same lists are populated by unsubscribe actions and can be managed in the admin UI under Suppression Lists'
        },
        {
            name: 'Multi Message Actions',
            description: 'Perform bulk operations on multiple messages simultaneously, such as marking as read, moving, or deleting'
        },
        {
            name: 'Export (Beta)',
            description:
                'Bulk export messages from email accounts. This feature is in beta and the API may change in future releases. Export files are encrypted at rest when a service secret is configured.'
        }
    ],

    // Custom vendor extensions for additional metadata
    'x-logo': {
        url: 'https://emailengine.dev/static/logo.png',
        altText: 'EmailEngine Logo'
    }
};
