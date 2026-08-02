'use strict';

// The spec-shaping half of the hapi-swagger options: everything that describes the API
// document itself (grouping, tag list and order, security scheme, external docs, logo)
// rather than how the bundled swagger-ui page looks.
//
// Kept separate from workers/api.js so the generated document can be reproduced outside a
// running server - test/helpers/build-openapi-spec.js registers the real route table and
// these options to build the same spec in-process. A copy in the test would silently drift,
// and `tags` is not cosmetic: it drives the tag ORDER and descriptions that the API
// reference navigation is built from (lib/api-reference/model.js).
//
// The presentation-only options (swaggerUI, templates, expanded, tryItOutEnabled, cache,
// cors, info) stay in workers/api.js, where the values they depend on live.

module.exports = {
    OAS: 'v3.0',

    grouping: 'tags',

    definitionPrefix: 'useLabel',

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
            description: 'Manage email address blocklists to prevent sending to specific recipients or domains'
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
