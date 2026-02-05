'use strict';

const Boom = require('@hapi/boom');
const Joi = require('joi');

const settings = require('../settings');
const tokens = require('../tokens');
const { redis } = require('../db');
const getSecret = require('../get-secret');
const { failAction, verifyAccountInfo } = require('../tools');
const { templateSchemas, accountIdSchema } = require('../schemas');
const { Account } = require('../account');
const { Gateway } = require('../gateway');
const { templates } = require('../templates');
const { webhooks } = require('../webhooks');
const consts = require('../consts');
const wellKnownServices = require('nodemailer/lib/well-known/services.json');
const exampleWebhookPayloads = require('../payload-examples-webhooks.json');

const { DEFAULT_PAGE_SIZE } = consts;

const notificationTypes = Object.keys(consts)
    .map(key => {
        if (/_NOTIFY$/.test(key)) {
            return key.replace(/_NOTIFY$/, '');
        }
        return false;
    })
    .filter(key => key)
    .map(key => ({
        key,
        name: consts[`${key}_NOTIFY`],
        description: consts[`${key}_DESCRIPTION`]
    }));

const CODE_FORMATS = [
    {
        format: 'html',
        name: 'HTML'
    },
    {
        format: 'markdown',
        name: 'Markdown'
    }
];

async function getExampleWebhookPayloads() {
    let serviceUrl = await settings.get('serviceUrl');
    let date = new Date().toISOString();

    let examplePayloads = structuredClone(exampleWebhookPayloads);

    examplePayloads.forEach(payload => {
        if (payload && payload.content) {
            if (typeof payload.content.serviceUrl === 'string') {
                payload.content.serviceUrl = serviceUrl;
            }

            if (typeof payload.content.date === 'string') {
                payload.content.date = date;
            }

            if (payload.content.data && typeof payload.content.data.date === 'string') {
                payload.content.data.date = date;
            }

            if (payload.content.data && typeof payload.content.data.created === 'string') {
                payload.content.data.created = date;
            }
        }
    });
    return examplePayloads;
}

function init(args) {
    const { server, call } = args;

    // Webhook routes

    server.route({
        method: 'GET',
        path: '/admin/webhooks',
        async handler(request, h) {
            let data = await webhooks.list(request.query.page - 1, request.query.pageSize);

            let nextPage = false;
            let prevPage = false;

            if (request.query.account) {
                let accountObject = new Account({ redis, account: request.query.account });
                data.account = await accountObject.loadAccountData();
            }

            let getPagingUrl = page => {
                let url = new URL(`admin/webhooks`, 'http://localhost');

                if (page) {
                    url.searchParams.append('page', page);
                }

                if (request.query.pageSize !== DEFAULT_PAGE_SIZE) {
                    url.searchParams.append('pageSize', request.query.pageSize);
                }

                return url.pathname + url.search;
            };

            if (data.pages > data.page + 1) {
                nextPage = getPagingUrl(data.page + 2);
            }

            if (data.page > 0) {
                prevPage = getPagingUrl(data.page);
            }

            let newLink = new URL('/admin/webhooks/new', 'http://localhost');

            return h.view(
                'webhooks/index',
                {
                    pageTitle: 'Webhook Routing',
                    menuWebhooks: true,

                    newLink: newLink.pathname + newLink.search,

                    showPaging: data.pages > 1,
                    nextPage,
                    prevPage,
                    firstPage: data.page === 0,
                    pageLinks: new Array(data.pages || 1).fill(0).map((z, i) => ({
                        url: getPagingUrl(i + 1),
                        title: i + 1,
                        active: i === data.page
                    })),

                    webhooksEnabled: await settings.get('webhooksEnabled'),

                    webhooks: data.webhooks
                },
                {
                    layout: 'app'
                }
            );
        },

        options: {
            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                async failAction(request, h /*, err*/) {
                    return h.redirect('/admin/webhooks').takeover();
                },

                query: Joi.object({
                    page: Joi.number().integer().min(1).max(1000000).default(1),
                    pageSize: Joi.number().integer().min(1).max(250).default(DEFAULT_PAGE_SIZE)
                })
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/admin/webhooks/new',
        async handler(request, h) {
            const values = {
                name: '',
                description: '',

                contentFnJson: JSON.stringify(`/*
// The following example passes webhooks for new emails that appear in the Inbox of the user "testaccount".
// NB! Gmail webhooks are always emitted from the "All Mail" folder, not the Inbox, so we need to check both the path and label values.

const isInbox = payload.path === 'INBOX' || payload.data?.labels?.includes('\\\\Inbox');
if (payload.event === 'messageNew' && payload.account === 'testaccount' && isInbox) {
    return true;
}
*/

return true; // pass all`),
                contentMapJson: JSON.stringify(`// By default the output payload is returned unmodified.

return payload;`)
            };

            return h.view(
                'webhooks/new',
                {
                    pageTitle: 'Webhook Routing',
                    menuWebhooks: true,
                    values,

                    examplePayloadsJson: JSON.stringify(await getExampleWebhookPayloads()),
                    notificationTypesJson: JSON.stringify(notificationTypes),
                    scriptEnvJson: JSON.stringify((await settings.get('scriptEnv')) || '{}')
                },
                {
                    layout: 'app'
                }
            );
        },

        options: {
            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                async failAction(request, h /*, err*/) {
                    return h.redirect('/admin/webhooks').takeover();
                },

                query: Joi.object({})
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/webhooks/new',
        async handler(request, h) {
            let contentFn, contentMap;
            try {
                if (request.payload.contentFnJson === '') {
                    contentFn = null;
                } else {
                    contentFn = JSON.parse(request.payload.contentFnJson);
                    if (typeof contentFn !== 'string') {
                        throw new Error('Invalid Format');
                    }
                }
            } catch (err) {
                err.details = {
                    contentFnJson: 'Invalid JSON'
                };
                throw err;
            }

            try {
                if (request.payload.contentMapJson === '') {
                    contentMap = null;
                } else {
                    contentMap = JSON.parse(request.payload.contentMapJson);
                    if (typeof contentMap !== 'string') {
                        throw new Error('Invalid Format');
                    }
                }
            } catch (err) {
                err.details = {
                    contentMapJson: 'Invalid JSON'
                };
                throw err;
            }

            let customHeaders = request.payload.customHeaders
                .split(/[\r\n]+/)
                .map(header => header.trim())
                .filter(header => header)
                .map(line => {
                    let sep = line.indexOf(':');
                    if (sep >= 0) {
                        return {
                            key: line.substring(0, sep).trim(),
                            value: line.substring(sep + 1).trim()
                        };
                    }
                    return {
                        key: line,
                        value: ''
                    };
                });

            try {
                let createRequest = await webhooks.create(
                    {
                        name: request.payload.name,
                        description: request.payload.description,
                        targetUrl: request.payload.targetUrl,
                        enabled: request.payload.enabled,

                        customHeaders
                    },
                    {
                        fn: contentFn,
                        map: contentMap
                    }
                );

                await request.flash({ type: 'info', message: `Webhook created` });
                return h.redirect(`/admin/webhooks/webhook/${createRequest.id}`);
            } catch (err) {
                await request.flash({ type: 'danger', message: `Couldn't create webhook. Try again.` });
                request.logger.error({ msg: 'Failed to create webhook routing', err });

                return h.view(
                    'webhooks/new',
                    {
                        pageTitle: 'Webhook Routing',
                        menuWebhooks: true,
                        errors: err.details,

                        examplePayloadsJson: JSON.stringify(await getExampleWebhookPayloads()),
                        notificationTypesJson: JSON.stringify(notificationTypes),
                        scriptEnvJson: JSON.stringify((await settings.get('scriptEnv')) || '{}')
                    },
                    {
                        layout: 'app'
                    }
                );
            }
        },
        options: {
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

                    await request.flash({ type: 'danger', message: `Couldn't create webhook. Try again.` });
                    request.logger.error({ msg: 'Failed to create webhook routing', err });

                    return h
                        .view(
                            'templates/new',
                            {
                                pageTitle: 'Templates',
                                menuTemplates: true,
                                errors,

                                examplePayloadsJson: JSON.stringify(await getExampleWebhookPayloads()),
                                notificationTypesJson: JSON.stringify(notificationTypes)
                            },
                            {
                                layout: 'app'
                            }
                        )
                        .takeover();
                },

                payload: Joi.object({
                    name: Joi.string().max(256).example('Transaction receipt').description('Name of the routing').label('RoutingName').required(),
                    description: Joi.string()
                        .allow('')
                        .max(1024)
                        .example('Something about the routing')
                        .description('Optional description of the webhook routing')
                        .label('RoutingDescription'),
                    targetUrl: Joi.string()
                        .uri({
                            scheme: ['http', 'https'],
                            allowRelative: false
                        })
                        .allow('')
                        .default('')
                        .example('https://myservice.com/imap/webhooks')
                        .description('Webhook target URL'),
                    enabled: Joi.boolean()
                        .truthy('Y', 'true', '1', 'on')
                        .falsy('N', 'false', 0, '')
                        .default(false)
                        .example(false)
                        .description('Is the routing enabled'),
                    customHeaders: Joi.string()
                        .allow('')
                        .trim()
                        .max(10 * 1024)
                        .description('Custom request headers'),
                    contentFnJson: Joi.string()
                        .max(1024 * 1024)
                        .default('')
                        .allow('')
                        .trim()
                        .description('Filter function'),
                    contentMapJson: Joi.string()
                        .max(1024 * 1024)
                        .default('')
                        .allow('')
                        .trim()
                        .description('Map function')
                })
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/admin/webhooks/webhook/{webhook}',
        async handler(request, h) {
            let webhook = await webhooks.get(request.params.webhook);
            if (!webhook) {
                let error = Boom.boomify(new Error('Webhook Route was not found.'), { statusCode: 404 });
                throw error;
            }

            webhook.targetUrlShort = webhook.targetUrl ? new URL(webhook.targetUrl).hostname : false;

            const errorLog = ((await webhooks.getErrorLog(webhook.id)) || []).map(entry => {
                if (entry.error && typeof entry.error === 'string') {
                    entry.error = entry.error
                        .replace(/\r?\n/g, '\n')
                        .replace(/^\s+at\s+.*$/gm, '')
                        .replace(/\n+/g, '\n')
                        .trim()
                        .replace(/(evalmachine.<anonymous>:)(\d+)/, (o, p, n) => p + (Number(n) - 1));
                }
                return entry;
            });

            return h.view(
                'webhooks/webhook',
                {
                    pageTitle: 'Webhook Routing',
                    menuWebhooks: true,
                    webhook,

                    errorLog
                },
                {
                    layout: 'app'
                }
            );
        },

        options: {
            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                async failAction(request, h /*, err*/) {
                    return h.redirect('/admin/webhooks').takeover();
                },

                params: Joi.object({
                    webhook: Joi.string()
                        .base64({ paddingRequired: false, urlSafe: true })
                        .max(512)
                        .example('AAAAAQAACnA')
                        .required()
                        .description('Webhook Route ID')
                })
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/admin/webhooks/webhook/{webhook}/edit',
        async handler(request, h) {
            let webhook = await webhooks.get(request.params.webhook);
            if (!webhook) {
                let error = Boom.boomify(new Error('Webhook Route not found.'), { statusCode: 404 });
                throw error;
            }

            const values = {
                webhook: webhook.id,
                name: webhook.name,
                description: webhook.description,
                targetUrl: webhook.targetUrl,
                enabled: webhook.enabled,
                contentFnJson: JSON.stringify(webhook.content.fn || ''),
                contentMapJson: JSON.stringify(webhook.content.map || ''),

                customHeaders: []
                    .concat(webhook.customHeaders || [])
                    .map(entry => `${entry.key}: ${entry.value}`.trim())
                    .join('\n')
            };

            return h.view(
                'webhooks/edit',
                {
                    pageTitle: 'Webhook Routing',
                    menuWebhooks: true,

                    webhook,

                    values,

                    examplePayloadsJson: JSON.stringify(await getExampleWebhookPayloads()),
                    notificationTypesJson: JSON.stringify(notificationTypes),
                    scriptEnvJson: JSON.stringify((await settings.get('scriptEnv')) || '{}')
                },
                {
                    layout: 'app'
                }
            );
        },

        options: {
            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                async failAction(request, h /*, err*/) {
                    return h.redirect('/admin/webhooks').takeover();
                },

                params: Joi.object({
                    webhook: Joi.string()
                        .base64({ paddingRequired: false, urlSafe: true })
                        .max(512)
                        .example('AAAAAQAACnA')
                        .required()
                        .description('Webhook Route ID')
                })
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/webhooks/edit',
        async handler(request, h) {
            let contentFn, contentMap;
            try {
                if (request.payload.contentFnJson === '') {
                    contentFn = null;
                } else {
                    contentFn = JSON.parse(request.payload.contentFnJson);
                    if (typeof contentFn !== 'string') {
                        throw new Error('Invalid Format');
                    }
                }
            } catch (err) {
                err.details = {
                    contentFnJson: 'Invalid JSON'
                };
                throw err;
            }

            try {
                if (request.payload.contentMapJson === '') {
                    contentMap = null;
                } else {
                    contentMap = JSON.parse(request.payload.contentMapJson);
                    if (typeof contentMap !== 'string') {
                        throw new Error('Invalid Format');
                    }
                }
            } catch (err) {
                err.details = {
                    contentMapJson: 'Invalid JSON'
                };
                throw err;
            }

            let customHeaders = request.payload.customHeaders
                .split(/[\r\n]+/)
                .map(header => header.trim())
                .filter(header => header)
                .map(line => {
                    let sep = line.indexOf(':');
                    if (sep >= 0) {
                        return {
                            key: line.substring(0, sep).trim(),
                            value: line.substring(sep + 1).trim()
                        };
                    }
                    return {
                        key: line,
                        value: ''
                    };
                });

            try {
                await webhooks.update(
                    request.payload.webhook,
                    {
                        name: request.payload.name,
                        description: request.payload.description,
                        targetUrl: request.payload.targetUrl,
                        enabled: request.payload.enabled,

                        customHeaders
                    },
                    {
                        fn: contentFn,
                        map: contentMap
                    }
                );

                await request.flash({ type: 'info', message: `Webhook saved` });
                return h.redirect(`/admin/webhooks/webhook/${request.payload.webhook}`);
            } catch (err) {
                await request.flash({ type: 'danger', message: `Couldn't save webhook. Try again.` });
                request.logger.error({ msg: 'Failed to update Webhook Route', err });

                let webhook = await webhooks.get(request.payload.webhook);
                if (!webhook) {
                    let error = Boom.boomify(new Error('Webhook Route not found.'), { statusCode: 404 });
                    throw error;
                }

                return h.view(
                    'webhooks/edit',
                    {
                        pageTitle: 'Webhook Routing',
                        menuWebhooks: true,

                        webhook,

                        errors: err.details,

                        examplePayloadsJson: JSON.stringify(await getExampleWebhookPayloads()),
                        notificationTypesJson: JSON.stringify(notificationTypes),
                        scriptEnvJson: JSON.stringify((await settings.get('scriptEnv')) || '{}')
                    },
                    {
                        layout: 'app'
                    }
                );
            }
        },
        options: {
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

                    await request.flash({ type: 'danger', message: `Couldn't save webhook. Try again.` });
                    request.logger.error({ msg: 'Failed to update Webhook Route', err });

                    let webhook = await webhooks.get(request.payload.webhook);
                    if (!webhook) {
                        let error = Boom.boomify(new Error('Webhook Route not found.'), { statusCode: 404 });
                        throw error;
                    }

                    return h
                        .view(
                            'webhooks/edit',
                            {
                                pageTitle: 'Webhook Routing',
                                menuWebhooks: true,

                                webhook,

                                errors,

                                examplePayloadsJson: JSON.stringify(await getExampleWebhookPayloads()),
                                notificationTypesJson: JSON.stringify(notificationTypes),
                                scriptEnvJson: JSON.stringify((await settings.get('scriptEnv')) || '{}')
                            },
                            {
                                layout: 'app'
                            }
                        )
                        .takeover();
                },

                payload: Joi.object({
                    webhook: Joi.string()
                        .base64({ paddingRequired: false, urlSafe: true })
                        .max(512)
                        .example('AAAAAQAACnA')
                        .required()
                        .description('Webhook Route ID'),

                    name: Joi.string().max(256).example('Transaction receipt').description('Name of the routing').label('RoutingName').required(),
                    description: Joi.string()
                        .allow('')
                        .max(1024)
                        .example('Something about the routing')
                        .description('Optional description of the webhook routing')
                        .label('RoutingDescription'),
                    targetUrl: Joi.string()
                        .uri({
                            scheme: ['http', 'https'],
                            allowRelative: false
                        })
                        .allow('')
                        .default('')
                        .example('https://myservice.com/imap/webhooks')
                        .description('Webhook target URL'),
                    enabled: Joi.boolean()
                        .truthy('Y', 'true', '1', 'on')
                        .falsy('N', 'false', 0, '')
                        .default(false)
                        .example(false)
                        .description('Is the routing enabled'),
                    customHeaders: Joi.string()
                        .allow('')
                        .trim()
                        .max(10 * 1024)
                        .description('Custom request headers'),
                    contentFnJson: Joi.string()
                        .max(1024 * 1024)
                        .default('')
                        .allow('')
                        .trim()
                        .description('Filter function'),
                    contentMapJson: Joi.string()
                        .max(1024 * 1024)
                        .default('')
                        .allow('')
                        .trim()
                        .description('Map function')
                })
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/webhooks/delete',
        async handler(request, h) {
            try {
                await webhooks.del(request.payload.webhook);

                await request.flash({ type: 'info', message: `Webhook deleted` });

                let accountWebhooksLink = new URL('/admin/webhooks', 'http://localhost');

                return h.redirect(accountWebhooksLink.pathname + accountWebhooksLink.search);
            } catch (err) {
                await request.flash({ type: 'danger', message: `Couldn't delete webhook. Try again.` });
                request.logger.error({ msg: 'Failed to delete Webhook Route', err, webhook: request.payload.webhook, remoteAddress: request.app.ip });
                return h.redirect(`/admin/webhooks/webhook/${request.payload.webhook}`);
            }
        },
        options: {
            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                async failAction(request, h, err) {
                    await request.flash({ type: 'danger', message: `Couldn't delete webhook. Try again.` });
                    request.logger.error({ msg: 'Failed to delete delete Webhook Route', err });

                    return h.redirect('/admin/webhooks').takeover();
                },

                payload: Joi.object({
                    webhook: Joi.string()
                        .base64({ paddingRequired: false, urlSafe: true })
                        .max(512)
                        .example('AAAAAQAACnA')
                        .required()
                        .description('Webhook Route ID')
                })
            }
        }
    });

    // Template routes

    server.route({
        method: 'GET',
        path: '/admin/templates',
        async handler(request, h) {
            let data = await templates.list(request.query.account, request.query.page - 1, request.query.pageSize);

            let nextPage = false;
            let prevPage = false;

            if (request.query.account) {
                let accountObject = new Account({ redis, account: request.query.account });
                data.account = await accountObject.loadAccountData();
            }

            let getPagingUrl = page => {
                let url = new URL(`admin/templates`, 'http://localhost');
                url.searchParams.append('page', page);

                if (request.query.account) {
                    url.searchParams.append('account', request.query.account);
                }

                if (request.query.pageSize !== DEFAULT_PAGE_SIZE) {
                    url.searchParams.append('pageSize', request.query.pageSize);
                }

                return url.pathname + url.search;
            };

            if (data.pages > data.page + 1) {
                nextPage = getPagingUrl(data.page + 2);
            }

            if (data.page > 0) {
                prevPage = getPagingUrl(data.page);
            }

            let newLink = new URL('/admin/templates/new', 'http://localhost');
            if (request.query.account) {
                newLink.searchParams.append('account', request.query.account);
            }

            return h.view(
                'templates/index',
                {
                    pageTitle: 'Templates',
                    menuTemplates: true,

                    account: data.account,
                    newLink: newLink.pathname + newLink.search,

                    showPaging: data.pages > 1,
                    nextPage,
                    prevPage,
                    firstPage: data.page === 0,
                    pageLinks: new Array(data.pages || 1).fill(0).map((z, i) => ({
                        url: getPagingUrl(i + 1),
                        title: i + 1,
                        active: i === data.page
                    })),

                    templates: data.templates
                },
                {
                    layout: 'app'
                }
            );
        },

        options: {
            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                async failAction(request, h /*, err*/) {
                    return h.redirect('/admin/templates').takeover();
                },

                query: Joi.object({
                    account: accountIdSchema.default(null),
                    page: Joi.number().integer().min(1).max(1000000).default(1),
                    pageSize: Joi.number().integer().min(1).max(250).default(DEFAULT_PAGE_SIZE)
                })
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/admin/templates/template/{template}',
        async handler(request, h) {
            let template = await templates.get(request.params.template);
            if (!template) {
                let error = Boom.boomify(new Error('Template not found.'), { statusCode: 404 });
                throw error;
            }

            let account;
            if (template.account) {
                let accountObject = new Account({ redis, account: template.account });
                account = await accountObject.loadAccountData();
            }

            let accountTemplatesLink = new URL('/admin/templates', 'http://localhost');
            if (account) {
                accountTemplatesLink.searchParams.append('account', account.account);
            }

            return h.view(
                'templates/template',
                {
                    pageTitle: 'Templates',
                    menuTemplates: true,

                    account,

                    accountTemplatesLink: accountTemplatesLink.pathname + accountTemplatesLink.search,

                    format: CODE_FORMATS.find(entry => entry.format === template.format),

                    template
                },
                {
                    layout: 'app'
                }
            );
        },

        options: {
            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                async failAction(request, h /*, err*/) {
                    return h.redirect('/admin/templates').takeover();
                },

                params: Joi.object({
                    template: Joi.string()
                        .base64({ paddingRequired: false, urlSafe: true })
                        .max(512)
                        .example('AAAAAQAACnA')
                        .required()
                        .description('Template ID')
                })
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/admin/templates/template/{template}/edit',
        async handler(request, h) {
            let template = await templates.get(request.params.template);
            if (!template) {
                let error = Boom.boomify(new Error('Template not found.'), { statusCode: 404 });
                throw error;
            }

            let account;
            if (template.account) {
                let accountObject = new Account({ redis, account: template.account });
                account = await accountObject.loadAccountData();
            }

            let accountTemplatesLink = new URL('/admin/templates', 'http://localhost');
            if (account) {
                accountTemplatesLink.searchParams.append('account', account.account);
            }

            const values = {
                template: template.id,
                name: template.name,
                description: template.description,
                subject: template.content.subject,
                format: template.format,
                previewText: template.content.previewText
            };

            return h.view(
                'templates/edit',
                {
                    pageTitle: 'Templates',
                    menuTemplates: true,

                    account,

                    accountTemplatesLink: accountTemplatesLink.pathname + accountTemplatesLink.search,

                    template,

                    formats: CODE_FORMATS.map(format => Object.assign({ selected: format.format === values.format }, format)),

                    values,

                    contentHtmlJson: JSON.stringify(template.content.html || ''),
                    contentTextJson: JSON.stringify(template.content.text || '')
                },
                {
                    layout: 'app'
                }
            );
        },

        options: {
            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                async failAction(request, h /*, err*/) {
                    return h.redirect('/admin/templates').takeover();
                },

                params: Joi.object({
                    template: Joi.string()
                        .base64({ paddingRequired: false, urlSafe: true })
                        .max(512)
                        .example('AAAAAQAACnA')
                        .required()
                        .description('Template ID')
                })
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/templates/edit',
        async handler(request, h) {
            try {
                await templates.update(
                    request.payload.template,
                    {
                        name: request.payload.name,
                        description: request.payload.description,
                        format: request.payload.format
                    },
                    {
                        subject: request.payload.subject,
                        html: request.payload.contentHtml,
                        text: request.payload.contentText,
                        previewText: request.payload.previewText
                    }
                );

                await request.flash({ type: 'info', message: `Template saved` });
                return h.redirect(`/admin/templates/template/${request.payload.template}`);
            } catch (err) {
                await request.flash({ type: 'danger', message: `Couldn't save template. Try again.` });
                request.logger.error({ msg: 'Failed to update template', err });

                let template = await templates.get(request.payload.template);
                if (!template) {
                    let error = Boom.boomify(new Error('Template not found.'), { statusCode: 404 });
                    throw error;
                }

                let account;
                if (template.account) {
                    let accountObject = new Account({ redis, account: template.account });
                    account = await accountObject.loadAccountData();
                }

                let accountTemplatesLink = new URL('/admin/templates', 'http://localhost');
                if (account) {
                    accountTemplatesLink.searchParams.append('account', account.account);
                }

                return h.view(
                    'templates/edit',
                    {
                        pageTitle: 'Templates',
                        menuTemplates: true,

                        account,

                        accountTemplatesLink: accountTemplatesLink.pathname + accountTemplatesLink.search,

                        template,

                        formats: CODE_FORMATS.map(format => Object.assign({ selected: format.format === request.payload.format }, format)),

                        errors: err.details,

                        contentHtmlJson: JSON.stringify(request.payload.contentHtml || ''),
                        contentTextJson: JSON.stringify(request.payload.contentText || '')
                    },
                    {
                        layout: 'app'
                    }
                );
            }
        },
        options: {
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

                    await request.flash({ type: 'danger', message: `Couldn't save template. Try again.` });
                    request.logger.error({ msg: 'Failed to update template', err });

                    let template = await templates.get(request.payload.template);
                    if (!template) {
                        let error = Boom.boomify(new Error('Template not found.'), { statusCode: 404 });
                        throw error;
                    }

                    let account;
                    if (template.account) {
                        let accountObject = new Account({ redis, account: template.account });
                        account = await accountObject.loadAccountData();
                    }

                    let accountTemplatesLink = new URL('/admin/templates', 'http://localhost');
                    if (account) {
                        accountTemplatesLink.searchParams.append('account', account.account);
                    }

                    return h
                        .view(
                            'templates/edit',
                            {
                                pageTitle: 'Templates',
                                menuTemplates: true,

                                account,

                                accountTemplatesLink: accountTemplatesLink.pathname + accountTemplatesLink.search,

                                template,

                                formats: CODE_FORMATS.map(format => Object.assign({ selected: format.format === request.payload.format }, format)),

                                errors,

                                contentHtmlJson: JSON.stringify(request.payload.contentHtml || ''),
                                contentTextJson: JSON.stringify(request.payload.contentText || '')
                            },
                            {
                                layout: 'app'
                            }
                        )
                        .takeover();
                },

                payload: Joi.object({
                    template: Joi.string()
                        .base64({ paddingRequired: false, urlSafe: true })
                        .max(512)
                        .example('AAAAAQAACnA')
                        .required()
                        .description('Template ID'),

                    name: Joi.string().max(256).example('Transaction receipt').description('Name of the template').label('TemplateName').required(),
                    description: Joi.string()
                        .allow('')
                        .max(1024)
                        .example('Something about the template')
                        .description('Optional description of the template')
                        .label('TemplateDescription'),
                    format: Joi.string().valid('html', 'markdown').default('html').description('Markup language for HTML ("html" or "markdown")'),
                    subject: templateSchemas.subject,
                    contentText: templateSchemas.text,
                    contentHtml: templateSchemas.html,
                    previewText: templateSchemas.previewText
                })
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/admin/templates/new',
        async handler(request, h) {
            let account;
            if (request.query.account) {
                let accountObject = new Account({ redis, account: request.query.account });
                account = await accountObject.loadAccountData();
            }

            let accountTemplatesLink = new URL('/admin/templates', 'http://localhost');
            if (account) {
                accountTemplatesLink.searchParams.append('account', account.account);
            }

            const values = {
                account: request.query.account,
                name: '',
                description: '',
                subject: '',
                format: 'html',
                contentHtml: '',
                contentText: '',
                previewText: ''
            };

            return h.view(
                'templates/new',
                {
                    pageTitle: 'Templates',
                    menuTemplates: true,

                    account,

                    accountTemplatesLink: accountTemplatesLink.pathname + accountTemplatesLink.search,

                    formats: CODE_FORMATS.map(format => Object.assign({ selected: format.format === values.format }, format)),

                    values,

                    contentHtmlJson: JSON.stringify(''),
                    contentTextJson: JSON.stringify('')
                },
                {
                    layout: 'app'
                }
            );
        },

        options: {
            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                async failAction(request, h /*, err*/) {
                    return h.redirect('/admin/templates').takeover();
                },

                query: Joi.object({
                    account: accountIdSchema.default(null)
                })
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/templates/new',
        async handler(request, h) {
            try {
                let createRequest = await templates.create(
                    request.payload.account,
                    {
                        name: request.payload.name,
                        description: request.payload.description,
                        format: request.payload.format
                    },
                    {
                        subject: request.payload.subject,
                        html: request.payload.contentHtml,
                        text: request.payload.contentText,
                        previewText: request.payload.previewText
                    }
                );

                await request.flash({ type: 'info', message: `Template created` });
                return h.redirect(`/admin/templates/template/${createRequest.id}`);
            } catch (err) {
                await request.flash({ type: 'danger', message: `Couldn't create template. Try again.` });
                request.logger.error({ msg: 'Failed to create template', err });

                let account;
                if (request.payload.account) {
                    let accountObject = new Account({ redis, account: request.payload.account });
                    account = await accountObject.loadAccountData();
                }

                let accountTemplatesLink = new URL('/admin/templates', 'http://localhost');
                if (account) {
                    accountTemplatesLink.searchParams.append('account', account.account);
                }

                return h.view(
                    'templates/new',
                    {
                        pageTitle: 'Templates',
                        menuTemplates: true,

                        account,

                        accountTemplatesLink: accountTemplatesLink.pathname + accountTemplatesLink.search,

                        formats: CODE_FORMATS.map(format => Object.assign({ selected: format.format === request.payload.format }, format)),

                        errors: err.details,

                        contentHtmlJson: JSON.stringify(request.payload.contentHtml || ''),
                        contentTextJson: JSON.stringify(request.payload.contentText || '')
                    },
                    {
                        layout: 'app'
                    }
                );
            }
        },
        options: {
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

                    await request.flash({ type: 'danger', message: `Couldn't create template. Try again.` });
                    request.logger.error({ msg: 'Failed to create template', err });

                    let account;
                    if (request.payload.account) {
                        let accountObject = new Account({ redis, account: request.payload.account });
                        account = await accountObject.loadAccountData();
                    }

                    let accountTemplatesLink = new URL('/admin/templates', 'http://localhost');
                    if (account) {
                        accountTemplatesLink.searchParams.append('account', account.account);
                    }

                    return h
                        .view(
                            'templates/new',
                            {
                                pageTitle: 'Templates',
                                menuTemplates: true,

                                account,

                                accountTemplatesLink: accountTemplatesLink.pathname + accountTemplatesLink.search,

                                formats: CODE_FORMATS.map(format => Object.assign({ selected: format.format === request.payload.format }, format)),

                                errors,

                                contentHtmlJson: JSON.stringify(request.payload.contentHtml || ''),
                                contentTextJson: JSON.stringify(request.payload.contentText || '')
                            },
                            {
                                layout: 'app'
                            }
                        )
                        .takeover();
                },

                payload: Joi.object({
                    account: accountIdSchema.default(null),

                    name: Joi.string().max(256).example('Transaction receipt').description('Name of the template').label('TemplateName').required(),
                    description: Joi.string()
                        .allow('')
                        .max(1024)
                        .example('Something about the template')
                        .description('Optional description of the template')
                        .label('TemplateDescription'),
                    format: Joi.string().valid('html', 'markdown').default('html').description('Markup language for HTML ("html" or "markdown")'),
                    subject: templateSchemas.subject,
                    contentText: templateSchemas.text,
                    contentHtml: templateSchemas.html,
                    previewText: templateSchemas.previewText
                })
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/templates/delete',
        async handler(request, h) {
            try {
                let templateResponse = await templates.del(request.payload.template);

                await request.flash({ type: 'info', message: `Template deleted` });

                let accountTemplatesLink = new URL('/admin/templates', 'http://localhost');
                if (templateResponse && templateResponse.account) {
                    accountTemplatesLink.searchParams.append('account', templateResponse.account);
                }

                return h.redirect(accountTemplatesLink.pathname + accountTemplatesLink.search);
            } catch (err) {
                await request.flash({ type: 'danger', message: `Couldn't delete template. Try again.` });
                request.logger.error({ msg: 'Failed to delete the template', err, template: request.payload.template, remoteAddress: request.app.ip });
                return h.redirect(`/admin/templates/template/${request.payload.template}`);
            }
        },
        options: {
            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                async failAction(request, h, err) {
                    await request.flash({ type: 'danger', message: `Couldn't delete account. Try again.` });
                    request.logger.error({ msg: 'Failed to delete delete the account', err });

                    return h.redirect('/admin/templates').takeover();
                },

                payload: Joi.object({
                    template: Joi.string()
                        .base64({ paddingRequired: false, urlSafe: true })
                        .max(512)
                        .example('AAAAAQAACnA')
                        .required()
                        .description('Template ID')
                })
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/templates/test',
        async handler(request) {
            try {
                request.logger.info({ msg: 'Trying to send test message', payload: request.payload });

                let template = await templates.get(request.payload.template);
                if (!template) {
                    return {
                        error: 'Template was not found'
                    };
                }

                let accountId = template.account || request.payload.account;
                if (!accountId) {
                    return { error: 'Account ID not provided' };
                }

                let accountObject = new Account({ redis, account: accountId, call, secret: await getSecret() });

                let account;
                try {
                    account = await accountObject.loadAccountData();
                } catch (err) {
                    return {
                        error: err.message
                    };
                }

                try {
                    return await accountObject.queueMessage(
                        {
                            account: account.account,
                            template: template.id,
                            from: {
                                name: account.name,
                                address: account.email
                            },
                            to: [{ name: '', address: request.payload.to }],
                            render: {
                                params: request.payload.params || {}
                            },
                            copy: false,
                            deliveryAttempts: 0
                        },
                        { source: 'ui' }
                    );
                } catch (err) {
                    return {
                        error: err.message
                    };
                }
            } catch (err) {
                request.logger.error({ msg: 'Failed sending test message', err });
                return {
                    success: false,
                    error: err.message
                };
            }
        },
        options: {
            tags: ['test'],
            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                failAction,

                payload: Joi.object({
                    account: accountIdSchema.default(null),
                    template: Joi.string()
                        .base64({ paddingRequired: false, urlSafe: true })
                        .max(512)
                        .example('AAAAAQAACnA')
                        .required()
                        .description('Template ID'),
                    to: Joi.string().email().required().description('Recipient address'),
                    params: Joi.object().description('Optional handlebars values').unknown()
                })
            }
        }
    });

    // Gateway routes

    server.route({
        method: 'GET',
        path: '/admin/gateways',
        async handler(request, h) {
            let gatewayObject = new Gateway({ redis });

            let gateways = await gatewayObject.listGateways(request.query.page - 1, request.query.pageSize);

            if (gateways.pages < request.query.page) {
                request.query.page = gateways.pages;
            }

            let nextPage = false;
            let prevPage = false;

            let getPagingUrl = page => {
                let url = new URL(`admin/gateways`, 'http://localhost');
                url.searchParams.append('page', page);
                if (request.query.pageSize !== DEFAULT_PAGE_SIZE) {
                    url.searchParams.append('pageSize', request.query.pageSize);
                }
                return url.pathname + url.search;
            };

            if (gateways.pages > gateways.page + 1) {
                nextPage = getPagingUrl(gateways.page + 2);
            }

            if (gateways.page > 0) {
                prevPage = getPagingUrl(gateways.page);
            }

            return h.view(
                'gateways/index',
                {
                    pageTitle: 'Email Gateways',
                    menuGateways: true,

                    showPaging: gateways.pages > 1,
                    nextPage,
                    prevPage,
                    firstPage: gateways.page === 0,
                    pageLinks: new Array(gateways.pages || 1).fill(0).map((z, i) => ({
                        url: getPagingUrl(i + 1),
                        title: i + 1,
                        active: i === gateways.page
                    })),

                    gateways: gateways.gateways.map(entry => {
                        let label = {};
                        if (entry.deliveries && !entry.lastError) {
                            label.type = 'success';
                            label.name = 'Connected';
                        } else if (entry.lastError) {
                            label.type = 'danger';
                            label.name = 'Error';
                            label.error = entry.lastError.response;
                        } else {
                            label.type = 'info';
                            label.name = 'Not used';
                        }

                        return Object.assign(entry, {
                            timeStr: entry.lastUse ? entry.lastUse.toISOString() : null,
                            label
                        });
                    })
                },
                {
                    layout: 'app'
                }
            );
        },

        options: {
            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                async failAction(request, h /*, err*/) {
                    return h.redirect('/admin/gateways').takeover();
                },

                query: Joi.object({
                    page: Joi.number().integer().min(1).max(1000000).default(1),
                    pageSize: Joi.number().integer().min(1).max(250).default(DEFAULT_PAGE_SIZE)
                })
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/admin/gateways/new',
        async handler(request, h) {
            return h.view(
                'gateways/new',
                {
                    pageTitle: 'Email Gateways',
                    menuGateways: true,
                    wellKnownServices: JSON.stringify(Object.keys(wellKnownServices).map(key => Object.assign({ key }, wellKnownServices[key])))
                },
                {
                    layout: 'app'
                }
            );
        }
    });

    server.route({
        method: 'GET',
        path: '/admin/gateways/gateway/{gateway}',
        async handler(request, h) {
            let gatewayObject = new Gateway({ gateway: request.params.gateway, redis, secret: await getSecret() });
            let gatewayData = await gatewayObject.loadGatewayData();

            let label = {};
            if (gatewayData.deliveries && !gatewayData.lastError) {
                label.type = 'success';
                label.name = 'Connected';
            } else if (gatewayData.lastError) {
                label.type = 'danger';
                label.name = 'Error';
                label.error = gatewayData.lastError.response;
            } else {
                label.type = 'info';
                label.name = 'Not used';
            }

            return h.view(
                'gateways/gateway',
                {
                    pageTitle: 'Email Gateways',
                    menuGateways: true,
                    wellKnownServices: JSON.stringify(Object.keys(wellKnownServices).map(key => Object.assign({ key }, wellKnownServices[key]))),

                    gateway: gatewayData,
                    label
                },
                {
                    layout: 'app'
                }
            );
        },

        options: {
            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                async failAction(request, h, err) {
                    await request.flash({ type: 'danger', message: `Invalid gateway request: ${err.message}` });
                    return h.redirect('/admin/gateways').takeover();
                },

                params: Joi.object({
                    gateway: Joi.string().max(256).required().example('sendgun').description('Gateway ID')
                })
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/admin/gateways/edit/{gateway}',
        async handler(request, h) {
            let gatewayObject = new Gateway({ gateway: request.params.gateway, redis, secret: await getSecret() });
            let gatewayData = await gatewayObject.loadGatewayData();

            let hasSMTPPass = !!gatewayData.pass;
            delete gatewayData.pass;

            return h.view(
                'gateways/edit',
                {
                    pageTitle: 'Email Gateways',
                    menuGateways: true,
                    wellKnownServices: JSON.stringify(Object.keys(wellKnownServices).map(key => Object.assign({ key }, wellKnownServices[key]))),
                    values: gatewayData,
                    gatewayData,
                    hasSMTPPass
                },
                {
                    layout: 'app'
                }
            );
        },

        options: {
            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                async failAction(request, h, err) {
                    await request.flash({ type: 'danger', message: `Invalid gateway request: ${err.message}` });
                    return h.redirect('/admin/gateways').takeover();
                },

                params: Joi.object({
                    gateway: Joi.string().max(256).required().example('sendgun').description('Gateway ID')
                })
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/gateways/new',
        async handler(request, h) {
            try {
                let gatewayData = {
                    gateway: request.payload.gateway || null,
                    name: request.payload.name || null,
                    host: request.payload.host || null,
                    port: request.payload.port || null,
                    secure: request.payload.secure || null,
                    user: request.payload.user || null,
                    pass: request.payload.pass || null,
                    tls: {}
                };

                let gatewayObject = new Gateway({ redis, secret: await getSecret() });
                let result = await gatewayObject.create(gatewayData);

                if (result.state === 'new') {
                    await request.flash({ type: 'success', message: `Added new SMTP gateway`, result });
                } else {
                    await request.flash({ type: 'success', message: `Updated SMTP gateway`, result });
                }

                return h.redirect(`/admin/gateways/gateway/${encodeURIComponent(result.gateway)}?state=${result.state}`);
            } catch (err) {
                await request.flash({ type: 'danger', message: `Couldn't add gateway. Try again.` });
                request.logger.error({ msg: 'Failed to add new gateway', err });

                return h.view(
                    'gateways/new',
                    {
                        pageTitle: 'Email Gateways',
                        menuGateways: true,
                        wellKnownServices: JSON.stringify(Object.keys(wellKnownServices).map(key => Object.assign({ key }, wellKnownServices[key])))
                    },
                    {
                        layout: 'app'
                    }
                );
            }
        },

        options: {
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

                    await request.flash({ type: 'danger', message: `Couldn't add gateway. Try again.` });
                    request.logger.error({ msg: 'Failed to add new gateway', err });

                    return h
                        .view(
                            'gateways/new',
                            {
                                pageTitle: 'Email Gateways',
                                menuGateways: true,
                                wellKnownServices: JSON.stringify(Object.keys(wellKnownServices).map(key => Object.assign({ key }, wellKnownServices[key]))),

                                errors
                            },
                            {
                                layout: 'app'
                            }
                        )
                        .takeover();
                },

                payload: Joi.object({
                    gateway: Joi.string().empty('').trim().max(256).default(null).example('sendgun').description('Gateway ID').label('Gateway ID'),

                    name: Joi.string().empty('').max(256).example('John Smith').description('Account Name').label('Gateway Name').required(),

                    user: Joi.string().empty('').trim().max(1024).default(null).label('UserName'),
                    pass: Joi.string().empty('').max(1024).default(null).label('Password'),

                    host: Joi.string().hostname().example('smtp.gmail.com').description('Hostname to connect to').label('Hostname').required(),
                    port: Joi.number()
                        .integer()
                        .min(1)
                        .max(64 * 1024)
                        .example(465)
                        .description('Service port number')
                        .label('Port')
                        .required(),

                    secure: Joi.boolean()
                        .truthy('Y', 'true', '1', 'on')
                        .falsy('N', 'false', 0, '')
                        .default(false)
                        .example(true)
                        .description('Should connection use TLS. Usually true for port 465')
                        .label('TLS')
                })
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/gateways/edit',
        async handler(request, h) {
            try {
                let gatewayData = {
                    gateway: request.payload.gateway || null,
                    name: request.payload.name || null,
                    host: request.payload.host || null,
                    port: request.payload.port || null,
                    secure: request.payload.secure || null,
                    user: request.payload.user || null
                };

                if (request.payload.pass) {
                    gatewayData.pass = request.payload.pass;
                }

                if (!request.payload.user && !request.payload.pass) {
                    gatewayData.pass = null;
                }

                let gatewayObject = new Gateway({ gateway: request.payload.gateway, redis, secret: await getSecret() });
                let result = await gatewayObject.update(gatewayData);

                await request.flash({ type: 'success', message: `Updated SMTP gateway`, result });

                return h.redirect(`/admin/gateways/gateway/${encodeURIComponent(result.gateway)}`);
            } catch (err) {
                await request.flash({ type: 'danger', message: `Couldn't save gateway. Try again.` });
                request.logger.error({ msg: 'Failed to update gateway', err });

                let gatewayObject = new Gateway({ gateway: request.payload.gateway, redis, secret: await getSecret() });
                let gatewayData = await gatewayObject.loadGatewayData();

                let hasSMTPPass = !!gatewayData.pass;

                return h.view(
                    'gateways/edit',
                    {
                        pageTitle: 'Email Gateways',
                        menuGateways: true,
                        wellKnownServices: JSON.stringify(Object.keys(wellKnownServices).map(key => Object.assign({ key }, wellKnownServices[key]))),
                        hasSMTPPass,
                        gatewayData
                    },
                    {
                        layout: 'app'
                    }
                );
            }
        },

        options: {
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

                    await request.flash({ type: 'danger', message: `Couldn't save gateway. Try again.` });
                    request.logger.error({ msg: 'Failed to update gateway', err });

                    let gatewayObject = new Gateway({ gateway: request.payload.gateway, redis, secret: await getSecret() });
                    let gatewayData = await gatewayObject.loadGatewayData();

                    let hasSMTPPass = !!gatewayData.pass;

                    return h
                        .view(
                            'gateways/edit',
                            {
                                pageTitle: 'Email Gateways',
                                menuGateways: true,
                                wellKnownServices: JSON.stringify(Object.keys(wellKnownServices).map(key => Object.assign({ key }, wellKnownServices[key]))),
                                hasSMTPPass,
                                gatewayData,

                                errors
                            },
                            {
                                layout: 'app'
                            }
                        )
                        .takeover();
                },

                payload: Joi.object({
                    gateway: Joi.string().empty('').trim().max(256).default(null).example('sendgun').description('Gateway ID').label('Gateway ID').required(),

                    name: Joi.string().empty('').max(256).example('John Smith').description('Account Name').label('Gateway Name').required(),

                    user: Joi.string().empty('').trim().max(1024).default(null).label('UserName'),
                    pass: Joi.string().empty('').max(1024).default(null).label('Password'),

                    host: Joi.string().hostname().example('smtp.gmail.com').description('Hostname to connect to').label('Hostname').required(),
                    port: Joi.number()
                        .integer()
                        .min(1)
                        .max(64 * 1024)
                        .example(465)
                        .description('Service port number')
                        .label('Port')
                        .required(),

                    secure: Joi.boolean()
                        .truthy('Y', 'true', '1', 'on')
                        .falsy('N', 'false', 0, '')
                        .default(false)
                        .example(true)
                        .description('Should connection use TLS. Usually true for port 465')
                        .label('TLS')
                })
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/gateways/test',
        async handler(request) {
            let { gateway, host, port, user, pass, secure } = request.payload;

            try {
                if (user && !pass && gateway) {
                    let gatewayObject = new Gateway({ gateway, redis, secret: await getSecret() });
                    try {
                        let gatewayData = await gatewayObject.loadGatewayData();
                        if (gatewayData) {
                            pass = gatewayData.pass || '';
                        }
                    } catch (err) {
                        // ignore
                    }
                }

                let accountData = {
                    smtp: {
                        host,
                        port,
                        secure,
                        auth:
                            user || pass
                                ? {
                                      user,
                                      pass: pass || ''
                                  }
                                : false
                    }
                };

                let verifyResult = await verifyAccountInfo(redis, accountData, request.logger.child({ gateway, action: 'verify-gateway' }));

                if (verifyResult) {
                    if (verifyResult.smtp && verifyResult.smtp.error && verifyResult.smtp.code) {
                        switch (verifyResult.smtp.code) {
                            case 'EDNS':
                                verifyResult.smtp.error = request.app.gt.gettext('Server hostname was not found');
                                break;
                            case 'EAUTH':
                                verifyResult.smtp.error = request.app.gt.gettext('Invalid username or password');
                                break;
                            case 'ENOAUTH':
                                verifyResult.smtp.error = request.app.gt.gettext('Authentication credentials were not provided');
                                break;
                            case 'EOAUTH2':
                                verifyResult.smtp.error = request.app.gt.gettext('OAuth2 authentication failed');
                                break;
                            case 'ETLS':
                                verifyResult.smtp.error = request.app.gt.gettext('TLS protocol error');
                                break;
                            case 'ESOCKET':
                                if (/openssl/.test(verifyResult.smtp.error)) {
                                    verifyResult.smtp.error = request.app.gt.gettext('TLS protocol error');
                                }
                                break;
                            case 'ETIMEDOUT':
                                verifyResult.smtp.error = request.app.gt.gettext('Connection timed out');
                                break;
                            case 'ECONNECTION':
                                verifyResult.smtp.error = request.app.gt.gettext('Could not connect to server');
                                break;
                            case 'EPROTOCOL':
                                verifyResult.smtp.error = request.app.gt.gettext('Unexpected server response');
                                break;
                        }
                    }
                }

                return verifyResult.smtp;
            } catch (err) {
                request.logger.error({ msg: 'Failed posting request', host, port, user, pass: !!pass, err });
                return {
                    success: false,
                    error: err.message
                };
            }
        },
        options: {
            tags: ['test'],
            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                failAction,

                payload: Joi.object({
                    gateway: Joi.string().empty('').trim().max(256).example('sendgun').description('Gateway ID'),
                    user: Joi.string().empty('').trim().max(1024).label('UserName'),
                    pass: Joi.string().empty('').max(1024).label('Password'),
                    host: Joi.string().hostname().example('smtp.gmail.com').description('Hostname to connect to').label('Hostname'),
                    port: Joi.number()
                        .integer()
                        .min(1)
                        .max(64 * 1024)
                        .example(465)
                        .description('Service port number')
                        .label('Port'),
                    secure: Joi.boolean()
                        .truthy('Y', 'true', '1', 'on')
                        .falsy('N', 'false', 0, '')
                        .default(false)
                        .example(true)
                        .description('Should connection use TLS. Usually true for port 465')
                        .label('TLS')
                })
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/gateways/delete/{gateway}',
        async handler(request, h) {
            try {
                let gatewayObject = new Gateway({ redis, gateway: request.params.gateway, secret: await getSecret() });

                let deleted = await gatewayObject.delete();
                if (deleted) {
                    await request.flash({ type: 'info', message: `Gateway deleted` });
                }

                return h.redirect('/admin/gateways');
            } catch (err) {
                await request.flash({ type: 'danger', message: `Couldn't delete gateway. Try again.` });
                request.logger.error({ msg: 'Failed to delete the gateway', err, gateway: request.payload.gateway, remoteAddress: request.app.ip });
                return h.redirect(`/admin/gateways/${request.params.gateway}`);
            }
        },
        options: {
            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                async failAction(request, h, err) {
                    await request.flash({ type: 'danger', message: `Couldn't delete gateway. Try again.` });
                    request.logger.error({ msg: 'Failed to delete delete the gateway', err });

                    return h.redirect('/admin/gateways').takeover();
                },

                params: Joi.object({
                    gateway: Joi.string().max(256).required().example('sendgun').description('Gateway ID')
                })
            }
        }
    });

    // Token routes

    server.route({
        method: 'GET',
        path: '/admin/tokens',
        async handler(request, h) {
            let accountData;
            if (request.query.account) {
                let accountObject = new Account({ redis, account: request.query.account });
                accountData = await accountObject.loadAccountData();
            }

            const data = await tokens.list(request.query.account, request.query.page - 1, request.query.pageSize);

            data.tokens.forEach(entry => {
                entry.access = entry.access || {};
                entry.access.timeStr =
                    entry.access && entry.access.time && typeof entry.access.time.toISOString === 'function' ? entry.access.time.toISOString() : null;
                entry.scopes = entry.scopes
                    ? entry.scopes.map((scope, i) => ({
                          name: scope === '*' ? 'all scopes' : scope,
                          first: !i
                      }))
                    : false;
            });

            let nextPage = false;
            let prevPage = false;

            let getPagingUrl = page => {
                let url = new URL(`admin/tokens`, 'http://localhost');

                if (page) {
                    url.searchParams.append('page', page);
                }

                if (request.query.pageSize !== DEFAULT_PAGE_SIZE) {
                    url.searchParams.append('pageSize', request.query.pageSize);
                }

                return url.pathname + url.search;
            };

            if (data.pages > data.page + 1) {
                nextPage = getPagingUrl(data.page + 2);
            }

            if (data.page > 0) {
                prevPage = getPagingUrl(data.page);
            }

            let newLink = new URL('/admin/tokens/new', 'http://localhost');
            if (request.query.account) {
                newLink.searchParams.append('account', request.query.account);
            }

            return h.view(
                'tokens/index',
                {
                    pageTitle: 'Access Tokens',
                    menuTokens: true,
                    data,

                    account: accountData,

                    showPaging: data.pages > 1,
                    nextPage,
                    prevPage,
                    firstPage: data.page === 0,
                    pageLinks: new Array(data.pages || 1).fill(0).map((z, i) => ({
                        url: getPagingUrl(i + 1, request.query.state, request.query.query),
                        title: i + 1,
                        active: i === data.page
                    })),

                    newLink: newLink.pathname + newLink.search
                },
                {
                    layout: 'app'
                }
            );
        },

        options: {
            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                async failAction(request, h /*, err*/) {
                    return h.redirect('/admin/tokens').takeover();
                },

                query: Joi.object({
                    account: accountIdSchema.default(null),
                    page: Joi.number().integer().min(1).max(1000000).default(1),
                    pageSize: Joi.number().integer().min(1).max(250).default(DEFAULT_PAGE_SIZE)
                })
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/admin/tokens/new',
        async handler(request, h) {
            let accountTokensLink = new URL('/admin/tokens', 'http://localhost');

            let accountData;
            if (request.query.account) {
                let accountObject = new Account({ redis, account: request.query.account });
                accountData = await accountObject.loadAccountData();
                accountTokensLink.searchParams.append('account', request.query.account);
            }

            return h.view(
                'tokens/new',
                {
                    pageTitle: 'Access Tokens',
                    menuTokens: true,
                    values: {
                        scopesAll: true,
                        allAccounts: !request.query.account,
                        account: request.query.account
                    },
                    account: accountData,
                    accountTokensLink: accountTokensLink.pathname + accountTokensLink.search
                },
                {
                    layout: 'app'
                }
            );
        },

        options: {
            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                async failAction(request, h /*, err*/) {
                    return h.redirect('/admin/tokens').takeover();
                },

                query: Joi.object({
                    account: accountIdSchema.default(null)
                })
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/tokens/new',

        async handler(request) {
            try {
                let data = {
                    ip: request.app.ip,
                    remoteAddress: request.app.ip,
                    description: request.payload.description,
                    scopes: request.payload.scopes
                };

                if (request.payload.account) {
                    let accountObject = new Account({ redis, account: request.payload.account });
                    await accountObject.loadAccountData();
                    data.account = request.payload.account;
                }

                let token = await tokens.provision(data);

                return {
                    success: true,
                    token
                };
            } catch (err) {
                request.logger.error({ msg: 'Failed to generate token', err, remoteAddress: request.app.ip, description: request.payload.description });
                if (Boom.isBoom(err)) {
                    return Object.assign({ success: false }, err.output.payload);
                }
                return { success: false, error: err.code || 'Error', message: err.message };
            }
        },
        options: {
            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                failAction,

                payload: Joi.object({
                    description: Joi.string().empty('').trim().max(1024).required().example('Token description').description('Token description'),
                    scopes: Joi.array()
                        .items(Joi.string().valid('*', 'api', 'metrics', 'smtp', 'imap-proxy'))
                        .required()
                        .label('Scopes'),
                    account: accountIdSchema.default(null)
                })
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/tokens/delete',
        async handler(request, h) {
            try {
                let deleted = await tokens.delete(request.payload.token, { remoteAddress: request.app.ip });
                if (deleted) {
                    await request.flash({ type: 'info', message: `Token deleted` });
                }

                return h.redirect('/admin/tokens');
            } catch (err) {
                await request.flash({ type: 'danger', message: `Couldn't delete token. Try again.` });
                request.logger.error({ msg: 'Failed to delete access token', err, token: request.payload.token, remoteAddress: request.app.ip });
                return h.redirect('/admin/tokens');
            }
        },
        options: {
            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                async failAction(request, h, err) {
                    await request.flash({ type: 'danger', message: `Couldn't delete token. Try again.` });
                    request.logger.error({ msg: 'Failed to delete access token', err });

                    return h.redirect('/admin/tokens').takeover();
                },

                payload: Joi.object({ token: Joi.string().length(64).hex().required().example('123456').description('Access token') })
            }
        }
    });
}

module.exports = init;
