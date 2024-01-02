'use strict';

const { redis } = require('../db');
const { Account } = require('../account');
const getSecret = require('../get-secret');
const { templates } = require('../templates');
const Boom = require('@hapi/boom');
const Joi = require('joi');
const { failAction } = require('../tools');

const { templateSchemas, accountIdSchema } = require('../schemas');

async function init(args) {
    const { server, call, CORS_CONFIG } = args;

    server.route({
        method: 'POST',
        path: '/v1/templates/template',

        async handler(request) {
            try {
                if (request.payload.account) {
                    // throws if account does not exist
                    let accountObject = new Account({ redis, account: request.payload.account, call, secret: await getSecret() });
                    await accountObject.loadAccountData();
                }

                return await templates.create(
                    request.payload.account,
                    {
                        name: request.payload.name,
                        description: request.payload.description,
                        format: request.payload.format
                    },
                    request.payload.content
                );
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
            description: 'Create template',
            notes: 'Create a new stored template. Templates can be used when sending emails as the content of the message.',
            tags: ['api', 'Templates'],

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

                payload: Joi.object({
                    account: Joi.string()
                        .empty('')
                        .trim()
                        .allow(null)
                        .max(256)
                        .example('example')
                        .description('Account ID. Use `null` for public templates.')
                        .required(),

                    name: Joi.string().max(256).example('Transaction receipt').description('Name of the template').label('TemplateName').required(),
                    description: Joi.string()
                        .allow('')
                        .max(1024)
                        .example('Something about the template')
                        .description('Optional description of the template')
                        .label('TemplateDescription'),
                    format: Joi.string()
                        .valid('html', 'mjml', 'markdown')
                        .default('html')
                        .description('Markup language for HTML ("html", "markdown" or "mjml")'),
                    content: Joi.object({
                        subject: templateSchemas.subject,
                        text: templateSchemas.text,
                        html: templateSchemas.html,
                        previewText: templateSchemas.previewText
                    })
                        .required()
                        .label('CreateTemplateContent')
                }).label('CreateTemplate')
            },

            response: {
                schema: Joi.object({
                    created: Joi.boolean().description('Was the template created or not'),
                    account: accountIdSchema.required(),
                    id: Joi.string().max(256).required().example('example').description('Template ID')
                }).label('CreateTemplateResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'PUT',
        path: '/v1/templates/template/{template}',

        async handler(request) {
            try {
                let meta = {};
                for (let key of ['name', 'description', 'format']) {
                    if (typeof request.payload[key] !== 'undefined') {
                        meta[key] = request.payload[key];
                    }
                }

                return await templates.update(request.params.template, meta, request.payload.content);
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
            description: 'Update a template',
            notes: 'Update a stored template.',
            tags: ['api', 'Templates'],

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
                    template: Joi.string().max(256).required().example('example').description('Template ID')
                }).label('GetTemplateRequest'),

                payload: Joi.object({
                    name: Joi.string().empty('').max(256).example('Transaction receipt').description('Name of the template').label('TemplateName'),
                    description: Joi.string()
                        .allow('')
                        .max(1024)
                        .example('Something about the template')
                        .description('Optional description of the template')
                        .label('TemplateDescription'),
                    format: Joi.string()
                        .empty('')
                        .valid('html', 'mjml', 'markdown')
                        .default('html')
                        .description('Markup language for HTML ("html", "markdown" or "mjml")'),
                    content: Joi.object({
                        subject: templateSchemas.subject,
                        text: templateSchemas.text,
                        html: templateSchemas.html,
                        previewText: templateSchemas.previewText
                    }).label('UpdateTemplateContent')
                }).label('UpdateTemplate')
            },

            response: {
                schema: Joi.object({
                    updated: Joi.boolean().description('Was the template updated or not'),
                    account: accountIdSchema.required(),
                    id: Joi.string().max(256).required().example('example').description('Template ID')
                }).label('UpdateTemplateResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/v1/templates',

        async handler(request) {
            try {
                if (request.query.account) {
                    // throws if account does not exist
                    let accountObject = new Account({ redis, account: request.query.account, call, secret: await getSecret() });
                    await accountObject.loadAccountData();
                }

                return await templates.list(request.query.account, request.query.page, request.query.pageSize);
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
            description: 'List account templates',
            notes: 'Lists stored templates for the account',
            tags: ['api', 'Templates'],

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
                    account: Joi.string().empty('').max(256).example('example').description('Account ID to list the templates for'),

                    page: Joi.number()
                        .integer()
                        .min(0)
                        .max(1024 * 1024)
                        .default(0)
                        .example(0)
                        .description('Page number (zero indexed, so use 0 for first page)')
                        .label('PageNumber'),
                    pageSize: Joi.number().integer().min(1).max(1000).default(20).example(20).description('How many entries per page').label('PageSize')
                }).label('AccountTemplatesRequest')
            },

            response: {
                schema: Joi.object({
                    account: accountIdSchema.required(),
                    total: Joi.number().integer().example(120).description('How many matching entries').label('TotalNumber'),
                    page: Joi.number().integer().example(0).description('Current page (0-based index)').label('PageNumber'),
                    pages: Joi.number().integer().example(24).description('Total page count').label('PagesNumber'),

                    templates: Joi.array()
                        .items(
                            Joi.object({
                                id: Joi.string().max(256).required().example('AAABgS-UcAYAAAABAA').description('Template ID'),
                                name: Joi.string().max(256).example('Transaction receipt').description('Name of the template').label('TemplateName').required(),
                                description: Joi.string()
                                    .allow('')
                                    .max(1024)
                                    .example('Something about the template')
                                    .description('Optional description of the template')
                                    .label('TemplateDescription'),
                                format: Joi.string()
                                    .valid('html', 'mjml', 'markdown')
                                    .default('html')
                                    .description('Markup language for HTML ("html", "markdown" or "mjml")'),
                                created: Joi.date().iso().example('2021-02-17T13:43:18.860Z').description('The time this template was created'),
                                updated: Joi.date().iso().example('2021-02-17T13:43:18.860Z').description('The time this template was last updated')
                            }).label('AccountTemplate')
                        )
                        .label('AccountTemplatesList')
                }).label('AccountTemplatesResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/v1/templates/template/{template}',

        async handler(request) {
            try {
                return await templates.get(request.params.template);
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
            description: 'Get template information',
            notes: 'Retrieve template content and information',
            tags: ['api', 'Templates'],

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
                    template: Joi.string().max(256).required().example('example').description('Template ID')
                }).label('GetTemplateRequest')
            },

            response: {
                schema: Joi.object({
                    account: accountIdSchema.required(),
                    id: Joi.string().max(256).required().example('AAABgS-UcAYAAAABAA').description('Template ID'),
                    name: Joi.string().max(256).example('Transaction receipt').description('Name of the template').label('TemplateName').required(),
                    description: Joi.string()
                        .allow('')
                        .max(1024)
                        .example('Something about the template')
                        .description('Optional description of the template')
                        .label('TemplateDescription'),
                    format: Joi.string()
                        .valid('html', 'mjml', 'markdown')
                        .default('html')
                        .description('Markup language for HTML ("html", "markdown" or "mjml")'),
                    created: Joi.date().iso().example('2021-02-17T13:43:18.860Z').description('The time this template was created'),
                    updated: Joi.date().iso().example('2021-02-17T13:43:18.860Z').description('The time this template was last updated'),
                    content: Joi.object({
                        subject: templateSchemas.subject,
                        text: templateSchemas.text,
                        html: templateSchemas.html,
                        previewText: templateSchemas.previewText,
                        format: Joi.string()
                            .valid('html', 'mjml', 'markdown')
                            .default('html')
                            .description('Markup language for HTML ("html", "markdown" or "mjml")')
                    }).label('RequestTemplateContent')
                }).label('AccountTemplateResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'DELETE',
        path: '/v1/templates/template/{template}',

        async handler(request) {
            try {
                return await templates.del(request.params.template);
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
            description: 'Remove a template',
            notes: 'Delete a stored template',
            tags: ['api', 'Templates'],

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
                    template: Joi.string().max(256).required().example('example').description('Template ID')
                }).label('GetTemplateRequest')
            },

            response: {
                schema: Joi.object({
                    deleted: Joi.boolean().truthy('Y', 'true', '1').falsy('N', 'false', 0).default(true).description('Was the template deleted'),
                    account: accountIdSchema.required(),
                    id: Joi.string().max(256).required().example('AAABgS-UcAYAAAABAA').description('Template ID')
                }).label('DeleteTemplateRequestResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'DELETE',
        path: '/v1/templates/account/{account}',

        async handler(request) {
            let accountObject = new Account({ redis, account: request.params.account, call, secret: await getSecret() });

            try {
                // throws if account does not exist
                await accountObject.loadAccountData();

                return await templates.flush(request.params.account);
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
            description: 'Flush templates',
            notes: 'Delete all stored templates for an account',
            tags: ['api', 'Templates'],

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
                    force: Joi.boolean()
                        .truthy('Y', 'true', '1')
                        .falsy('N', 'false', 0)
                        .default(false)
                        .valid(true)
                        .description('Must be true in order to flush templates')
                        .label('ForceFlush')
                }).label('FlushTemplateQuerye')
            },

            response: {
                schema: Joi.object({
                    deleted: Joi.boolean().truthy('Y', 'true', '1').falsy('N', 'false', 0).default(true).description('Was the account flushed'),
                    account: accountIdSchema.required()
                }).label('DeleteTemplateRequestResponse'),
                failAction: 'log'
            }
        }
    });
}

module.exports = init;
