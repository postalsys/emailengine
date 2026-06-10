'use strict';

const Joi = require('joi');
const { failAction } = require('../tools');
const { oauth2Apps } = require('../oauth2-apps');
const { pubSubErrorSchema } = require('../schemas');
const { handleError, flattenOAuthAppMeta } = require('./route-helpers');

async function init(args) {
    const { server, CORS_CONFIG } = args;

    server.route({
        method: 'GET',
        path: '/v1/pubsub/status',

        async handler(request) {
            try {
                let response = await oauth2Apps.list(request.query.page, request.query.pageSize, { pubsub: true });

                let apps = response.apps.map(app => {
                    flattenOAuthAppMeta(app);
                    return { id: app.id, name: app.name || null, lastError: app.lastError || null, pubSubError: app.pubSubError || null };
                });

                return {
                    total: response.total,
                    page: response.page,
                    pages: response.pages,
                    apps
                };
            } catch (err) {
                handleError(request, err);
            }
        },

        options: {
            description: 'List Pub/Sub status',
            notes: 'Lists Pub/Sub enabled OAuth2 applications and their subscription status',
            tags: ['api', 'OAuth2 Applications'],

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
                        .description('Page number (zero indexed, so use 0 for first page)')
                        .label('PageNumber'),
                    pageSize: Joi.number().integer().min(1).max(1000).default(20).example(20).description('How many entries per page').label('PageSize')
                }).label('PubSubStatusFilter')
            },

            response: {
                schema: Joi.object({
                    total: Joi.number().integer().example(120).description('How many matching entries').label('TotalNumber'),
                    page: Joi.number().integer().example(0).description('Current page (0-based index)').label('PageNumber'),
                    pages: Joi.number().integer().example(24).description('Total page count').label('PagesNumber'),

                    apps: Joi.array()
                        .items(
                            Joi.object({
                                id: Joi.string().max(256).required().example('AAABhaBPHscAAAAH').description('OAuth2 application ID'),
                                name: Joi.string().allow(null).max(256).example('My Gmail App').description('Display name for the app'),
                                lastError: Joi.object({
                                    response: Joi.string().example('Enable the Cloud Pub/Sub API').description('Error message')
                                })
                                    .allow(null)
                                    .description('Last Pub/Sub related error for this app - either a setup error or an OAuth2 token renewal failure')
                                    .label('PubSubSetupError'),
                                pubSubError: pubSubErrorSchema.allow(null)
                            }).label('PubSubAppStatus')
                        )
                        .label('PubSubAppStatusList')
                }).label('PubSubStatusResponse'),
                failAction: 'log'
            }
        }
    });
}

module.exports = init;
