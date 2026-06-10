'use strict';

const Joi = require('joi');
const { redis, documentsQueue, notifyQueue, submitQueue } = require('../db');
const settings = require('../settings');
const consts = require('../consts');
const { REDIS_PREFIX } = consts;
const { failAction } = require('../tools');
const { handleError } = require('./route-helpers');
const { settingsSchema, settingsQuerySchema, errorResponses } = require('../schemas');

// Response variant of the settings schema. Secret values are masked and returned as booleans,
// any setting that has never been set is returned as null, and the virtual eventTypes key is
// not part of the stored settings.
const settingsOutputSchema = {};
for (let key of Object.keys(settingsSchema)) {
    if (settings.encryptedKeys.includes(key)) {
        settingsOutputSchema[key] = Joi.boolean()
            .allow(null)
            .example(true)
            .description('Whether a value is set for this setting. Secret values are never returned, only a boolean marker');
    } else {
        // Use a distinct label for the nullable response variant, otherwise the generated
        // OpenAPI spec would contain suffixed duplicates of the request-side components
        settingsOutputSchema[key] = settingsSchema[key].allow(null).label(`${key}Response`);
    }
}
settingsOutputSchema.eventTypes = Joi.array()
    .items(Joi.string().example('messageNew').label('EventTypeEntry'))
    .description('Supported webhook event types')
    .label('EventTypesList');

async function init(args) {
    const { server, notify, CORS_CONFIG } = args;

    server.route({
        method: 'GET',
        path: '/v1/settings',

        async handler(request) {
            let values = {};
            for (let key of Object.keys(request.query)) {
                if (request.query[key]) {
                    if (key === 'eventTypes') {
                        values[key] = Object.keys(consts)
                            .filter(key => /_NOTIFY?/.test(key))
                            .map(key => consts[key]);
                        continue;
                    }

                    let value = await settings.get(key);

                    if (settings.encryptedKeys.includes(key)) {
                        // do not reveal secret values
                        // instead show boolean value true if value is set, or false if it's not
                        value = value ? true : false;
                    }

                    values[key] = value;
                }
            }
            return values;
        },
        options: {
            description: 'List specific settings',
            notes: 'List setting values for specific keys',
            tags: ['api', 'Settings'],

            plugins: {
                'hapi-swagger': {
                    responses: errorResponses(400, 401, 403, 429, 500)
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

                query: Joi.object(settingsQuerySchema).label('SettingsQuery')
            },

            response: {
                schema: Joi.object(settingsOutputSchema).label('SettingsQueryResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/v1/settings',

        async handler(request) {
            let updated = [];
            for (let key of Object.keys(request.payload)) {
                switch (key) {
                    case 'serviceUrl': {
                        if (request.payload.serviceUrl) {
                            let url = new URL(request.payload.serviceUrl);
                            request.payload.serviceUrl = url.origin;
                        }
                        break;
                    }

                    case 'webhooksEnabled':
                        if (!request.payload.webhooksEnabled) {
                            // clear error message (if exists)
                            await settings.clear('webhookErrorFlag');
                        }
                        break;
                }

                await settings.set(key, request.payload[key]);
                updated.push(key);
            }

            // Broadcast to all workers (including this one); each reloads its HTTP proxy agent via
            // the 'settings' message handler, so no inline reload is needed here.
            notify('settings', request.payload);
            return { updated };
        },
        options: {
            description: 'Set setting values',
            notes: 'Set setting values for specific keys',
            tags: ['api', 'Settings'],

            plugins: {
                'hapi-swagger': {
                    responses: errorResponses(400, 401, 403, 429, 500)
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

                payload: Joi.object(settingsSchema).label('Settings')
            },

            response: {
                schema: Joi.object({
                    updated: Joi.array().items(Joi.string().example('notifyHeaders')).description('List of updated setting keys').label('UpdatedSettings')
                }).label('SettingsUpdatedResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/v1/settings/queue/{queue}',

        async handler(request) {
            try {
                let queue = request.params.queue;
                let values = {
                    queue
                };

                const [resActive, resDelayed, resPaused, resWaiting, resMeta] = await redis
                    .multi()
                    .llen(`${REDIS_PREFIX}bull:${queue}:active`)
                    .zcard(`${REDIS_PREFIX}bull:${queue}:delayed`)
                    .llen(`${REDIS_PREFIX}bull:${queue}:paused`)
                    .llen(`${REDIS_PREFIX}bull:${queue}:wait`)
                    .hget(`${REDIS_PREFIX}bull:${queue}:meta`, 'paused')
                    .exec();

                if (resActive[0] || resDelayed[0] || resPaused[0] || resWaiting[0]) {
                    // counting failed
                    let err = new Error('Failed to count queue length');
                    err.statusCode = 500;
                    throw err;
                }

                values.jobs = {
                    active: Number(resActive[1]) || 0,
                    delayed: Number(resDelayed[1]) || 0,
                    paused: Number(resPaused[1]) || 0,
                    waiting: Number(resWaiting[1]) || 0
                };

                values.paused = !!Number(resMeta[1]) || false;

                return values;
            } catch (err) {
                handleError(request, err);
            }
        },
        options: {
            description: 'Show queue information',
            notes: 'Show queue status and current state',
            tags: ['api', 'Settings'],

            plugins: {
                'hapi-swagger': {
                    responses: errorResponses(400, 401, 403, 429, 500)
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
                    queue: Joi.string()
                        .empty('')
                        .trim()
                        .valid('notify', 'submit', 'documents')
                        .required()
                        .example('notify')
                        .description('Queue ID')
                        .label('QueueId')
                })
            },

            response: {
                schema: Joi.object({
                    queue: Joi.string()
                        .empty('')
                        .trim()
                        .valid('notify', 'submit', 'documents')
                        .required()
                        .example('notify')
                        .description('Queue ID')
                        .label('QueueIdResponse'),
                    jobs: Joi.object({
                        active: Joi.number().integer().example(123).description('Jobs that are currently being processed'),
                        delayed: Joi.number().integer().example(123).description('Jobs that are processed in the future'),
                        paused: Joi.number().integer().example(123).description('Jobs that would be processed once queue processing is resumed'),
                        waiting: Joi.number()
                            .integer()
                            .example(123)
                            .description('Jobs that should be processed, but are waiting until there are any free handlers')
                    }).label('QueueJobs'),
                    paused: Joi.boolean().example(false).description('Is the queue paused or not')
                }).label('SettingsQueueResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'PUT',
        path: '/v1/settings/queue/{queue}',

        async handler(request) {
            try {
                let queue = request.params.queue;

                let queueObj = {
                    documents: documentsQueue,
                    notify: notifyQueue,
                    submit: submitQueue
                }[queue];

                let values = {
                    queue
                };

                for (let key of Object.keys(request.payload)) {
                    switch (key) {
                        case 'paused':
                            if (request.payload[key]) {
                                await queueObj.pause();
                            } else {
                                await queueObj.resume();
                            }
                            break;
                    }
                }

                values.paused = await queueObj.isPaused();

                return values;
            } catch (err) {
                handleError(request, err);
            }
        },
        options: {
            description: 'Set queue settings',
            notes: 'Set queue settings',
            tags: ['api', 'Settings'],

            plugins: {
                'hapi-swagger': {
                    responses: errorResponses(400, 401, 403, 429, 500)
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
                    queue: Joi.string()
                        .empty('')
                        .trim()
                        .valid('notify', 'submit', 'documents')
                        .required()
                        .example('notify')
                        .description('Queue ID')
                        .label('QueueIdParam')
                }),

                payload: Joi.object({
                    paused: Joi.boolean().empty('').example(false).description('Set queue state to paused')
                }).label('SettingsPutQueuePayload')
            },

            response: {
                schema: Joi.object({
                    queue: Joi.string()
                        .empty('')
                        .trim()
                        .valid('notify', 'submit', 'documents')
                        .required()
                        .example('notify')
                        .description('Queue ID')
                        .label('QueueIdPutResponse'),
                    paused: Joi.boolean().example(false).description('Is the queue paused or not')
                }).label('SettingsPutQueueResponse'),
                failAction: 'log'
            }
        }
    });
}

module.exports = init;
