'use strict';

const Joi = require('joi');
const { QUEUES_BY_NAME } = require('../db');
const settings = require('../settings');
const consts = require('../consts');
const { failAction, maybeReloadTlsCertificates, TLS_MATERIAL_SETTINGS } = require('../tools');
const { tlsSettingChanged } = require('../tls/store');
const { queueStats } = require('../queue-stats');
const Boom = require('@hapi/boom');
const { handleError, maskSecrets, containsMaskedSecret, isMaskedRoundTrip, assertNoPrivilegedSettings, MASKED } = require('./route-helpers');
const { settingsSchema, settingsQuerySchema, apiResponses, ENUM_DESCRIPTIONS } = require('../schemas');

// Response variant of the settings schema. Secret values are masked and returned as booleans,
// any setting that has never been set is returned as null, and the virtual eventTypes key is
// not part of the stored settings.
const settingsOutputSchema = {};
for (let key of Object.keys(settingsSchema)) {
    if (settings.secretKeys.includes(key)) {
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

// The settings the two MCP settings tools offer: every key of the schema except the privileged
// ones (PRIVILEGED_SETTINGS_KEYS in lib/settings.js) and the ones the schema hides from the
// published document (`swaggerHidden`, the deprecated aliases), which the tool schema converter
// drops as well. Derived rather than listed, so a setting added to the schema is offered and one
// added to the privileged list is withdrawn without a second edit here. The REST handler refuses
// the privileged keys to a narrowed credential, so the `write/settings` grant means the same thing
// on both surfaces; test/settings-privileged-keys-test.js asserts the tool schema and the list
// agree.
const isHiddenSetting = key => (settingsSchema[key].describe().metas || []).some(meta => meta && meta.swaggerHidden);
const MCP_SETTINGS_KEYS = Object.keys(settingsSchema).filter(key => !settings.privilegedKeys.includes(key) && !isHiddenSetting(key));

async function init(args) {
    const { server, call, notify, CORS_CONFIG } = args;

    server.route({
        method: 'GET',
        path: '/v1/settings',

        async handler(request) {
            let values = {};
            try {
                // Before the first read, like the write below: the keys a narrowed credential may
                // not change are the ones it may not read either
                assertNoPrivilegedSettings(
                    request,
                    Object.keys(request.query).filter(key => request.query[key]),
                    'read'
                );

                for (let key of Object.keys(request.query)) {
                    if (request.query[key]) {
                        if (key === 'eventTypes') {
                            values[key] = Object.keys(consts)
                                .filter(key => /_NOTIFY?/.test(key))
                                .map(key => consts[key]);
                            continue;
                        }

                        let value = await settings.get(key);

                        if (settings.secretKeys.includes(key)) {
                            // do not reveal secret values
                            // instead show boolean value true if value is set, or false if it's not
                            value = value ? true : false;
                        }

                        values[key] = value;
                    }
                }
            } catch (err) {
                handleError(request, err);
            }

            // The global equivalents of the credential-bearing account fields. secretKeys above
            // covers the values that are hidden behind a boolean, which is not the same set:
            // proxyUrl, httpProxyUrl, webhooks and webhooksCustomHeaders are returned as values
            // (they are useful to read back) and used to be returned in full, so this endpoint
            // disclosed exactly what the account getters were masking. A narrowed credential is
            // refused the privileged keys above; this is what the unnarrowed one gets.
            maskSecrets(values);

            return values;
        },
        options: {
            description: 'List specific settings',
            notes: `List setting values for specific keys. Credentials are masked: the credentials in any proxy or webhook URL and the values of custom webhook headers read back as "${MASKED}", and encrypted secrets are returned as booleans. A masked value is not the stored one - POST /v1/settings skips it when it matches the stored value and refuses it otherwise.`,
            tags: ['api', 'Settings'],

            plugins: {
                mcp: {
                    name: 'get_settings',
                    title: 'Get settings',
                    description:
                        'Read instance settings. Set each setting you want returned to true. Secrets come back as a boolean saying whether a value is stored, credentials inside URLs are masked, and eventTypes lists the webhook event names the instance supports. Settings that would widen this credential (operator scripts, proxies, secrets, the built-in listeners and their TLS, mail certificate checking) are not offered.',
                    keep: MCP_SETTINGS_KEYS.concat(['eventTypes'])
                },
                openapi: {
                    responses: apiResponses('Returns the values of the settings requested via query arguments. Secrets are masked.', 400, 401, 403, 429, 500)
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
            let applied = {};
            // Only the keys whose value actually changed, unlike `applied` - see tlsSettingChanged()
            let tlsChanged = [];
            try {
                // Before the first write, so a refused payload leaves nothing half-applied
                assertNoPrivilegedSettings(request, Object.keys(request.payload));

                for (let key of Object.keys(request.payload)) {
                    let value = request.payload[key];

                    // GET /v1/settings masks stored credentials ("******"), and the masked values
                    // pass the schemas here - they are well-formed URLs and header lists - so a
                    // read-modify-write client would silently replace the stored credential with
                    // the literal mask. The unchanged masked echo of the stored value is skipped
                    // as "not an update"; a mask anywhere else is refused, because the credential
                    // it stands for cannot be reconstructed.
                    if (containsMaskedSecret(key, value)) {
                        if (isMaskedRoundTrip(key, value, await settings.get(key))) {
                            continue;
                        }
                        throw Boom.badRequest(
                            `The value for "${key}" carries the masked placeholder "${MASKED}" instead of a credential. Send the real value, or leave the key out to keep the stored one`
                        );
                    }

                    if (key === 'webhooksEnabled' && !value) {
                        // clear error message (if exists)
                        await settings.clear('webhookErrorFlag');
                    }

                    if (TLS_MATERIAL_SETTINGS.includes(key) && tlsSettingChanged(key, await settings.get(key), value)) {
                        tlsChanged.push(key);
                    }

                    await settings.set(key, value);
                    applied[key] = value;
                }
            } catch (err) {
                handleError(request, err);
            } finally {
                // Broadcast to all workers (including this one); each reloads its HTTP proxy agent
                // via the 'settings' message handler, so no inline reload is needed here. Only the
                // keys that were actually written: a skipped masked echo must not trigger reloads
                // either. In a finally because the keys are written one at a time: when a later
                // key fails, the earlier ones are already stored and the other workers still have
                // to reload for them, or they keep running on settings Redis no longer holds.
                notify('settings', applied);

                // What a listener serves is not carried by that broadcast, and no worker acts on
                // it. Until this was here, an instance switched to "self-signed only" through the
                // API went on offering its Let's Encrypt certificate, and a name added to
                // tlsHostnames was answered with the certificate that predates it, until something
                // restarted the workers. Each command reports its own failure, so this cannot mask
                // the error being thrown out of the catch.
                await maybeReloadTlsCertificates(call, request.logger, tlsChanged, { action: 'settings' });
            }

            return { updated: Object.keys(applied) };
        },
        options: {
            description: 'Set setting values',
            notes: `Set setting values for specific keys. Masked credential values ("${MASKED}") read from GET /v1/settings are not accepted: a masked value that matches the stored one is skipped as unchanged, any other value carrying the mask is refused. Send the real credential, or leave the key out to keep the stored value.`,
            tags: ['api', 'Settings'],

            plugins: {
                mcp: {
                    name: 'update_settings',
                    title: 'Update settings',
                    description:
                        'Change instance settings. Send only the keys to change; they take effect immediately on every worker. Covers where webhooks are delivered and which events are sent, notification shaping, the service URL and branding, sync strategy, queue retention and AI processing. Confirm with the user before changing the webhook target or the service URL. The settings that would widen this credential (operator scripts, proxies, secrets, the built-in listeners and their TLS, mail certificate checking, the MCP and audit switches) are not offered.',
                    keep: MCP_SETTINGS_KEYS
                },
                openapi: {
                    responses: apiResponses('Returns the list of setting keys that were updated.', 400, 401, 403, 429, 500)
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

                let stats;
                try {
                    stats = await queueStats(QUEUES_BY_NAME[queue]);
                } catch (countErr) {
                    let err = new Error('Failed to count queue length');
                    err.statusCode = 500;
                    err.cause = countErr;
                    throw err;
                }

                values.jobs = {
                    active: stats.active,
                    delayed: stats.delayed,
                    // Reported for compatibility only - see the response schema below
                    paused: stats.paused,
                    waiting: stats.waiting
                };

                values.paused = stats.isPaused;

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
                mcp: {
                    name: 'get_queue',
                    title: 'Get queue state',
                    description:
                        'Get the state of a job queue: whether it is paused and how many jobs are active, waiting and delayed. `notify` carries webhook deliveries, `submit` carries outbound mail.'
                },
                openapi: {
                    responses: apiResponses('Returns the job counts and paused state for the queue.', 400, 401, 403, 429, 500)
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
                        .meta({ enumDescriptions: ENUM_DESCRIPTIONS.queueId })
                        .label('QueueIdResponse'),
                    jobs: Joi.object({
                        active: Joi.number().integer().example(123).description('Jobs that are currently being processed'),
                        delayed: Joi.number().integer().example(123).description('Jobs that are processed in the future'),
                        paused: Joi.number()
                            .integer()
                            .example(0)
                            .description(
                                'Always 0. BullMQ 6 no longer parks jobs in a separate paused list, so jobs held by a paused queue are counted as waiting. Kept so existing clients still see the key'
                            ),
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

                let queueObj = QUEUES_BY_NAME[queue];

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
                mcp: {
                    name: 'set_queue_state',
                    title: 'Pause or resume a queue',
                    description:
                        'Pause or resume a job queue. Set paused to true to stop the queue from processing jobs (they keep accumulating), false to resume it.'
                },
                openapi: {
                    responses: apiResponses('Returns the queue state after the change.', 400, 401, 403, 429, 500)
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
