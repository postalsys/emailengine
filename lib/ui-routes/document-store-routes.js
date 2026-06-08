'use strict';

// Admin UI routes for the Document Store config pages (/admin/config/document-store*).
// Extracted verbatim from lib/routes-ui.js: Elasticsearch-backed document store settings,
// the chat/embeddings model, pre-processing scripts, field mappings, and the connection
// test. The Document Store (Elasticsearch indexing) is a deprecated feature.

const Joi = require('joi');
const assert = require('assert');
const Boom = require('@hapi/boom');
const { Client: ElasticSearch } = require('@elastic/elasticsearch');

const settings = require('../settings');
const { redis } = require('../db');
const { REDIS_PREFIX } = require('../consts');
const { failAction } = require('../tools');
const { settingsSchema } = require('../schemas');
const { defaultMappings } = require('../es');
const { getESClient } = require('../document-store');
const { getOpenAiModels, OPEN_AI_MODELS, getExampleDocumentsPayloads } = require('./route-helpers');

const FIELD_TYPES = [
    {
        type: 'keyword',
        name: 'Keyword - for exact matches'
    },
    {
        type: 'text',
        name: 'Text - for fulltext search'
    },
    {
        type: 'html',
        name: 'HTML - a text field with HTML analyzer (does not index HTML tags)'
    },
    {
        type: 'filename',
        name: 'File name - a text field with filename analyzer (ngram)'
    },
    {
        type: 'boolean',
        name: 'Boolean'
    },
    {
        type: 'date',
        name: 'Date - date and date-time values'
    },
    {
        type: 'long',
        name: 'Number, long - from -2^63 to 2^63-1'
    },
    {
        type: 'integer',
        name: 'Number, integer - from -2^31 to 2^31-1'
    },
    {
        type: 'short',
        name: 'Number, short - from -32,768 to 32,767'
    },
    {
        type: 'byte',
        name: 'Number, short - from -128 to 127'
    },
    {
        type: 'double',
        name: 'Number, double - a double-precision 64-bit IEEE 754 floating point number'
    }
];

const defaultMappingsList = Object.keys(defaultMappings)
    .map(key => {
        let type = defaultMappings[key].type || (defaultMappings[key].properties ? 'object' : 'text');
        if (defaultMappings[key].analyzer === 'htmlStripAnalyzer') {
            type += ' (HTML)';
        }
        if (defaultMappings[key].analyzer === 'filenameIndex') {
            type += ' (filename)';
        }
        return {
            key,
            type,
            indexed: defaultMappings[key].index !== false
        };
    })
    .sort((a, b) => a.key.toLowerCase().localeCompare(b.key.toLowerCase()));

const configDocumentStoreSchema = {
    documentStoreEnabled: settingsSchema.documentStoreEnabled.default(false),
    documentStoreUrl: settingsSchema.documentStoreUrl.default(''),
    documentStoreIndex: settingsSchema.documentStoreIndex.default('emailengine'),
    documentStoreAuthEnabled: settingsSchema.documentStoreAuthEnabled.default(false),
    documentStoreUsername: settingsSchema.documentStoreUsername.default(''),
    documentStorePassword: settingsSchema.documentStorePassword
};

function init(args) {
    const { server } = args;

    server.route({
        method: 'GET',
        path: '/admin/config/document-store',
        async handler(request, h) {
            let documentStoreEnabled = await settings.get('documentStoreEnabled');
            let documentStoreUrl = await settings.get('documentStoreUrl');
            let documentStoreIndex = (await settings.get('documentStoreIndex')) || 'emailengine';
            let documentStoreGenerateEmbeddings = await settings.get('documentStoreGenerateEmbeddings');
            let documentStoreAuthEnabled = await settings.get('documentStoreAuthEnabled');
            let documentStoreUsername = await settings.get('documentStoreUsername');
            let hasDocumentStorePassword = !!(await settings.get('documentStorePassword'));

            return h.view(
                'config/document-store/index',
                {
                    menuConfig: true,
                    menuConfigDocumentStore: true,
                    documentStoreSettings: true,

                    values: {
                        documentStoreEnabled,
                        documentStoreUrl,
                        documentStoreIndex,
                        documentStoreAuthEnabled,
                        documentStoreUsername,
                        documentStoreGenerateEmbeddings
                    },

                    hasDocumentStorePassword,
                    hasOpenAiAPIKey: !!(await settings.get('openAiAPIKey'))
                },
                {
                    layout: 'app'
                }
            );
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/config/document-store',
        async handler(request, h) {
            try {
                if (!request.payload.documentStoreUrl) {
                    request.payload.documentStoreEnabled = false;
                }

                if (!request.payload.documentStoreUsername) {
                    request.payload.documentStoreAuthEnabled = false;
                    // clear password as well if no username set
                    request.payload.documentStorePassword = '';
                }

                for (let key of Object.keys(request.payload)) {
                    await settings.set(key, request.payload[key]);
                }

                await request.flash({ type: 'info', message: `Configuration updated` });

                return h.redirect('/admin/config/document-store');
            } catch (err) {
                await request.flash({ type: 'danger', message: `Couldn't save settings. Try again.` });
                request.logger.error({ msg: 'Failed to update configuration', err });

                let hasDocumentStorePassword = !!(await settings.get('documentStorePassword'));

                return h.view(
                    'config/document-store/index',
                    {
                        menuConfig: true,
                        menuConfigDocumentStore: true,
                        documentStoreSettings: true,

                        hasDocumentStorePassword,
                        hasOpenAiAPIKey: !!(await settings.get('openAiAPIKey'))
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

                    await request.flash({ type: 'danger', message: `Couldn't save settings. Try again.` });
                    request.logger.error({ msg: 'Failed to update configuration', err });

                    let hasDocumentStorePassword = !!(await settings.get('documentStorePassword'));

                    return h
                        .view(
                            'config/document-store/index',
                            {
                                menuConfig: true,
                                menuConfigDocumentStore: true,
                                documentStoreSettings: true,

                                hasDocumentStorePassword,
                                hasOpenAiAPIKey: !!(await settings.get('openAiAPIKey')),

                                errors
                            },
                            {
                                layout: 'app'
                            }
                        )
                        .takeover();
                },

                payload: Joi.object(configDocumentStoreSchema)
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/admin/config/document-store/chat',
        async handler(request, h) {
            let documentStoreChatModel = await settings.get('documentStoreChatModel');

            return h.view(
                'config/document-store/chat',
                {
                    menuConfig: true,
                    menuConfigDocumentStore: true,
                    documentStoreChat: true,

                    documentStoreEnabled: await settings.get('documentStoreEnabled'),
                    hasOpenAiAPIKey: !!(await settings.get('openAiAPIKey')),
                    indexInfo: await settings.get('embeddings:index'),

                    openAiModels: await getOpenAiModels(OPEN_AI_MODELS, documentStoreChatModel),

                    values: {
                        documentStoreGenerateEmbeddings: (await settings.get(`documentStoreGenerateEmbeddings`)) || false
                    }
                },
                {
                    layout: 'app'
                }
            );
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/config/document-store/chat',
        async handler(request, h) {
            try {
                for (let key of Object.keys(request.payload)) {
                    await settings.set(key, request.payload[key]);
                }

                await request.flash({ type: 'info', message: `Configuration updated` });

                return h.redirect('/admin/config/document-store/chat');
            } catch (err) {
                await request.flash({ type: 'danger', message: `Couldn't save settings. Try again.` });
                request.logger.error({ msg: 'Failed to update configuration', err });

                return h.view(
                    'config/document-store/index',
                    {
                        menuConfig: true,
                        menuConfigDocumentStore: true,
                        documentStoreChat: true,

                        documentStoreEnabled: await settings.get('documentStoreEnabled'),
                        hasOpenAiAPIKey: !!(await settings.get('openAiAPIKey')),
                        indexInfo: await settings.get('embeddings:index'),

                        openAiModels: await getOpenAiModels(OPEN_AI_MODELS, request.payload.documentStoreChatModel)
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

                    await request.flash({ type: 'danger', message: `Couldn't save settings. Try again.` });
                    request.logger.error({ msg: 'Failed to update configuration', err });

                    return h
                        .view(
                            'config/document-store/index',
                            {
                                menuConfig: true,
                                menuConfigDocumentStore: true,
                                documentStoreChat: true,

                                documentStoreEnabled: await settings.get('documentStoreEnabled'),
                                hasOpenAiAPIKey: !!(await settings.get('openAiAPIKey')),
                                indexInfo: await settings.get('embeddings:index'),

                                openAiModels: await getOpenAiModels(OPEN_AI_MODELS, request.payload.documentStoreChatModel),

                                errors
                            },
                            {
                                layout: 'app'
                            }
                        )
                        .takeover();
                },

                payload: Joi.object({
                    documentStoreGenerateEmbeddings: settingsSchema.documentStoreGenerateEmbeddings.default(false),
                    openAiAPIKey: settingsSchema.openAiAPIKey.empty(''),
                    documentStoreChatModel: settingsSchema.documentStoreChatModel.empty('')
                })
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/admin/config/document-store/pre-processing',
        async handler(request, h) {
            return h.view(
                'config/document-store/pre-processing/index',
                {
                    menuConfig: true,
                    menuConfigDocumentStore: true,
                    documentStorePreProcessing: true,

                    values: {
                        enabled: (await settings.get(`documentStorePreProcessingEnabled`)) || false,

                        contentFnJson: JSON.stringify(
                            (await settings.get(`documentStorePreProcessingFn`)) ||
                                `// Pass all emails
return true;`
                        ),
                        contentMapJson: JSON.stringify(
                            (await settings.get(`documentStorePreProcessingMap`)) ||
                                `// By default the output payload is returned unmodified.
return payload;`
                        )
                    },

                    examplePayloadsJson: JSON.stringify(await getExampleDocumentsPayloads()),
                    scriptEnvJson: JSON.stringify((await settings.get('scriptEnv')) || '{}')
                },
                {
                    layout: 'app'
                }
            );
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/config/document-store/pre-processing',
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

            try {
                await settings.setMulti({
                    documentStorePreProcessingEnabled: request.payload.enabled,
                    documentStorePreProcessingFn: contentFn,
                    documentStorePreProcessingMap: contentMap
                });

                await request.flash({ type: 'info', message: `Document Store rules saved` });
                return h.redirect(`/admin/config/document-store/pre-processing`);
            } catch (err) {
                await request.flash({ type: 'danger', message: `Couldn't save Document Store rules. Try again.` });
                request.logger.error({ msg: 'Failed to update Document Store pre-processing rules', err });

                return h.view(
                    'config/document-store/pre-processing/index',
                    {
                        menuConfig: true,
                        menuConfigDocumentStore: true,
                        documentStorePreProcessing: true,

                        errors: err.details,

                        examplePayloadsJson: JSON.stringify(await getExampleDocumentsPayloads()),
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

                    await request.flash({ type: 'danger', message: `Couldn't save Document Store rules. Try again.` });
                    request.logger.error({ msg: 'Failed to update Document Store pre-processing rules', err });

                    return h
                        .view(
                            'config/document-store/pre-processing/index',
                            {
                                menuConfig: true,
                                menuConfigDocumentStore: true,
                                documentStorePreProcessing: true,

                                errors,

                                examplePayloadsJson: JSON.stringify(await getExampleDocumentsPayloads()),
                                scriptEnvJson: JSON.stringify((await settings.get('scriptEnv')) || '{}')
                            },
                            {
                                layout: 'app'
                            }
                        )
                        .takeover();
                },

                payload: Joi.object({
                    enabled: Joi.boolean()
                        .truthy('Y', 'true', '1', 'on')
                        .falsy('N', 'false', 0, '')
                        .default(false)
                        .example(false)
                        .description('Is the pre-processing enabled'),
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
        path: '/admin/config/document-store/mappings',
        async handler(request, h) {
            let customMappings = (await redis.hgetall(`${REDIS_PREFIX}mappings`)) || {};
            const customMappingsList = Object.keys(customMappings)
                .map(key => {
                    let value;
                    try {
                        value = JSON.parse(customMappings[key]);
                    } catch (err) {
                        return null;
                    }

                    let type = value.type || (value.properties ? 'object' : 'text');
                    if (value.analyzer === 'htmlStripAnalyzer') {
                        type += ' (HTML)';
                    }
                    if (value.analyzer === 'filenameIndex') {
                        type += ' (filename)';
                    }
                    return {
                        key,
                        type,
                        indexed: value.index !== false
                    };
                })
                .sort((a, b) => a.key.toLowerCase().localeCompare(b.key.toLowerCase()));
            return h.view(
                'config/document-store/mappings/index',
                {
                    menuConfig: true,
                    menuConfigDocumentStore: true,
                    documentStoreMappings: true,

                    defaultMappingsList,
                    customMappingsList
                },
                {
                    layout: 'app'
                }
            );
        }
    });

    server.route({
        method: 'GET',
        path: '/admin/config/document-store/mappings/new',
        async handler(request, h) {
            return h.view(
                'config/document-store/mappings/new',
                {
                    menuConfig: true,
                    menuConfigDocumentStore: true,
                    documentStoreMappings: true,

                    fieldTypes: FIELD_TYPES.map(entry => ({ type: entry.type, name: entry.name, selected: false })),

                    values: {
                        indexed: true
                    }
                },
                {
                    layout: 'app'
                }
            );
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/config/document-store/mappings/new',
        async handler(request, h) {
            try {
                const { index, client } = await getESClient(request.logger);
                if (!client) {
                    return;
                }

                let mappingEntry = {};
                switch (request.payload.type) {
                    case 'html':
                        mappingEntry[request.payload.field] = {
                            type: 'text',
                            analyzer: 'htmlStripAnalyzer',
                            index: !!request.payload.indexed
                        };
                        break;
                    case 'filename':
                        mappingEntry[request.payload.field] = {
                            type: 'text',
                            analyzer: 'filenameIndex',
                            search_analyzer: 'filenameSearch',
                            index: !!request.payload.indexed
                        };
                        break;
                    default: {
                        mappingEntry[request.payload.field] = {
                            type: request.payload.type,
                            index: !!request.payload.indexed
                        };
                    }
                }

                try {
                    const updateRes = await client.indices.putMapping({ index, properties: mappingEntry });
                    assert(updateRes && updateRes.acknowledged);
                } catch (err) {
                    if (err.meta && err.meta.body && err.meta.body.error && err.meta.body.error.reason) {
                        let error = Boom.boomify(new Error(err.meta.body.error.reason), { statusCode: err.meta.statusCode || 500 });
                        throw error;
                    }
                    throw err;
                }

                await redis.hset(`${REDIS_PREFIX}mappings`, request.payload.field, JSON.stringify(mappingEntry[request.payload.field]));

                await request.flash({ type: 'info', message: `Mapping created` });
                return h.redirect('/admin/config/document-store/mappings');
            } catch (err) {
                if (Boom.isBoom(err)) {
                    await request.flash({ type: 'danger', message: err.message });
                } else {
                    await request.flash({ type: 'danger', message: err.responseText || `Couldn't create mapping. Try again.` });
                }
                request.logger.error({ msg: 'Failed to create mapping', err });

                return h.view(
                    'config/document-store/mappings/new',
                    {
                        menuConfig: true,
                        menuConfigDocumentStore: true,
                        documentStoreMappings: true,

                        fieldTypes: FIELD_TYPES.map(entry => ({ type: entry.type, name: entry.name, selected: request.payload.type === entry.type }))
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

                    await request.flash({ type: 'danger', message: `Couldn't create mapping. Try again.` });
                    request.logger.error({ msg: 'Failed to create mapping', err });

                    return h
                        .view(
                            'config/document-store/mappings/new',
                            {
                                menuConfig: true,
                                menuConfigDocumentStore: true,
                                documentStoreMappings: true,

                                fieldTypes: FIELD_TYPES.map(entry => ({ type: entry.type, name: entry.name, selected: request.payload.type === entry.type })),

                                errors
                            },
                            {
                                layout: 'app'
                            }
                        )
                        .takeover();
                },
                payload: Joi.object({
                    field: Joi.string()
                        .empty('')
                        .trim()
                        .lowercase()
                        .pattern(/^[-_+]|[\\/*?"<>| ,#:]/, { name: 'allowed elasticsearch field', invert: true })
                        .invalid(...Object.keys(defaultMappings))
                        .required()
                        .label('Field name'),
                    type: Joi.string()
                        .empty('')
                        .trim()
                        .valid(...FIELD_TYPES.map(entry => entry.type))
                        .default('text')
                        .label('Field type'),
                    indexed: Joi.boolean().truthy('Y', 'true', '1', 'on').falsy('N', 'false', 0, '')
                })
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/config/document-store/test',
        async handler(request) {
            const { documentStoreUrl, documentStoreAuthEnabled, documentStoreUsername, documentStorePassword } = request.payload;

            let clientConfig = {
                node: { url: new URL(documentStoreUrl), tls: { rejectUnauthorized: false } },
                auth:
                    documentStoreAuthEnabled && documentStoreUsername
                        ? {
                              username: documentStoreUsername,
                              password: documentStorePassword || (await settings.get('documentStorePassword'))
                          }
                        : false
            };

            const client = new ElasticSearch(clientConfig);

            let start = Date.now();
            let duration;
            try {
                let clusterInfo;

                try {
                    clusterInfo = await client.info();
                    duration = Date.now() - start;
                } catch (err) {
                    duration = Date.now() - start;
                    throw err;
                }

                if (!clusterInfo || !clusterInfo.name) {
                    let err = new Error(`Invalid response from server`);
                    throw err;
                }

                return {
                    success: true,
                    duration
                };
            } catch (err) {
                request.logger.error({
                    msg: 'Failed posting request',
                    documentStoreUrl,
                    documentStoreAuthEnabled,
                    documentStoreUsername,
                    command: 'info',
                    err
                });
                return {
                    success: false,
                    duration,
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
                    documentStoreUrl: settingsSchema.documentStoreUrl.required(),
                    documentStoreAuthEnabled: settingsSchema.documentStoreAuthEnabled.default(false),
                    documentStoreUsername: settingsSchema.documentStoreUsername.default(''),
                    documentStorePassword: settingsSchema.documentStorePassword
                })
            }
        }
    });
}

module.exports = init;
