'use strict';

const Joi = require('joi');
const crypto = require('crypto');
const he = require('he');
const { simpleParser } = require('mailparser');
const libmime = require('libmime');

const settings = require('../settings');
const { redis, submitQueue, notifyQueue, documentsQueue } = require('../db');
const getSecret = require('../get-secret');
const { llmPreProcess } = require('../llm-pre-process');
const { locales } = require('../translations');
const consts = require('../consts');
const packageData = require('../../package.json');
const timezonesList = require('timezones-list').default;

const { failAction, getByteSize, formatByteSize, getDuration, readEnvValue, hasEnvValue, retryAgent } = require('../tools');

const { settingsSchema } = require('../schemas');

const { DEFAULT_MAX_LOG_LINES, DEFAULT_DELIVERY_ATTEMPTS, REDIS_PREFIX, NONCE_BYTES, DEFAULT_GMAIL_EXPORT_BATCH_SIZE, DEFAULT_OUTLOOK_EXPORT_BATCH_SIZE } =
    consts;

const { fetch: fetchCmd } = require('undici');

const OPEN_AI_MODELS = [
    { name: 'GPT-3 (instruct)', id: 'gpt-3.5-turbo-instruct' },
    { name: 'GPT-3 (chat)', id: 'gpt-3.5-turbo' },
    { name: 'GPT-4', id: 'gpt-4' }
];

const IMAP_INDEXERS = [
    {
        id: 'full',
        name: 'Full (Default): Builds a comprehensive index that detects new, deleted, and updated emails. This method is slower and uses more storage in Redis.'
    },
    {
        id: 'fast',
        name: 'Fast: Quickly detects newly received emails with minimal storage usage in Redis. It does not detect updated or deleted emails.'
    }
];

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

const ADMIN_ACCESS_ADDRESSES = hasEnvValue('EENGINE_ADMIN_ACCESS_ADDRESSES')
    ? readEnvValue('EENGINE_ADMIN_ACCESS_ADDRESSES')
          .split(',')
          .map(v => v.trim())
          .filter(v => v)
    : null;

const MAX_BODY_SIZE = getByteSize(readEnvValue('EENGINE_MAX_BODY_SIZE')) || consts.DEFAULT_MAX_BODY_SIZE;
const MAX_PAYLOAD_TIMEOUT = getDuration(readEnvValue('EENGINE_MAX_PAYLOAD_TIMEOUT')) || consts.DEFAULT_MAX_PAYLOAD_TIMEOUT;

// Validation schemas
const configWebhooksSchema = {
    webhooksEnabled: Joi.boolean().truthy('Y', 'true', '1', 'on').falsy('N', 'false', 0, '').default(false),
    webhooks: Joi.string()
        .uri({ scheme: ['http', 'https'], allowRelative: false })
        .allow('')
        .example('https://myservice.com/imap/webhooks'),
    notifyAll: Joi.boolean().truthy('Y', 'true', '1', 'on').falsy('N', 'false', 0, '').default(false),
    headersAll: Joi.boolean().truthy('Y', 'true', '1', 'on').falsy('N', 'false', 0, '').default(false),
    notifyHeaders: Joi.string().empty('').trim(),
    notifyText: Joi.boolean().truthy('Y', 'true', '1', 'on').falsy('N', 'false', 0, '').default(false),
    notifyWebSafeHtml: Joi.boolean().truthy('Y', 'true', '1', 'on').falsy('N', 'false', 0, '').default(false),
    notifyTextSize: Joi.alternatives().try(
        Joi.number().empty('').integer().min(0),
        Joi.string().custom((value, helpers) => {
            let nr = getByteSize(value);
            if (typeof nr !== 'number' || nr < 0) {
                return helpers.error('any.invalid');
            }
            return nr;
        }, 'Byte size conversion')
    ),
    notifyCalendarEvents: Joi.boolean().truthy('Y', 'true', '1', 'on').falsy('N', 'false', 0, '').default(false),
    inboxNewOnly: Joi.boolean().truthy('Y', 'true', '1', 'on').falsy('N', 'false', 0, '').default(false),
    notifyAttachments: Joi.boolean().truthy('Y', 'true', '1', 'on').falsy('N', 'false', 0, '').default(false),
    notifyAttachmentSize: Joi.alternatives().try(
        Joi.number().empty('').integer().min(0),
        Joi.string().custom((value, helpers) => {
            let nr = getByteSize(value);
            if (typeof nr !== 'number' || nr < 0) {
                return helpers.error('any.invalid');
            }
            return nr;
        }, 'Byte size conversion')
    ),
    customHeaders: Joi.string()
        .allow('')
        .trim()
        .max(10 * 1024)
};

for (let type of notificationTypes) {
    configWebhooksSchema[`notify_${type.name}`] = Joi.boolean().truthy('Y', 'true', '1', 'on').falsy('N', 'false', 0, '').default(false);
}

const configLoggingSchema = {
    all: Joi.boolean().truthy('Y', 'true', '1', 'on').falsy('N', 'false', 0, '').default(false),
    maxLogLines: Joi.number().integer().empty('').min(0).max(10000000).default(DEFAULT_MAX_LOG_LINES)
};

// Helper functions
async function getOpenAiModels(models, selectedModel) {
    let modelList = (await settings.get('openAiModels')) || structuredClone(models);

    if (selectedModel && !modelList.find(model => model.id === selectedModel)) {
        modelList.unshift({ name: selectedModel, id: selectedModel });
    }

    return modelList.map(model => {
        model.selected = model.id === selectedModel;
        return model;
    });
}

async function getOpenAiError(gt) {
    let openAiErrorData = await redis.get(`${REDIS_PREFIX}:openai:error`);
    if (openAiErrorData) {
        try {
            let { error, time } = JSON.parse(openAiErrorData);
            return { error, time: (gt && gt.dateFns.formatDistance(new Date(time), new Date(), { addSuffix: true })) || time };
        } catch (err) {
            return false;
        }
    }
    return false;
}

async function getExampleDocumentsPayloads() {
    const exampleDocumentsPayloads = require('../payload-examples-documents.json');
    let examples = structuredClone(exampleDocumentsPayloads);
    let serviceUrl = await settings.get('serviceUrl');
    for (let example of examples) {
        if (example.serviceUrl) {
            example.serviceUrl = serviceUrl || example.serviceUrl;
        }
    }
    return examples;
}

function init(args) {
    const { server, call } = args;

    const getDefaultPrompt = async () =>
        await call({
            cmd: 'openAiDefaultPrompt'
        });

    // Webhooks config routes
    server.route({
        method: 'GET',
        path: '/admin/config/webhooks',
        async handler(request, h) {
            const notifyHeaders = (await settings.get('notifyHeaders')) || [];
            const webhookEvents = (await settings.get('webhookEvents')) || [];
            const notifyText = (await settings.get('notifyText')) || false;
            const notifyWebSafeHtml = (await settings.get('notifyWebSafeHtml')) || false;
            const notifyTextSize = Number(await settings.get('notifyTextSize')) || 0;
            const notifyCalendarEvents = (await settings.get('notifyCalendarEvents')) || false;
            const notifyAttachments = (await settings.get('notifyAttachments')) || false;
            const notifyAttachmentSize = Number(await settings.get('notifyAttachmentSize')) || 0;
            const inboxNewOnly = (await settings.get('inboxNewOnly')) || false;
            const customHeaders = (await settings.get('webhooksCustomHeaders')) || [];

            let webhooksEnabled = await settings.get('webhooksEnabled');
            let values = {
                webhooksEnabled: webhooksEnabled !== null ? !!webhooksEnabled : false,
                webhooks: (await settings.get('webhooks')) || '',
                notifyAll: webhookEvents.includes('*'),
                inboxNewOnly,
                headersAll: notifyHeaders.includes('*'),
                notifyHeaders: notifyHeaders
                    .filter(entry => entry !== '*')
                    .map(entry => entry.replace(/^mime|^dkim|-id$|^.|-./gi, c => c.toUpperCase()))
                    .join('\n'),
                notifyText,
                notifyWebSafeHtml,
                notifyTextSize: notifyTextSize ? formatByteSize(notifyTextSize) : '',
                notifyCalendarEvents,
                notifyAttachments,
                notifyAttachmentSize: notifyAttachmentSize ? formatByteSize(notifyAttachmentSize) : '',
                customHeaders: []
                    .concat(customHeaders || [])
                    .map(entry => `${entry.key}: ${entry.value}`.trim())
                    .join('\n')
            };

            return h.view(
                'config/webhooks',
                {
                    pageTitle: 'Webhooks',
                    menuConfig: true,
                    menuConfigWebhooks: true,
                    notificationTypes: notificationTypes.map(type =>
                        Object.assign({}, type, { checked: webhookEvents.includes(type.name), isMessageNew: type.name === 'messageNew' })
                    ),
                    values,
                    webhookErrorFlag: await settings.get('webhookErrorFlag'),
                    documentStoreEnabled: (await settings.get('documentStoreEnabled')) || false
                },
                { layout: 'app' }
            );
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/config/webhooks',
        async handler(request, h) {
            try {
                let customHeaders = request.payload.customHeaders
                    .split(/[\r\n]+/)
                    .map(header => header.trim())
                    .filter(header => header)
                    .map(line => {
                        let sep = line.indexOf(':');
                        if (sep >= 0) {
                            return { key: line.substring(0, sep).trim(), value: line.substring(sep + 1).trim() };
                        }
                        return { key: line, value: '' };
                    });

                const data = {
                    webhooksEnabled: request.payload.webhooksEnabled,
                    webhooks: request.payload.webhooks,
                    notifyText: request.payload.notifyText,
                    notifyWebSafeHtml: request.payload.notifyWebSafeHtml,
                    notifyTextSize: request.payload.notifyTextSize || 0,
                    notifyCalendarEvents: request.payload.notifyCalendarEvents,
                    notifyAttachments: request.payload.notifyAttachments,
                    notifyAttachmentSize: request.payload.notifyAttachmentSize,
                    inboxNewOnly: request.payload.inboxNewOnly,
                    webhookEvents: notificationTypes.filter(type => !!request.payload[`notify_${type.name}`]).map(type => type.name),
                    notifyHeaders: (request.payload.notifyHeaders || '')
                        .split(/\r?\n/)
                        .map(line => line.toLowerCase().trim())
                        .filter(line => line),
                    webhooksCustomHeaders: customHeaders
                };

                if (request.payload.notifyAll) {
                    data.webhookEvents.push('*');
                }

                if (request.payload.headersAll) {
                    data.notifyHeaders.push('*');
                }

                for (let key of Object.keys(data)) {
                    await settings.set(key, data[key]);
                }

                if (!data.webhooksEnabled) {
                    await settings.clear('webhookErrorFlag');
                }

                await request.flash({ type: 'info', message: `Configuration updated` });
                return h.redirect('/admin/config/webhooks');
            } catch (err) {
                await request.flash({ type: 'danger', message: `Couldn't save settings. Try again.` });
                request.logger.error({ msg: 'Failed to update configuration', err });

                return h.view(
                    'config/webhooks',
                    {
                        pageTitle: 'Webhooks',
                        menuConfig: true,
                        menuConfigWebhooks: true,
                        notificationTypes: notificationTypes.map(type =>
                            Object.assign({}, type, { checked: !!request.payload[`notify_${type.name}`], isMessageNew: type.name === 'messageNew' })
                        ),
                        webhookErrorFlag: await settings.get('webhookErrorFlag'),
                        documentStoreEnabled: (await settings.get('documentStoreEnabled')) || false
                    },
                    { layout: 'app' }
                );
            }
        },
        options: {
            validate: {
                options: { stripUnknown: true, abortEarly: false, convert: true },
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
                            'config/webhooks',
                            {
                                pageTitle: 'Webhooks',
                                menuConfig: true,
                                menuConfigWebhooks: true,
                                notificationTypes: notificationTypes.map(type =>
                                    Object.assign({}, type, {
                                        checked: !!request.payload[`notify_${type.name}`],
                                        isMessageNew: type.name === 'messageNew',
                                        error: errors[`notify_${type.name}`]
                                    })
                                ),
                                errors,
                                webhookErrorFlag: await settings.get('webhookErrorFlag'),
                                documentStoreEnabled: (await settings.get('documentStoreEnabled')) || false
                            },
                            { layout: 'app' }
                        )
                        .takeover();
                },
                payload: Joi.object(configWebhooksSchema)
            }
        }
    });

    // Service config routes
    server.route({
        method: 'GET',
        path: '/admin/config/service',
        async handler(request, h) {
            let trackSentMessages = (await settings.get('trackSentMessages')) || false;

            const values = {
                serviceUrl: (await settings.get('serviceUrl')) || null,
                serviceSecret: (await settings.get('serviceSecret')) || null,
                queueKeep: (await settings.get('queueKeep')) || 0,
                deliveryAttempts: await settings.get('deliveryAttempts'),
                imapIndexer: (await settings.get('imapIndexer')) || 'full',
                pageBrandName: (await settings.get('pageBrandName')) || '',
                templateHeader: (await settings.get('templateHeader')) || '',
                templateHtmlHead: (await settings.get('templateHtmlHead')) || '',
                scriptEnv: (await settings.get('scriptEnv')) || '',
                enableTokens: !(await settings.get('disableTokens')),
                enableApiProxy: (await settings.get('enableApiProxy')) || false,
                trackClicks: await settings.get('trackClicks'),
                trackOpens: await settings.get('trackOpens'),
                resolveGmailCategories: (await settings.get('resolveGmailCategories')) || false,
                enableOAuthTokensApi: (await settings.get('enableOAuthTokensApi')) || false,
                ignoreMailCertErrors: (await settings.get('ignoreMailCertErrors')) || false,
                locale: (await settings.get('locale')) || false,
                timezone: (await settings.get('timezone')) || false,
                gmailExportBatchSize: (await settings.get('gmailExportBatchSize')) || DEFAULT_GMAIL_EXPORT_BATCH_SIZE,
                outlookExportBatchSize: (await settings.get('outlookExportBatchSize')) || DEFAULT_OUTLOOK_EXPORT_BATCH_SIZE
            };

            if (typeof values.trackClicks !== 'boolean') {
                values.trackClicks = trackSentMessages;
            }

            if (typeof values.trackOpens !== 'boolean') {
                values.trackOpens = trackSentMessages;
            }

            if (typeof values.deliveryAttempts !== 'number') {
                values.deliveryAttempts = DEFAULT_DELIVERY_ATTEMPTS;
            }

            return h.view(
                'config/service',
                {
                    pageTitle: 'General Settings',
                    menuConfig: true,
                    menuConfigService: true,
                    encryption: await getSecret(),
                    locales: locales.map(locale => Object.assign({ selected: locale.locale === values.locale }, locale)),
                    timezones: timezonesList.map(entry => ({
                        name: entry.label,
                        timezone: entry.tzCode,
                        selected: entry.tzCode === values.timezone
                    })),
                    imapIndexers: structuredClone(IMAP_INDEXERS).map(entry => {
                        if (entry.id === values.imapIndexer) {
                            entry.selected = true;
                        }
                        return entry;
                    }),
                    adminAccessLimit: ADMIN_ACCESS_ADDRESSES && ADMIN_ACCESS_ADDRESSES.length,
                    values
                },
                { layout: 'app' }
            );
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/config/service',
        async handler(request, h) {
            try {
                let data = {
                    serviceSecret: request.payload.serviceSecret,
                    queueKeep: request.payload.queueKeep,
                    pageBrandName: request.payload.pageBrandName,
                    templateHeader: request.payload.templateHeader,
                    templateHtmlHead: request.payload.templateHtmlHead,
                    scriptEnv: request.payload.scriptEnv,
                    disableTokens: !request.payload.enableTokens,
                    enableApiProxy: request.payload.enableApiProxy,
                    trackOpens: request.payload.trackOpens,
                    trackClicks: request.payload.trackClicks,
                    resolveGmailCategories: request.payload.resolveGmailCategories,
                    enableOAuthTokensApi: request.payload.enableOAuthTokensApi,
                    ignoreMailCertErrors: request.payload.ignoreMailCertErrors,
                    locale: request.payload.locale,
                    timezone: request.payload.timezone,
                    deliveryAttempts: request.payload.deliveryAttempts,
                    imapIndexer: request.payload.imapIndexer,
                    gmailExportBatchSize: request.payload.gmailExportBatchSize,
                    outlookExportBatchSize: request.payload.outlookExportBatchSize
                };

                if (request.payload.serviceUrl) {
                    let url = new URL(request.payload.serviceUrl);
                    data.serviceUrl = url.origin;
                }

                for (let key of Object.keys(data)) {
                    await settings.set(key, data[key]);
                }

                await request.flash({ type: 'info', message: `Configuration updated` });
                return h.redirect('/admin/config/service');
            } catch (err) {
                await request.flash({ type: 'danger', message: `Couldn't save settings. Try again.` });
                request.logger.error({ msg: 'Failed to update configuration', err });

                return h.view(
                    'config/service',
                    {
                        pageTitle: 'General Settings',
                        menuConfig: true,
                        menuConfigService: true,
                        locales: locales.map(locale => Object.assign({ selected: locale.locale === request.payload.locale }, locale)),
                        encryption: await getSecret(),
                        timezones: timezonesList.map(entry => ({
                            name: entry.label,
                            timezone: entry.tzCode,
                            selected: entry.tzCode === request.payload.timezone
                        })),
                        imapIndexers: structuredClone(IMAP_INDEXERS).map(entry => {
                            if (entry.id === request.payload.imapIndexer) {
                                entry.selected = true;
                            }
                            return entry;
                        }),
                        adminAccessLimit: ADMIN_ACCESS_ADDRESSES && ADMIN_ACCESS_ADDRESSES.length
                    },
                    { layout: 'app' }
                );
            }
        },
        options: {
            validate: {
                options: { stripUnknown: true, abortEarly: false, convert: true },
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
                            'config/service',
                            {
                                pageTitle: 'General Settings',
                                menuConfig: true,
                                menuConfigService: true,
                                locales: locales.map(locale => Object.assign({ selected: locale.locale === request.payload.locale }, locale)),
                                encryption: await getSecret(),
                                timezones: timezonesList.map(entry => ({
                                    name: entry.label,
                                    timezone: entry.tzCode,
                                    selected: entry.tzCode === request.payload.timezone
                                })),
                                imapIndexers: structuredClone(IMAP_INDEXERS).map(entry => {
                                    if (entry.id === request.payload.imapIndexer) {
                                        entry.selected = true;
                                    }
                                    return entry;
                                }),
                                adminAccessLimit: ADMIN_ACCESS_ADDRESSES && ADMIN_ACCESS_ADDRESSES.length,
                                errors
                            },
                            { layout: 'app' }
                        )
                        .takeover();
                },
                payload: Joi.object({
                    serviceUrl: settingsSchema.serviceUrl,
                    serviceSecret: settingsSchema.serviceSecret,
                    queueKeep: settingsSchema.queueKeep.default(0),
                    deliveryAttempts: settingsSchema.deliveryAttempts.default(DEFAULT_DELIVERY_ATTEMPTS),
                    imapIndexer: settingsSchema.imapIndexer.default('full'),
                    pageBrandName: settingsSchema.pageBrandName.default(''),
                    templateHeader: settingsSchema.templateHeader.default(''),
                    templateHtmlHead: settingsSchema.templateHtmlHead.default(''),
                    scriptEnv: settingsSchema.scriptEnv.default(''),
                    enableApiProxy: settingsSchema.enableApiProxy.default(false),
                    trackOpens: settingsSchema.trackOpens.default(false),
                    trackClicks: settingsSchema.trackClicks.default(false),
                    resolveGmailCategories: settingsSchema.resolveGmailCategories.default(false),
                    ignoreMailCertErrors: settingsSchema.ignoreMailCertErrors.default(false),
                    enableOAuthTokensApi: Joi.boolean().truthy('Y', 'true', '1', 'on').falsy('N', 'false', 0, '').default(false),
                    enableTokens: Joi.boolean().truthy('Y', 'true', '1', 'on').falsy('N', 'false', 0, '').default(false),
                    locale: settingsSchema.locale
                        .empty('')
                        .valid(...locales.map(locale => locale.locale))
                        .default('en'),
                    timezone: settingsSchema.timezone.empty(''),
                    gmailExportBatchSize: settingsSchema.gmailExportBatchSize.default(DEFAULT_GMAIL_EXPORT_BATCH_SIZE),
                    outlookExportBatchSize: settingsSchema.outlookExportBatchSize.default(DEFAULT_OUTLOOK_EXPORT_BATCH_SIZE)
                })
            }
        }
    });

    // Service preview route
    server.route({
        method: 'POST',
        path: '/admin/config/service/preview',
        async handler(request, h) {
            return h.view(
                'config/service-preview',
                {
                    pageBrandName: request.payload.pageBrandName,
                    embeddedTemplateHeader: request.payload.templateHeader,
                    embeddedTemplateHtmlHead: request.payload.templateHtmlHead
                },
                { layout: 'public' }
            );
        },
        options: {
            validate: {
                options: { stripUnknown: true, abortEarly: false, convert: true },
                async failAction(request, h, err) {
                    request.logger.error({ msg: 'Failed to process preview', err });
                    return h.redirect('/admin').takeover();
                },
                payload: Joi.object({
                    pageBrandName: settingsSchema.pageBrandName.default(''),
                    templateHeader: settingsSchema.templateHeader.default(''),
                    templateHtmlHead: settingsSchema.templateHtmlHead.default('')
                })
            }
        }
    });

    // Clear error route
    server.route({
        method: 'POST',
        path: '/admin/config/clear-error',
        async handler(request) {
            switch (request.payload.alert) {
                case 'open-ai':
                    await redis.del(`${REDIS_PREFIX}:openai:error`);
                    break;
                case 'webhook-default':
                    await settings.clear('webhookErrorFlag');
                    break;
                case 'webhook-route':
                    if (request.payload.entry) {
                        await redis.hdel(`${REDIS_PREFIX}wh:c`, `${request.payload.entry}:webhookErrorFlag`);
                    }
                    break;
            }
            return { success: true };
        },
        options: {
            validate: {
                options: { stripUnknown: true, abortEarly: false, convert: true },
                failAction,
                payload: Joi.object({
                    alert: Joi.string().required().max(1024),
                    entry: Joi.string().empty('').max(1024).trim()
                })
            }
        }
    });

    // Service clean route
    server.route({
        method: 'POST',
        path: '/admin/config/service/clean',
        async handler(request) {
            let errors = [];
            for (let queue of [submitQueue, notifyQueue, documentsQueue]) {
                for (let type of ['failed', 'completed']) {
                    try {
                        await queue.clean(1000, 100000, type);
                        request.logger.trace({ msg: 'Queue cleaned', queue: queue.name, type });
                    } catch (err) {
                        request.logger.error({ msg: 'Failed to clean queue', queue: queue.name, type, err });
                        errors.push(err.message);
                    }
                }
            }

            if (errors.length) {
                return { success: false, error: 'Cleaning failed for some queues' };
            }
            return { success: true };
        },
        options: {
            validate: {
                options: { stripUnknown: true, abortEarly: false, convert: true }
            }
        }
    });

    // Logging config routes
    server.route({
        method: 'GET',
        path: '/admin/config/logging',
        async handler(request, h) {
            let values = (await settings.get('logs')) || {};
            if (typeof values.maxLogLines === 'undefined') {
                values.maxLogLines = DEFAULT_MAX_LOG_LINES;
            }
            values.accounts = [].concat(values.accounts || []).join('\n');

            return h.view(
                'config/logging',
                {
                    pageTitle: 'Logging',
                    menuConfig: true,
                    menuConfigLogging: true,
                    values
                },
                { layout: 'app' }
            );
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/config/logging',
        async handler(request, h) {
            try {
                const data = {
                    logs: {
                        all: !!request.payload.all,
                        maxLogLines: request.payload.maxLogLines || 0
                    }
                };

                for (let key of Object.keys(data)) {
                    await settings.set(key, data[key]);
                }

                await request.flash({ type: 'info', message: `Configuration updated` });
                return h.redirect('/admin/config/logging');
            } catch (err) {
                await request.flash({ type: 'danger', message: `Couldn't save settings. Try again.` });
                request.logger.error({ msg: 'Failed to update configuration', err });

                return h.view(
                    'config/logging',
                    {
                        pageTitle: 'Logging',
                        menuConfig: true,
                        menuConfigWebhooks: true
                    },
                    { layout: 'app' }
                );
            }
        },
        options: {
            validate: {
                options: { stripUnknown: true, abortEarly: false, convert: true },
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
                            'config/logging',
                            {
                                pageTitle: 'Logging',
                                menuConfig: true,
                                menuConfigWebhooks: true,
                                errors
                            },
                            { layout: 'app' }
                        )
                        .takeover();
                },
                payload: Joi.object(configLoggingSchema)
            }
        }
    });

    // Logging reconnect route
    server.route({
        method: 'POST',
        path: '/admin/config/logging/reconnect',
        async handler(request) {
            try {
                let requested = 0;
                for (let account of request.payload.accounts) {
                    request.logger.info({ msg: 'Request reconnect for logging', account });
                    try {
                        await call({ cmd: 'update', account });
                        requested++;
                    } catch (err) {
                        request.logger.error({ msg: 'Reconnect request failed', action: 'request_reconnect', account, err });
                    }
                }

                return { success: true, accounts: requested };
            } catch (err) {
                request.logger.error({ msg: 'Failed to request reconnect', err, accounts: request.payload.accounts });
                return { success: false, error: err.message };
            }
        },
        options: {
            validate: {
                options: { stripUnknown: true, abortEarly: false, convert: true },
                failAction,
                payload: Joi.object({
                    accounts: Joi.array().items(Joi.string().max(256)).default([]).label('LoggedAccounts')
                })
            }
        }
    });

    // Webhooks test route
    server.route({
        method: 'POST',
        path: '/admin/config/webhooks/test',
        async handler(request) {
            let headers = {
                'Content-Type': 'application/json',
                'User-Agent': `${packageData.name}/${packageData.version} (+${packageData.homepage})`
            };

            const webhooks = request.payload.webhooks;
            if (!webhooks) {
                return { success: false, target: webhooks, error: 'Webhook URL is not set' };
            }

            let parsed = new URL(webhooks);
            let username, password;

            if (parsed.username) {
                username = he.decode(parsed.username);
                parsed.username = '';
            }

            if (parsed.password) {
                password = he.decode(parsed.password);
                parsed.password = '';
            }

            if (username || password) {
                headers.Authorization = `Basic ${Buffer.from(he.encode(username || '') + ':' + he.encode(password || '')).toString('base64')}`;
            }

            let customHeaders = request.payload.customHeaders
                .split(/[\r\n]+/)
                .map(header => header.trim())
                .filter(header => header)
                .map(line => {
                    let sep = line.indexOf(':');
                    if (sep >= 0) {
                        return { key: line.substring(0, sep).trim(), value: line.substring(sep + 1).trim() };
                    }
                    return { key: line, value: '' };
                });

            customHeaders.forEach(header => {
                headers[header.key] = header.value;
            });

            let start = Date.now();
            let duration;
            try {
                let res;
                let serviceUrl = await settings.get('serviceUrl');

                try {
                    res = await fetchCmd(parsed.toString(), {
                        method: 'post',
                        body:
                            request.payload.payload ||
                            JSON.stringify({
                                serviceUrl,
                                account: null,
                                date: new Date().toISOString(),
                                event: 'test',
                                data: { nonce: crypto.randomBytes(NONCE_BYTES).toString('base64url') }
                            }),
                        headers,
                        dispatcher: retryAgent
                    });
                    duration = Date.now() - start;
                } catch (err) {
                    duration = Date.now() - start;
                    throw err.cause || err;
                }

                if (!res.ok) {
                    let err = new Error(res.statusText || `Invalid response: ${res.status} ${res.statusText}`);
                    err.statusCode = res.status;
                    throw err;
                }

                return { success: true, target: webhooks, duration };
            } catch (err) {
                request.logger.error({ msg: 'Failed posting webhook', webhooks, event: 'test', err });
                return { success: false, target: webhooks, duration, error: err.message, code: err.code };
            }
        },
        options: {
            tags: ['test'],
            validate: {
                options: { stripUnknown: true, abortEarly: false, convert: true },
                failAction,
                payload: Joi.object({
                    webhooks: Joi.string()
                        .uri({ scheme: ['http', 'https'], allowRelative: false })
                        .allow(''),
                    customHeaders: Joi.string()
                        .allow('')
                        .trim()
                        .max(10 * 1024)
                        .default(''),
                    payload: Joi.string()
                        .max(1024 * 1024)
                        .empty('')
                        .trim()
                })
            }
        }
    });

    // AI config routes
    server.route({
        method: 'GET',
        path: '/admin/config/ai',
        async handler(request, h) {
            const errorLog = ((await llmPreProcess.getErrorLog()) || []).map(entry => {
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

            const values = {
                generateEmailSummary: (await settings.get('generateEmailSummary')) || false,
                openAiPrompt: ((await settings.get('openAiPrompt')) || '').toString(),
                contentFnJson: JSON.stringify(
                    ((await settings.get(`openAiPreProcessingFn`)) || '').toString() ||
                        `// Pass all emails
return true;`
                ),
                openAiAPIUrl: ((await settings.get('openAiAPIUrl')) || '').toString(),
                openAiTemperature: ((await settings.get('openAiTemperature')) || '').toString(),
                openAiTopP: ((await settings.get('openAiTopP')) || '').toString(),
                openAiMaxTokens: ((await settings.get('openAiMaxTokens')) || '').toString()
            };

            if (!values.openAiPrompt.trim()) {
                values.openAiPrompt = await getDefaultPrompt();
            }

            let hasOpenAiAPIKey = !!(await settings.get('openAiAPIKey'));
            let openAiModel = await settings.get('openAiModel');
            let openAiError = await getOpenAiError(request.app.gt);

            return h.view(
                'config/ai',
                {
                    pageTitle: 'AI Processing',
                    menuConfig: true,
                    menuConfigAi: true,
                    errorLog,
                    defaultPromptJson: JSON.stringify({ prompt: await getDefaultPrompt() }),
                    values,
                    hasOpenAiAPIKey,
                    openAiError,
                    openAiModels: await getOpenAiModels(OPEN_AI_MODELS, openAiModel),
                    scriptEnvJson: JSON.stringify((await settings.get('scriptEnv')) || '{}'),
                    examplePayloadsJson: JSON.stringify(
                        (await getExampleDocumentsPayloads()).map(entry =>
                            Object.assign({}, entry, { summary: undefined, riskAssessment: undefined, preview: undefined })
                        )
                    )
                },
                { layout: 'app' }
            );
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/config/ai',
        async handler(request, h) {
            try {
                let contentFn;
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
                    err.details = { contentFnJson: 'Invalid JSON' };
                    throw err;
                }

                let data = {
                    generateEmailSummary: request.payload.generateEmailSummary,
                    openAiModel: request.payload.openAiModel,
                    openAiAPIUrl: request.payload.openAiAPIUrl,
                    openAiPrompt: (request.payload.openAiPrompt || '').toString(),
                    openAiPreProcessingFn: contentFn,
                    openAiTemperature: request.payload.openAiTemperature,
                    openAiTopP: request.payload.openAiTopP,
                    openAiMaxTokens: request.payload.openAiMaxTokens
                };

                let defaultUserPrompt = await getDefaultPrompt();
                if (!data.openAiPrompt.trim() || data.openAiPrompt.trim() === defaultUserPrompt.trim()) {
                    data.openAiPrompt = '';
                }

                if (typeof request.payload.openAiAPIKey === 'string') {
                    data.openAiAPIKey = request.payload.openAiAPIKey;
                }

                if (typeof request.payload.openAiAPIUrl === 'string') {
                    data.openAiAPIUrl = request.payload.openAiAPIUrl;
                }

                for (let key of Object.keys(data)) {
                    await settings.set(key, data[key]);
                }

                await request.flash({ type: 'info', message: `Configuration updated` });
                return h.redirect('/admin/config/ai');
            } catch (err) {
                await request.flash({ type: 'danger', message: `Couldn't save settings. Try again.` });
                request.logger.error({ msg: 'Failed to update configuration', err });

                let hasOpenAiAPIKey = !!(await settings.get('openAiAPIKey'));
                let openAiError = await getOpenAiError(request.app.gt);

                const errorLog = ((await llmPreProcess.getErrorLog()) || []).map(entry => {
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
                    'config/ai',
                    {
                        pageTitle: 'AI Processing',
                        menuConfig: true,
                        menuConfigAi: true,
                        errorLog,
                        defaultPromptJson: JSON.stringify({ prompt: await getDefaultPrompt() }),
                        hasOpenAiAPIKey,
                        openAiError,
                        openAiModels: await getOpenAiModels(OPEN_AI_MODELS, request.payload.openAiModel),
                        scriptEnvJson: JSON.stringify((await settings.get('scriptEnv')) || '{}'),
                        examplePayloadsJson: JSON.stringify(
                            (await getExampleDocumentsPayloads()).map(entry =>
                                Object.assign({}, entry, { summary: undefined, riskAssessment: undefined, preview: undefined })
                            )
                        )
                    },
                    { layout: 'app' }
                );
            }
        },
        options: {
            validate: {
                options: { stripUnknown: true, abortEarly: false, convert: true },
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

                    let hasOpenAiAPIKey = !!(await settings.get('openAiAPIKey'));
                    let openAiError = await getOpenAiError(request.app.gt);

                    const errorLog = ((await llmPreProcess.getErrorLog()) || []).map(entry => {
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

                    return h
                        .view(
                            'config/ai',
                            {
                                pageTitle: 'AI Processing',
                                menuConfig: true,
                                menuConfigAi: true,
                                errorLog,
                                defaultPromptJson: JSON.stringify({ prompt: await getDefaultPrompt() }),
                                hasOpenAiAPIKey,
                                openAiError,
                                openAiModels: await getOpenAiModels(OPEN_AI_MODELS, request.payload.openAiModel),
                                scriptEnvJson: JSON.stringify((await settings.get('scriptEnv')) || '{}'),
                                examplePayloadsJson: JSON.stringify(
                                    (await getExampleDocumentsPayloads()).map(entry =>
                                        Object.assign({}, entry, { summary: undefined, riskAssessment: undefined, preview: undefined })
                                    )
                                ),
                                errors
                            },
                            { layout: 'app' }
                        )
                        .takeover();
                },
                payload: Joi.object({
                    generateEmailSummary: settingsSchema.generateEmailSummary.default(false),
                    openAiAPIKey: settingsSchema.openAiAPIKey.empty(''),
                    openAiModel: settingsSchema.openAiModel.empty(''),
                    openAiAPIUrl: settingsSchema.openAiAPIUrl.default(''),
                    openAiPrompt: settingsSchema.openAiPrompt.default(''),
                    contentFnJson: Joi.string()
                        .max(1024 * 1024)
                        .default('')
                        .allow('')
                        .trim(),
                    openAiTemperature: settingsSchema.openAiTemperature.default(''),
                    openAiTopP: settingsSchema.openAiTopP.default(''),
                    openAiMaxTokens: settingsSchema.openAiMaxTokens.default('')
                })
            }
        }
    });

    // AI test prompt route
    server.route({
        method: 'POST',
        path: '/admin/config/ai/test-prompt',
        async handler(request) {
            try {
                request.logger.info({ msg: 'Prompt test' });

                const parsed = await simpleParser(Buffer.from(request.payload.emailFile, 'base64'));

                const response = {};
                response.summary = await call({
                    cmd: 'generateSummary',
                    data: {
                        message: {
                            headers: parsed.headerLines.map(header => libmime.decodeHeader(header.line)),
                            attachments: parsed.attachments,
                            html: parsed.html,
                            text: parsed.text
                        },
                        openAiAPIKey: request.payload.openAiAPIKey,
                        openAiModel: request.payload.openAiModel,
                        openAiAPIUrl: request.payload.openAiAPIUrl,
                        openAiPrompt: request.payload.openAiPrompt,
                        openAiTemperature: request.payload.openAiTemperature,
                        openAiTopP: request.payload.openAiTopP,
                        openAiMaxTokens: request.payload.openAiMaxTokens
                    },
                    timeout: 2 * 60 * 1000
                });

                for (let key of Object.keys(response.summary)) {
                    if (key.charAt(0) === '_' || response.summary[key] === '') {
                        delete response.summary[key];
                    }
                    if (key === 'riskAssessment') {
                        response.riskAssessment = response.summary.riskAssessment;
                        delete response.summary.riskAssessment;
                    }
                }

                return { success: true, response };
            } catch (err) {
                request.logger.error({ msg: 'Failed to test prompt', err });
                return { success: false, error: err.message };
            }
        },
        options: {
            payload: { maxBytes: MAX_BODY_SIZE, timeout: MAX_PAYLOAD_TIMEOUT },
            validate: {
                options: { stripUnknown: true, abortEarly: false, convert: true },
                failAction,
                payload: Joi.object({
                    emailFile: Joi.string().base64({ paddingRequired: false }).required(),
                    openAiAPIKey: settingsSchema.openAiAPIKey.empty(''),
                    openAiModel: settingsSchema.openAiModel.empty(''),
                    openAiAPIUrl: settingsSchema.openAiAPIUrl.default(''),
                    openAiPrompt: settingsSchema.openAiPrompt.default(''),
                    openAiTemperature: settingsSchema.openAiTemperature.empty(''),
                    openAiTopP: settingsSchema.openAiTopP.empty(''),
                    openAiMaxTokens: settingsSchema.openAiMaxTokens.empty('')
                })
            }
        }
    });

    // AI reload models route
    server.route({
        method: 'POST',
        path: '/admin/config/ai/reload-models',
        async handler(request) {
            try {
                request.logger.info({ msg: 'Reload models' });

                const { models } = await call({
                    cmd: 'openAiListModels',
                    data: {
                        openAiAPIKey: request.payload.openAiAPIKey,
                        openAiAPIUrl: request.payload.openAiAPIUrl
                    },
                    timeout: 2 * 60 * 1000
                });

                if (models && models.length) {
                    await settings.set('openAiModels', models);
                }

                return { success: true, models };
            } catch (err) {
                request.logger.error({ msg: 'Failed reloading OpenAI models', err });
                return { success: false, error: err.message };
            }
        },
        options: {
            validate: {
                options: { stripUnknown: true, abortEarly: false, convert: true },
                failAction,
                payload: Joi.object({
                    openAiAPIKey: settingsSchema.openAiAPIKey.empty(''),
                    openAiAPIUrl: settingsSchema.openAiAPIUrl.default('')
                })
            }
        }
    });

    // Browser config route
    server.route({
        method: 'POST',
        path: '/admin/config/browser',
        async handler(request) {
            for (let key of ['serviceUrl', 'language', 'timezone']) {
                if (request.payload[key]) {
                    let existingValue = await settings.get(key);
                    if (existingValue === null) {
                        await settings.set(key, request.payload[key]);
                    }
                }
            }
            return { success: true };
        },
        options: {
            validate: {
                options: { stripUnknown: true, abortEarly: false, convert: true },
                failAction,
                payload: Joi.object({
                    serviceUrl: settingsSchema.serviceUrl.empty('').allow(false),
                    language: Joi.string()
                        .empty('')
                        .lowercase()
                        .regex(/^[a-z0-9]{1,5}([-_][a-z0-9]{1,15})?$/)
                        .allow(false),
                    timezone: Joi.string().empty('').allow(false).max(255)
                })
            }
        }
    });
}

module.exports = init;
