'use strict';

// Admin UI routes for the remaining /admin/config/* pages: webhooks, service URL/branding,
// AI (OpenAI) settings, logging, and license. Extracted verbatim from lib/routes-ui.js.
// The notificationTypes / configWebhooksSchema / configLoggingSchema consts, the
// getOpenAiError helper, and the getDefaultPrompt helper move with the routes (only these
// config pages use them).

const Joi = require('joi');
const crypto = require('crypto');
const config = require('@zone-eu/wild-config');
const libmime = require('libmime');
const he = require('he');
const os = require('os');
const packageData = require('../../package.json');
const { simpleParser } = require('mailparser');
const { fetch: fetchCmd } = require('undici');

const settings = require('../settings');
const consts = require('../consts');
const getSecret = require('../get-secret');
const timezonesList = require('timezones-list').default;
const { redis, submitQueue, notifyQueue, documentsQueue } = require('../db');
const { getByteSize, formatByteSize, getDuration, failAction, hasEnvValue, readEnvValue, httpAgent } = require('../tools');
const { llmPreProcess } = require('../llm-pre-process');
const { documentStoreFeatureEnabled } = require('../document-store');
const { locales } = require('../translations');
const { settingsSchema } = require('../schemas');
const { getOpenAiModels, OPEN_AI_MODELS, getExampleDocumentsPayloads } = require('./route-helpers');
const { registerSettingsPage } = require('./settings-page');

const {
    REDIS_PREFIX,
    DEFAULT_MAX_LOG_LINES,
    DEFAULT_DELIVERY_ATTEMPTS,
    DEFAULT_MAX_BODY_SIZE,
    DEFAULT_MAX_PAYLOAD_TIMEOUT,
    NONCE_BYTES,
    DEFAULT_GMAIL_EXPORT_BATCH_SIZE,
    DEFAULT_OUTLOOK_EXPORT_BATCH_SIZE
} = consts;

const LICENSE_HOST = 'https://postalsys.com';

config.api = config.api || {
    port: 3000,
    host: '127.0.0.1',
    proxy: false
};

const MAX_BODY_SIZE = getByteSize(readEnvValue('EENGINE_MAX_BODY_SIZE') || config.api.maxBodySize) || DEFAULT_MAX_BODY_SIZE;
const MAX_PAYLOAD_TIMEOUT = getDuration(readEnvValue('EENGINE_MAX_PAYLOAD_TIMEOUT') || config.api.maxPayloadTimeout) || DEFAULT_MAX_PAYLOAD_TIMEOUT;

const ADMIN_ACCESS_ADDRESSES = hasEnvValue('EENGINE_ADMIN_ACCESS_ADDRESSES')
    ? readEnvValue('EENGINE_ADMIN_ACCESS_ADDRESSES')
          .split(',')
          .map(v => v.trim())
          .filter(v => v)
    : null;

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

const configWebhooksSchema = {
    webhooksEnabled: Joi.boolean().truthy('Y', 'true', '1', 'on').falsy('N', 'false', 0, '').default(false).description('Enable Webhooks'),
    webhooks: Joi.string()
        .uri({
            scheme: ['http', 'https'],
            allowRelative: false
        })
        .allow('')
        .example('https://myservice.com/imap/webhooks')
        .description('Webhook URL'),
    notifyAll: Joi.boolean().truthy('Y', 'true', '1', 'on').falsy('N', 'false', 0, '').default(false),
    headersAll: Joi.boolean().truthy('Y', 'true', '1', 'on').falsy('N', 'false', 0, '').default(false),
    notifyHeaders: Joi.string().empty('').trim(),
    notifyText: Joi.boolean().truthy('Y', 'true', '1', 'on').falsy('N', 'false', 0, '').default(false),
    notifyWebSafeHtml: Joi.boolean().truthy('Y', 'true', '1', 'on').falsy('N', 'false', 0, '').default(false),

    notifyTextSize: Joi.alternatives().try(
        Joi.number().empty('').integer().min(0),
        // If it's a string, parse and convert it to bytes
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
        // If it's a string, parse and convert it to bytes
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
        .description('Custom request headers'),

    scriptEnv: settingsSchema.scriptEnv.default('')
};

for (let type of notificationTypes) {
    configWebhooksSchema[`notify_${type.name}`] = Joi.boolean().truthy('Y', 'true', '1', 'on').falsy('N', 'false', 0, '').default(false);
}

const configLoggingSchema = {
    all: Joi.boolean().truthy('Y', 'true', '1', 'on').falsy('N', 'false', 0, '').default(false).description('Enable logs for all accounts'),
    maxLogLines: Joi.number().integer().empty('').min(0).max(10000000).default(DEFAULT_MAX_LOG_LINES),
    sentryEnabled: settingsSchema.sentryEnabled.default(false),
    sentryDsn: settingsSchema.sentryDsn.default('')
};

async function getAiErrorLog() {
    return ((await llmPreProcess.getErrorLog()) || []).map(entry => {
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
}

async function getOpenAiError(gt) {
    let openAiError = await redis.get(`${REDIS_PREFIX}:openai:error`);
    if (openAiError) {
        try {
            openAiError = JSON.parse(openAiError);
            switch (openAiError.code) {
                case 'invalid_api_key':
                    openAiError.message = gt.gettext('Invalid API key for OpenAI');
                    break;
            }
        } catch (err) {
            openAiError = null;
        }
    }
    return openAiError;
}

function init(args) {
    const { server, call } = args;

    const getDefaultPrompt = async () =>
        await call({
            cmd: 'openAiDefaultPrompt'
        });

    registerSettingsPage(server, {
        path: '/admin/config/webhooks',
        view: 'config/webhooks',
        pageTitle: 'Webhooks',
        menuKey: 'menuConfigWebhooks',
        schema: configWebhooksSchema,

        async loadValues() {
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
                    .join('\n'),

                scriptEnv: (await settings.get('scriptEnv')) || ''
            };

            // per-event checkbox states under their form field names, so the GET render
            // and the error re-renders (which see the raw payload) share one shape
            for (let type of notificationTypes) {
                values[`notify_${type.name}`] = webhookEvents.includes(type.name);
            }

            return values;
        },

        async viewContext(request, values) {
            return {
                notificationTypes: notificationTypes.map(type =>
                    Object.assign({}, type, { checked: !!values[`notify_${type.name}`], isMessageNew: type.name === 'messageNew' })
                ),

                webhookErrorFlag: await settings.get('webhookErrorFlag'),
                documentStoreEnabled: (documentStoreFeatureEnabled && (await settings.get('documentStoreEnabled'))) || false
            };
        },

        async applySettings(request) {
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

                scriptEnv: request.payload.scriptEnv,

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

            await settings.setMulti(data);

            if (!data.webhooksEnabled) {
                // clear error message (if exists)
                await settings.clear('webhookErrorFlag');
            }
        }
    });

    registerSettingsPage(server, {
        path: '/admin/config/service',
        view: 'config/service',
        pageTitle: 'General',
        menuKey: 'menuConfigService',
        schema: {
            serviceUrl: settingsSchema.serviceUrl,
            queueKeep: settingsSchema.queueKeep.default(0),
            enableApiProxy: settingsSchema.enableApiProxy.default(false),

            locale: settingsSchema.locale
                .empty('')
                .valid(...locales.map(locale => locale.locale))
                .default('en'),

            timezone: settingsSchema.timezone.empty('')
        },

        async loadValues() {
            const storedValues = await settings.getMulti('serviceUrl', 'queueKeep', 'enableApiProxy', 'locale', 'timezone');

            return {
                serviceUrl: storedValues.serviceUrl || null,
                queueKeep: storedValues.queueKeep || 0,
                enableApiProxy: storedValues.enableApiProxy || false,

                locale: storedValues.locale || false,
                timezone: storedValues.timezone || false
            };
        },

        async viewContext(request, values) {
            return {
                locales: locales.map(locale => Object.assign({ selected: locale.locale === values.locale }, locale)),

                timezones: timezonesList.map(entry => ({
                    name: entry.label,
                    timezone: entry.tzCode,
                    selected: entry.tzCode === values.timezone
                }))
            };
        },

        async applySettings(request) {
            let data = {
                queueKeep: request.payload.queueKeep,
                enableApiProxy: request.payload.enableApiProxy,
                locale: request.payload.locale,
                timezone: request.payload.timezone
            };

            if (request.payload.serviceUrl) {
                let url = new URL(request.payload.serviceUrl);
                data.serviceUrl = url.origin;
            }

            await settings.setMulti(data);
        }
    });

    registerSettingsPage(server, {
        path: '/admin/config/security',
        view: 'config/security',
        pageTitle: 'Security',
        menuKey: 'menuConfigSecurity',
        schema: {
            serviceSecret: settingsSchema.serviceSecret,
            ignoreMailCertErrors: settingsSchema.ignoreMailCertErrors.default(false),

            // Following options can only be changed via the UI
            enableOAuthTokensApi: Joi.boolean()
                .truthy('Y', 'true', '1', 'on')
                .falsy('N', 'false', 0, '')
                .description('If true, then allow using using the OAuth tokens API endpoint')
                .default(false),
            enableTokens: Joi.boolean().truthy('Y', 'true', '1', 'on').falsy('N', 'false', 0, '').default(false)
        },

        async loadValues() {
            const storedValues = await settings.getMulti('serviceSecret', 'disableTokens', 'enableOAuthTokensApi', 'ignoreMailCertErrors');

            return {
                serviceSecret: storedValues.serviceSecret || null,
                enableTokens: !storedValues.disableTokens,
                enableOAuthTokensApi: storedValues.enableOAuthTokensApi || false,
                ignoreMailCertErrors: storedValues.ignoreMailCertErrors || false
            };
        },

        async viewContext() {
            return {
                encryption: await getSecret(),
                adminAccessLimit: ADMIN_ACCESS_ADDRESSES && ADMIN_ACCESS_ADDRESSES.length
            };
        },

        async applySettings(request) {
            let data = {
                disableTokens: !request.payload.enableTokens,
                enableOAuthTokensApi: request.payload.enableOAuthTokensApi,
                ignoreMailCertErrors: request.payload.ignoreMailCertErrors
            };

            // Only overwrite the service secret when a non-empty value is provided: an empty
            // stored secret would break HMAC signing/verification for every hosted-form/tracking
            // link, so a blank field means "keep the current secret", never "clear it". Tell the
            // admin the field was ignored - silently dropping it would make the success flash
            // read as if a clear-to-rotate took effect.
            if (request.payload.serviceSecret) {
                data.serviceSecret = request.payload.serviceSecret;
            } else if (await settings.get('serviceSecret')) {
                await request.flash({ type: 'warning', message: `Service secret was left unchanged - type a new value to rotate it` });
            }

            await settings.setMulti(data);
        }
    });

    registerSettingsPage(server, {
        path: '/admin/config/email-processing',
        view: 'config/email-processing',
        pageTitle: 'Email Processing',
        menuKey: 'menuConfigEmailProcessing',
        schema: {
            deliveryAttempts: settingsSchema.deliveryAttempts.default(DEFAULT_DELIVERY_ATTEMPTS),
            imapIndexer: settingsSchema.imapIndexer.default('full'),
            trackOpens: settingsSchema.trackOpens.default(false),
            trackClicks: settingsSchema.trackClicks.default(false),
            resolveGmailCategories: settingsSchema.resolveGmailCategories.default(false),
            gmailExportBatchSize: settingsSchema.gmailExportBatchSize.empty('').default(DEFAULT_GMAIL_EXPORT_BATCH_SIZE),
            outlookExportBatchSize: settingsSchema.outlookExportBatchSize.empty('').default(DEFAULT_OUTLOOK_EXPORT_BATCH_SIZE)
        },

        async loadValues() {
            const storedValues = await settings.getMulti(
                'trackSentMessages',
                'serviceUrl',
                'deliveryAttempts',
                'imapIndexer',
                'trackClicks',
                'trackOpens',
                'resolveGmailCategories',
                'gmailExportBatchSize',
                'outlookExportBatchSize'
            );

            let trackSentMessages = storedValues.trackSentMessages || false;

            const values = {
                serviceUrl: storedValues.serviceUrl || null,
                deliveryAttempts: storedValues.deliveryAttempts,

                imapIndexer: storedValues.imapIndexer || 'full',

                trackClicks: storedValues.trackClicks,
                trackOpens: storedValues.trackOpens,

                resolveGmailCategories: storedValues.resolveGmailCategories || false,

                gmailExportBatchSize: storedValues.gmailExportBatchSize || DEFAULT_GMAIL_EXPORT_BATCH_SIZE,
                outlookExportBatchSize: storedValues.outlookExportBatchSize || DEFAULT_OUTLOOK_EXPORT_BATCH_SIZE
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

            return values;
        },

        // the tracking-card footer links to the service URL, which is not a form field
        async errorValues(request) {
            return Object.assign({}, request.payload, {
                serviceUrl: (await settings.get('serviceUrl')) || null
            });
        },

        async viewContext(request, values) {
            return {
                imapIndexers: structuredClone(IMAP_INDEXERS).map(entry => {
                    if (entry.id === values.imapIndexer) {
                        entry.selected = true;
                    }
                    return entry;
                })
            };
        },

        async applySettings(request) {
            await settings.setMulti({
                deliveryAttempts: request.payload.deliveryAttempts,
                imapIndexer: request.payload.imapIndexer,
                trackOpens: request.payload.trackOpens,
                trackClicks: request.payload.trackClicks,
                resolveGmailCategories: request.payload.resolveGmailCategories,
                gmailExportBatchSize: request.payload.gmailExportBatchSize,
                outlookExportBatchSize: request.payload.outlookExportBatchSize
            });
        }
    });

    registerSettingsPage(server, {
        path: '/admin/config/branding',
        view: 'config/branding',
        pageTitle: 'Branding',
        menuKey: 'menuConfigBranding',
        schema: {
            pageBrandName: settingsSchema.pageBrandName.default(''),
            templateHeader: settingsSchema.templateHeader.default(''),
            templateHtmlHead: settingsSchema.templateHtmlHead.default('')
        },

        async loadValues() {
            const storedValues = await settings.getMulti('pageBrandName', 'templateHeader', 'templateHtmlHead');

            return {
                pageBrandName: storedValues.pageBrandName || '',
                templateHeader: storedValues.templateHeader || '',
                templateHtmlHead: storedValues.templateHtmlHead || ''
            };
        },

        async applySettings(request) {
            await settings.setMulti({
                pageBrandName: request.payload.pageBrandName,
                templateHeader: request.payload.templateHeader,
                templateHtmlHead: request.payload.templateHtmlHead
            });
        }
    });

    registerSettingsPage(server, {
        path: '/admin/config/ai',
        view: 'config/ai',
        pageTitle: 'AI Processing',
        menuKey: 'menuConfigAi',
        schema: {
            generateEmailSummary: settingsSchema.generateEmailSummary.default(false),
            openAiAPIKey: settingsSchema.openAiAPIKey.empty(''),
            openAiModel: settingsSchema.openAiModel.empty(''),

            openAiAPIUrl: settingsSchema.openAiAPIUrl.default(''),

            openAiPrompt: settingsSchema.openAiPrompt.default(''),

            contentFnJson: Joi.string()
                .max(1024 * 1024)
                .default('')
                .allow('')
                .trim()
                .description('Filter function'),

            openAiTemperature: settingsSchema.openAiTemperature.default(''),
            openAiTopP: settingsSchema.openAiTopP.default(''),
            openAiMaxTokens: settingsSchema.openAiMaxTokens.default('')
        },

        async loadValues() {
            const values = {
                generateEmailSummary: (await settings.get('generateEmailSummary')) || false,
                openAiModel: await settings.get('openAiModel'),
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

            return values;
        },

        async viewContext(request, values) {
            return {
                errorLog: await getAiErrorLog(),
                defaultPromptJson: JSON.stringify({ prompt: await getDefaultPrompt() }),

                hasOpenAiAPIKey: !!(await settings.get('openAiAPIKey')),
                openAiError: await getOpenAiError(request.app.gt),
                openAiModels: await getOpenAiModels(OPEN_AI_MODELS, values.openAiModel),

                scriptEnvJson: JSON.stringify((await settings.get('scriptEnv')) || '{}'),
                examplePayloadsJson: JSON.stringify(
                    (await getExampleDocumentsPayloads()).map(entry =>
                        Object.assign({}, entry, { summary: undefined, riskAssessment: undefined, preview: undefined })
                    )
                )
            };
        },

        async applySettings(request) {
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
                err.details = {
                    contentFnJson: 'Invalid JSON'
                };
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

            // per-key set(), not setMulti: writing openAi* keys bumps the
            // openAiSettingsVersion counter and a truthy generateEmailSummary
            // force-enables notifyText - side effects that setMulti skips
            for (let key of Object.keys(data)) {
                await settings.set(key, data[key]);
            }
        }
    });

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

                // crux from olden times
                for (let key of Object.keys(response.summary)) {
                    // remove meta keys from output
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
            payload: {
                maxBytes: MAX_BODY_SIZE,
                timeout: MAX_PAYLOAD_TIMEOUT
            },
            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

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
                return {
                    success: false,
                    error: err.message
                };
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
                    openAiAPIKey: settingsSchema.openAiAPIKey.empty(''),
                    openAiAPIUrl: settingsSchema.openAiAPIUrl.default('')
                })
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/config/branding/preview',
        async handler(request, h) {
            return h.view(
                'config/service-preview',
                {
                    pageBrandName: request.payload.pageBrandName,
                    embeddedTemplateHeader: request.payload.templateHeader,
                    embeddedTemplateHtmlHead: request.payload.templateHtmlHead
                },
                {
                    layout: 'public'
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
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                failAction,

                payload: Joi.object({
                    alert: Joi.string().required().max(1024),
                    entry: Joi.string().empty('').max(1024).trim()
                })
            }
        }
    });

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
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                }
            }
        }
    });

    registerSettingsPage(server, {
        path: '/admin/config/logging',
        view: 'config/logging',
        pageTitle: 'Logging',
        menuKey: 'menuConfigLogging',
        schema: configLoggingSchema,

        async loadValues() {
            let logs = (await settings.get('logs')) || {};
            let sentryValues = await settings.getMulti('sentryEnabled', 'sentryDsn');

            return {
                all: !!logs.all,
                maxLogLines: typeof logs.maxLogLines === 'undefined' ? DEFAULT_MAX_LOG_LINES : logs.maxLogLines,
                sentryEnabled: !!sentryValues.sentryEnabled,
                sentryDsn: sentryValues.sentryDsn || ''
            };
        },

        async viewContext(request, values) {
            let sentryEnvManaged = !!readEnvValue('SENTRY_DSN');
            return {
                sentryEnvManaged,
                // a SENTRY_DSN environment value forces error reporting on, so the disabled
                // checkbox must render as checked regardless of the stored setting - also on
                // error re-renders, where the disabled (unsubmitted) field is absent from
                // the payload
                sentryChecked: sentryEnvManaged || !!values.sentryEnabled
            };
        },

        async applySettings(request) {
            const data = {
                logs: {
                    all: !!request.payload.all,
                    maxLogLines: request.payload.maxLogLines || 0
                }
            };

            if (!readEnvValue('SENTRY_DSN')) {
                // the form renders these fields as disabled when the DSN is pinned by the
                // environment, so do not overwrite the stored values in that case
                data.sentryEnabled = !!request.payload.sentryEnabled;
                data.sentryDsn = request.payload.sentryDsn || '';
            }

            await settings.setMulti(data);
        }
    });

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

                return {
                    success: true,
                    accounts: requested
                };
            } catch (err) {
                request.logger.error({ msg: 'Failed to request reconnect', err, accounts: request.payload.accounts });
                return { success: false, error: err.message };
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
                    accounts: Joi.array()
                        .items(Joi.string().max(256))
                        .default([])
                        .example(['account-id-1', 'account-id-2'])
                        .description('Request reconnect for listed accounts')
                        .label('LoggedAccounts')
                })
            }
        }
    });

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
                return {
                    success: false,
                    target: webhooks,
                    error: 'Webhook URL is not set'
                };
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
                                data: {
                                    nonce: crypto.randomBytes(NONCE_BYTES).toString('base64url')
                                }
                            }),
                        headers,
                        dispatcher: httpAgent.retry
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

                return {
                    success: true,
                    target: webhooks,
                    duration
                };
            } catch (err) {
                request.logger.error({ msg: 'Failed posting webhook', webhooks, event: 'test', err });
                return {
                    success: false,
                    target: webhooks,
                    duration,
                    error: err.message,
                    code: err.code
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
                    webhooks: Joi.string()
                        .uri({
                            scheme: ['http', 'https'],
                            allowRelative: false
                        })
                        .allow('')
                        .example('https://myservice.com/imap/webhooks')
                        .description('Webhook URL'),
                    customHeaders: Joi.string()
                        .allow('')
                        .trim()
                        .max(10 * 1024)
                        .default('')
                        .description('Custom request headers'),
                    payload: Joi.string()
                        .max(1024 * 1024)
                        .empty('')
                        .trim()
                        .description('Example JSON payload')
                })
            }
        }
    });

    // Webhook, template, gateway, and token routes are in admin-entities-routes.js

    server.route({
        method: 'GET',
        path: '/admin/config/license',
        async handler(request, h) {
            await call({ cmd: 'checkLicense' });

            let subexp = await settings.get('subexp');
            let expiresDays;
            if (subexp && !(request.app.licenseInfo && request.app.licenseInfo.details && request.app.licenseInfo.details.lt)) {
                let delayMs = new Date(subexp) - Date.now();
                expiresDays = Math.max(Math.ceil(delayMs / (24 * 3600 * 1000)), 0);
            }

            return h.view(
                'config/license',
                {
                    pageTitle: 'License',
                    menuLicense: true,
                    hideLicenseWarning: true,

                    subexp,
                    expiresDays,

                    showLicenseText:
                        !request.app.licenseInfo ||
                        !request.app.licenseInfo.active ||
                        (request.app.licenseInfo.details && request.app.licenseInfo.details.trial)
                },
                {
                    layout: 'app'
                }
            );
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/config/license',
        async handler(request, h) {
            try {
                // update license
                const licenseInfo = await call({ cmd: 'updateLicense', license: request.payload.license });
                if (!licenseInfo) {
                    let err = new Error('Failed to update license. Check license file contents.');
                    err.statusCode = 403;
                    err.details = { license: err.message };
                    throw err;
                }

                if (licenseInfo.active) {
                    await request.flash({ type: 'info', message: `License activated` });
                }

                return h.redirect('/admin/config/license');
            } catch (err) {
                await request.flash({ type: 'danger', message: `Couldn't register license. Check the key and try again.` });
                request.logger.error({ msg: 'Failed to register license key', err });

                return h.view(
                    'config/license',
                    {
                        pageTitle: 'License',
                        menuLicense: true,
                        hideLicenseWarning: true,

                        errors: err.details,
                        showLicenseText:
                            (err.details && !!err.details.license) ||
                            !request.app.licenseInfo ||
                            !request.app.licenseInfo.active ||
                            (request.app.licenseInfo.details && request.app.licenseInfo.details.trial)
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

                    await request.flash({ type: 'danger', message: `Couldn't register license. Check the key and try again.` });
                    request.logger.error({ msg: 'Failed to register license key', err });

                    return h
                        .view(
                            'config/license',
                            {
                                pageTitle: 'License',
                                menuLicense: true,
                                hideLicenseWarning: true,

                                errors,

                                showLicenseText:
                                    (errors && !!errors.license) ||
                                    !request.app.licenseInfo ||
                                    !request.app.licenseInfo.active ||
                                    (request.app.licenseInfo.details && request.app.licenseInfo.details.trial)
                            },
                            {
                                layout: 'app'
                            }
                        )
                        .takeover();
                },

                payload: Joi.object({
                    license: Joi.string()
                        .max(10 * 1024)
                        .required()
                        .example('-----BEGIN LICENSE-----\r\n...')
                        .description('License file')
                }).label('RegisterLicense')
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/config/license/delete',
        async handler(request, h) {
            try {
                const licenseInfo = await call({ cmd: 'removeLicense' });
                if (!licenseInfo) {
                    let err = new Error('Failed to clear license info');
                    err.statusCode = 403;
                    throw err;
                } else {
                    await request.flash({ type: 'info', message: `License removed` });
                }

                return h.redirect('/admin/config/license');
            } catch (err) {
                await request.flash({ type: 'danger', message: `Couldn't remove license. Try again.` });
                request.logger.error({ msg: 'Failed to unregister license key', err, token: request.payload.token, remoteAddress: request.app.ip });
                return h.redirect('/admin/config/license');
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
                    await request.flash({ type: 'danger', message: `Couldn't remove license. Try again.` });
                    request.logger.error({ msg: 'Failed to unregister license key', err });

                    return h.redirect('/admin/config/license').takeover();
                },

                payload: Joi.object({})
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/config/license/trial',
        async handler(request) {
            try {
                // provision new trial license

                let headers = {
                    'Content-Type': 'application/json',
                    'User-Agent': `${packageData.name}/${packageData.version} (+${packageData.homepage})`
                };

                let res = await fetchCmd(`${LICENSE_HOST}/licenses/trial`, {
                    method: 'post',
                    body: JSON.stringify({
                        version: packageData.version,
                        app: '@postalsys/emailengine-app',
                        hostname: os.hostname() || 'localhost',
                        url: (await settings.get('serviceUrl')) || ''
                    }),
                    headers,
                    dispatcher: httpAgent.retry
                });

                if (!res.ok) {
                    let err = new Error(res.statusText || `Invalid response: ${res.status} ${res.statusText}`);
                    err.statusCode = res.status;

                    try {
                        err.response = await res.json();
                    } catch (err) {
                        // ignore
                    }

                    throw err;
                }

                const data = await res.json();

                let licenseFile = `-----BEGIN LICENSE-----
${Buffer.from(data.content, 'base64url').toString('base64')}
-----END LICENSE-----`;

                const licenseInfo = await call({ cmd: 'updateLicense', license: licenseFile });
                if (!licenseInfo) {
                    let err = new Error('Failed to update license. Check license file contents.');
                    err.statusCode = 403;
                    err.details = { license: err.message };
                    throw err;
                }

                if (licenseInfo.active) {
                    await request.flash({ type: 'info', message: `Trial activated` });
                    return { success: true, message: `Trial activated` };
                }

                throw new Error('Failed to activate provisioned trial license');
            } catch (err) {
                request.logger.error({ msg: 'Failed to provision a trial license key', err, remoteAddress: request.app.ip });
                return { success: false, error: (err.response && err.response.error) || err.message };
            }
        },
        options: {
            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                failAction
            }
        }
    });
}

module.exports = init;
