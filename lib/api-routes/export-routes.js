'use strict';

const fs = require('fs');
const { Export } = require('../export');
const Boom = require('@hapi/boom');
const Joi = require('joi');
const { failAction } = require('../tools');
const { accountIdSchema, exportRequestSchema, exportStatusSchema, exportListSchema, exportIdSchema } = require('../schemas');
const getSecret = require('../get-secret');
const { createDecryptStream } = require('../stream-encrypt');

function handleError(request, err) {
    request.logger.error({ msg: 'API request failed', err });
    if (Boom.isBoom(err)) {
        throw err;
    }
    const error = Boom.boomify(err, { statusCode: err.statusCode || 500 });
    if (err.code) {
        error.output.payload.code = err.code;
    }
    throw error;
}

async function init(args) {
    const { server, CORS_CONFIG } = args;

    server.route({
        method: 'POST',
        path: '/v1/account/{account}/export',

        async handler(request) {
            try {
                return await Export.create(request.params.account, {
                    folders: request.payload.folders,
                    startDate: request.payload.startDate,
                    endDate: request.payload.endDate,
                    textType: request.payload.textType,
                    maxBytes: request.payload.maxBytes,
                    includeAttachments: request.payload.includeAttachments
                });
            } catch (err) {
                handleError(request, err);
            }
        },

        options: {
            description: 'Create export',
            notes: 'Creates a new bulk message export job. The export runs asynchronously and notifies via webhook when complete.',
            tags: ['api', 'Export (Beta)'],

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
                }).label('CreateExportParams'),

                payload: exportRequestSchema
            },

            response: {
                schema: Joi.object({
                    exportId: Joi.string().example('exp_abc123def456').description('Export job identifier'),
                    status: Joi.string().example('queued').description('Export status'),
                    created: Joi.date().iso().example('2024-01-15T10:30:00Z').description('When export was created')
                }).label('CreateExportResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/v1/account/{account}/export/{exportId}',

        async handler(request) {
            try {
                const result = await Export.get(request.params.account, request.params.exportId);
                if (!result) {
                    throw Boom.notFound('Export not found');
                }
                return result;
            } catch (err) {
                handleError(request, err);
            }
        },

        options: {
            description: 'Get export status',
            notes: 'Returns the status and progress of an export job.',
            tags: ['api', 'Export (Beta)'],

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
                    account: accountIdSchema.required(),
                    exportId: exportIdSchema
                }).label('GetExportParams')
            },

            response: {
                schema: exportStatusSchema,
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/v1/account/{account}/export/{exportId}/download',

        async handler(request, h) {
            try {
                const { account, exportId } = request.params;
                const fileInfo = await Export.getFile(account, exportId);
                if (!fileInfo) {
                    throw Boom.notFound('Export not found');
                }

                const fileReadStream = fs.createReadStream(fileInfo.filePath);
                let stream = fileReadStream;

                stream.on('error', err => {
                    request.logger.error({ msg: 'Export download stream error', exportId, err });
                });

                if (fileInfo.isEncrypted) {
                    const secret = await getSecret();
                    if (!secret) {
                        fileReadStream.destroy();
                        throw Boom.serverUnavailable('Encryption secret not available for decryption');
                    }
                    const decryptStream = createDecryptStream(secret);
                    decryptStream.on('error', err => {
                        request.logger.error({ msg: 'Export decryption error', exportId, err });
                        fileReadStream.destroy();
                    });
                    stream = fileReadStream.pipe(decryptStream);
                }

                return h
                    .response(stream)
                    .type('application/gzip')
                    .header('Content-Disposition', `attachment; filename="${fileInfo.filename}"`)
                    .header('Content-Encoding', 'identity');
            } catch (err) {
                handleError(request, err);
            }
        },

        options: {
            description: 'Download export file',
            notes: 'Downloads the completed export file as gzip-compressed NDJSON.',
            tags: ['api', 'Export (Beta)'],

            plugins: {
                'hapi-swagger': {
                    produces: ['application/gzip']
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
                    account: accountIdSchema.required(),
                    exportId: exportIdSchema
                }).label('DownloadExportParams')
            }
        }
    });

    server.route({
        method: 'DELETE',
        path: '/v1/account/{account}/export/{exportId}',

        async handler(request) {
            try {
                const deleted = await Export.delete(request.params.account, request.params.exportId);
                if (!deleted) {
                    throw Boom.notFound('Export not found');
                }
                return { deleted: true };
            } catch (err) {
                handleError(request, err);
            }
        },

        options: {
            description: 'Delete export',
            notes: 'Cancels a pending export or deletes a completed export. Removes both Redis data and the export file.',
            tags: ['api', 'Export (Beta)'],

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
                    account: accountIdSchema.required(),
                    exportId: exportIdSchema
                }).label('DeleteExportParams')
            },

            response: {
                schema: Joi.object({
                    deleted: Joi.boolean().example(true).description('True if export was deleted')
                }).label('DeleteExportResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/v1/account/{account}/export/{exportId}/resume',

        async handler(request) {
            try {
                return await Export.resume(request.params.account, request.params.exportId);
            } catch (err) {
                handleError(request, err);
            }
        },

        options: {
            description: 'Resume failed export',
            notes: 'Resumes a failed export from its last checkpoint. Only works for exports that are marked as resumable.',
            tags: ['api', 'Export (Beta)'],

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
                    account: accountIdSchema.required(),
                    exportId: exportIdSchema
                }).label('ResumeExportParams')
            },

            response: {
                schema: Joi.object({
                    exportId: Joi.string().example('exp_abc123def456').description('Export job identifier'),
                    status: Joi.string().example('queued').description('Export status'),
                    resumed: Joi.boolean().example(true).description('True if export was resumed'),
                    progress: Joi.object({
                        messagesExported: Joi.number().integer().example(500).description('Messages already exported'),
                        messagesQueued: Joi.number().integer().example(1500).description('Total messages queued'),
                        messagesSkipped: Joi.number().integer().example(5).description('Messages skipped')
                    }).label('ResumeExportProgress')
                }).label('ResumeExportResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'GET',
        path: '/v1/account/{account}/exports',

        async handler(request) {
            try {
                return await Export.list(request.params.account, {
                    page: request.query.page,
                    pageSize: request.query.pageSize
                });
            } catch (err) {
                handleError(request, err);
            }
        },

        options: {
            description: 'List exports',
            notes: 'Lists all exports for an account with pagination.',
            tags: ['api', 'Export (Beta)'],

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
                }).label('ListExportsParams'),

                query: Joi.object({
                    page: Joi.number()
                        .integer()
                        .min(0)
                        .max(1024 * 1024)
                        .default(0)
                        .example(0)
                        .description('Page number (zero indexed)')
                        .label('PageNumber'),
                    pageSize: Joi.number().integer().min(1).max(1000).default(20).example(20).description('How many entries per page').label('PageSize')
                }).label('ListExportsQuery')
            },

            response: {
                schema: exportListSchema,
                failAction: 'log'
            }
        }
    });
}

module.exports = init;
