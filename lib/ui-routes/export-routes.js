'use strict';

// Admin UI routes for account data exports (the Exports tab on an account page): list,
// status, create, delete, and download. Extracted verbatim from lib/routes-ui.js. These
// are session-authenticated JSON/file endpoints backed by the Export class.

const Joi = require('joi');
const Boom = require('@hapi/boom');
const fs = require('fs');

const { Export } = require('../export');
const getSecret = require('../get-secret');
const { failAction } = require('../tools');
const { exportIdSchema } = require('../schemas');
const { throwAsBoom } = require('./route-helpers');

function init(args) {
    const { server } = args;

    // List exports for account
    server.route({
        method: 'GET',
        path: '/admin/accounts/{account}/exports',
        async handler(request) {
            try {
                return await Export.list(request.params.account, {
                    page: request.query.page,
                    pageSize: request.query.pageSize
                });
            } catch (err) {
                request.logger.error({ msg: 'Failed to list exports', err, account: request.params.account });
                throwAsBoom(err);
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
                params: Joi.object({
                    account: Joi.string().max(256).required()
                }),
                query: Joi.object({
                    page: Joi.number().integer().min(0).default(0),
                    pageSize: Joi.number().integer().min(1).max(100).default(20)
                })
            }
        }
    });

    // Get export status
    server.route({
        method: 'GET',
        path: '/admin/accounts/{account}/export/{exportId}',
        async handler(request) {
            try {
                const result = await Export.get(request.params.account, request.params.exportId);
                if (!result) {
                    throw Boom.notFound('Export not found');
                }
                return result;
            } catch (err) {
                request.logger.error({ msg: 'Failed to get export', err, account: request.params.account, exportId: request.params.exportId });
                throwAsBoom(err);
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
                params: Joi.object({
                    account: Joi.string().max(256).required(),
                    exportId: exportIdSchema
                })
            }
        }
    });

    // Create export
    server.route({
        method: 'POST',
        path: '/admin/accounts/{account}/export',
        async handler(request) {
            try {
                return await Export.create(request.params.account, {
                    startDate: request.payload.startDate,
                    endDate: request.payload.endDate,
                    includeAttachments: request.payload.includeAttachments,
                    folders: []
                });
            } catch (err) {
                request.logger.error({ msg: 'Failed to create export', err, account: request.params.account });
                throwAsBoom(err);
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
                params: Joi.object({
                    account: Joi.string().max(256).required()
                }),
                payload: Joi.object({
                    startDate: Joi.date().iso().required(),
                    endDate: Joi.date().iso().required(),
                    includeAttachments: Joi.boolean().default(false)
                })
            }
        }
    });

    // Delete export
    server.route({
        method: 'DELETE',
        path: '/admin/accounts/{account}/export/{exportId}',
        async handler(request) {
            try {
                const deleted = await Export.delete(request.params.account, request.params.exportId);
                if (!deleted) {
                    throw Boom.notFound('Export not found');
                }
                return { deleted: true };
            } catch (err) {
                request.logger.error({ msg: 'Failed to delete export', err, account: request.params.account, exportId: request.params.exportId });
                throwAsBoom(err);
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
                params: Joi.object({
                    account: Joi.string().max(256).required(),
                    exportId: exportIdSchema
                })
            }
        }
    });

    // Download export file
    server.route({
        method: 'GET',
        path: '/admin/accounts/{account}/export/{exportId}/download',
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

                // Decrypt file if encrypted
                if (fileInfo.isEncrypted) {
                    const secret = await getSecret();
                    if (!secret) {
                        fileReadStream.destroy();
                        throw Boom.serverUnavailable('Encryption secret not available for decryption');
                    }
                    const { createDecryptStream } = require('../stream-encrypt');
                    const decryptStream = await createDecryptStream(secret);
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
                request.logger.error({ msg: 'Failed to download export', err, account: request.params.account, exportId: request.params.exportId });
                throwAsBoom(err);
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
                params: Joi.object({
                    account: Joi.string().max(256).required(),
                    exportId: exportIdSchema
                })
            }
        }
    });
}

module.exports = init;
