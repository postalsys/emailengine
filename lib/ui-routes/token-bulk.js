'use strict';

// Bulk delete on the access tokens list: one token per request, posted by static/js/list-bulk.js
// (views/partials/ui/bulk-actions.hbs), so a long selection shows progress and can be stopped. The
// answer follows the bulk contract: done, missing or failed.

const Joi = require('joi');

const tokens = require('../tokens');
const { formatPartialSecretKey } = require('../tools');
const { bulkFailAction } = require('./account-bulk');

function registerPostTokensBulk(server) {
    server.route({
        method: 'POST',
        path: '/admin/tokens/{token}/bulk',
        async handler(request) {
            const { token } = request.params;
            try {
                const deleted = await tokens.delete(token, { remoteAddress: request.app.ip });
                request.logger.info({
                    msg: 'Bulk token action',
                    action: 'delete',
                    token: formatPartialSecretKey(token),
                    deleted,
                    remoteAddress: request.app.ip
                });
                return { result: deleted ? 'done' : 'missing' };
            } catch (err) {
                // A partial value only: the id is the hash of the token, never the token itself, but
                // this is the same rule the single delete route keeps
                request.logger.error({
                    msg: 'Bulk token action failed',
                    action: 'delete',
                    token: formatPartialSecretKey(token),
                    err,
                    remoteAddress: request.app.ip
                });
                return { result: 'failed', error: err.message };
            }
        },
        options: {
            validate: {
                options: {
                    stripUnknown: true,
                    abortEarly: false,
                    convert: true
                },

                failAction: bulkFailAction,

                params: Joi.object({
                    token: Joi.string().length(64).hex().required().description('Access token ID')
                }),

                payload: Joi.object({
                    action: Joi.string().valid('delete').required()
                })
            }
        }
    });
}

module.exports = { registerPostTokensBulk };
