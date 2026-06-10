'use strict';

const Joi = require('joi');
const { failAction } = require('../tools');
const { handleError } = require('./route-helpers');
const { licenseSchema, errorResponses } = require('../schemas');

async function init(args) {
    const { server, call, CORS_CONFIG } = args;

    server.route({
        method: 'GET',
        path: '/v1/license',

        async handler(request) {
            try {
                const licenseInfo = await call({ cmd: 'license', timeout: request.headers['x-ee-timeout'] });
                if (!licenseInfo) {
                    let err = new Error('Failed to load license info');
                    err.statusCode = 403;
                    throw err;
                }
                return licenseInfo;
            } catch (err) {
                handleError(request, err);
            }
        },
        options: {
            description: 'Request license info',
            notes: 'Get active license information',
            tags: ['api', 'License'],

            plugins: {
                'hapi-swagger': {
                    responses: errorResponses(401, 403, 429, 500)
                }
            },

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },
            cors: CORS_CONFIG,

            response: {
                schema: licenseSchema.label('LicenseResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'DELETE',
        path: '/v1/license',

        async handler(request) {
            try {
                const licenseInfo = await call({ cmd: 'removeLicense', timeout: request.headers['x-ee-timeout'] });
                if (!licenseInfo) {
                    let err = new Error('Failed to clear license info');
                    err.statusCode = 403;
                    throw err;
                }
                return licenseInfo;
            } catch (err) {
                handleError(request, err);
            }
        },
        options: {
            description: 'Remove license',
            notes: 'Remove registered active license',
            tags: ['api', 'License'],

            plugins: {
                'hapi-swagger': {
                    responses: errorResponses(401, 403, 429, 500)
                }
            },

            auth: {
                strategy: 'api-token',
                mode: 'required'
            },
            cors: CORS_CONFIG,

            response: {
                schema: Joi.object({
                    active: Joi.boolean().example(false),
                    details: Joi.boolean().example(false),
                    type: Joi.string().example('LICENSE_EMAILENGINE')
                }).label('EmptyLicenseResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/v1/license',

        async handler(request) {
            try {
                const licenseInfo = await call({ cmd: 'updateLicense', license: request.payload.license, timeout: request.headers['x-ee-timeout'] });
                if (!licenseInfo) {
                    let err = new Error('Failed to update license. Check license file contents.');
                    err.statusCode = 403;
                    throw err;
                }
                return licenseInfo;
            } catch (err) {
                handleError(request, err);
            }
        },
        options: {
            description: 'Register a license',
            notes: 'Set up a license for EmailEngine to unlock all features',
            tags: ['api', 'License'],

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

                payload: Joi.object({
                    license: Joi.string()
                        .max(10 * 1024)
                        .required()
                        .example('-----BEGIN LICENSE-----\r\n...')
                        .description('License file')
                }).label('RegisterLicense')
            },

            response: {
                schema: licenseSchema.label('LicenseResponse'),
                failAction: 'log'
            }
        }
    });
}

module.exports = init;
