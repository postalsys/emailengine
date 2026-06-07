'use strict';

const Joi = require('joi');
const { redis } = require('../db');
const { failAction, getStats } = require('../tools');
const { MAX_DAYS_STATS } = require('../consts');
const packageData = require('../../package.json');

async function init(args) {
    const { server, call, CORS_CONFIG } = args;

    server.route({
        method: 'GET',
        path: '/v1/stats',

        async handler(request) {
            return await getStats(redis, call, request.query.seconds);
        },

        options: {
            description: 'Return server stats',
            tags: ['api', 'Stats'],

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
                    seconds: Joi.number()
                        .integer()
                        .empty('')
                        .min(0)
                        .max(MAX_DAYS_STATS * 24 * 3600)
                        .default(3600)
                        .example(3600)
                        .description('Duration for counters')
                        .label('CounterSeconds')
                }).label('ServerStats')
            },

            response: {
                schema: Joi.object({
                    version: Joi.string().example(packageData.version).description('EmailEngine version number'),
                    license: Joi.string().example(packageData.license).description('EmailEngine license'),
                    accounts: Joi.number().integer().example(26).description('Number of registered accounts'),
                    node: Joi.string().example('16.10.0').description('Node.js Version'),
                    redis: Joi.string().example('6.2.4').description('Redis Version'),
                    connections: Joi.object({
                        init: Joi.number().integer().example(2).description('Accounts not yet initialized'),
                        connected: Joi.number().integer().example(8).description('Successfully connected accounts'),
                        connecting: Joi.number().integer().example(7).description('Connection is being established'),
                        authenticationError: Joi.number().integer().example(3).description('Authentication failed'),
                        connectError: Joi.number().integer().example(5).description('Connection failed due to technical error'),
                        unset: Joi.number().integer().example(0).description('Accounts without valid IMAP settings'),
                        disconnected: Joi.number().integer().example(1).description('IMAP connection was closed')
                    })
                        .description('Counts of accounts in different connection states')
                        .label('ConnectionsStats'),
                    counters: Joi.object().label('CounterStats').unknown()
                }).label('SettingsResponse'),
                failAction: 'log'
            }
        }
    });
}

module.exports = init;
