'use strict';

const Joi = require('joi');
const { redis } = require('../db');
const { failAction, getStats } = require('../tools');
const { MAX_DAYS_STATS } = require('../consts');
const { errorResponses } = require('../schemas');
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
                    redis: Joi.string()
                        .example('6.2.4')
                        .description('Redis version. Can include the server software in parentheses, or an error message if the version lookup failed'),
                    redisSoftware: Joi.string().example('redis').description('Redis-compatible server software name'),
                    redisCluster: Joi.boolean().example(false).description('Whether Redis is running in cluster mode'),
                    redisWarnings: Joi.array()
                        .items(
                            Joi.object({
                                key: Joi.string().example('maxmemory-policy').description('Warning identifier'),
                                color: Joi.string().example('warning').description('Severity indicator'),
                                title: Joi.string().example('Unsafe Redis eviction policy').description('Warning title'),
                                details: Joi.array().items(Joi.string()).description('Warning details')
                            })
                                .unknown()
                                .label('RedisWarningEntry')
                        )
                        .description('Warnings about the Redis configuration')
                        .label('RedisWarnings'),
                    redisPing: Joi.number().description('Redis latency in milliseconds'),
                    imapflow: Joi.string().example('1.0.188').description('ImapFlow version'),
                    bullmq: Joi.string().example('5.0.0').description('BullMQ version'),
                    arch: Joi.string().example('arm64').description('CPU architecture of the host'),
                    build: Joi.object().unknown().description('Build information for the running EmailEngine instance').label('BuildInfo'),
                    queues: Joi.object().unknown().description('Job counters for the notify, submit, and documents queues').label('QueueStats'),
                    connections: Joi.object({
                        init: Joi.number().integer().example(2).description('Accounts not yet initialized'),
                        connected: Joi.number().integer().example(8).description('Successfully connected accounts'),
                        connecting: Joi.number().integer().example(7).description('Connection is being established'),
                        syncing: Joi.number().integer().example(1).description('Accounts that are currently syncing'),
                        authenticationError: Joi.number().integer().example(3).description('Authentication failed'),
                        connectError: Joi.number().integer().example(5).description('Connection failed due to technical error'),
                        unset: Joi.number().integer().example(0).description('Accounts without valid IMAP settings'),
                        disconnected: Joi.number().integer().example(1).description('IMAP connection was closed'),
                        paused: Joi.number().integer().example(0).description('Accounts that are paused'),
                        unassigned: Joi.number().integer().example(0).description('Accounts not assigned to any worker')
                    })
                        .unknown()
                        .description('Counts of accounts in different connection states')
                        .label('ConnectionsStats'),
                    counters: Joi.object().label('CounterStats').unknown()
                }).label('StatsResponse'),
                failAction: 'log'
            }
        }
    });
}

module.exports = init;
