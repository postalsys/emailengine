'use strict';

const { redis } = require('../db');
const { Account } = require('../account');
const getSecret = require('../get-secret');
const Boom = require('@hapi/boom');
const Joi = require('joi');
const { failAction } = require('../tools');

const { accountIdSchema } = require('../schemas');

async function init(args) {
    const { server, call, CORS_CONFIG } = args;

    server.route({
        method: 'POST',
        path: '/v1/chat/{account}',

        async handler(request, h) {
            try {
                // throws if account does not exist
                let accountObject = new Account({ redis, account: request.params.account, call, secret: await getSecret() });
                await accountObject.loadAccountData();

                const esClient = await h.getESClient(request.logger);
                const { index, client } = esClient;

                // Step 1. Embeddings for the request

                let embeddingsResult = await call({ cmd: 'generateChunkEmbeddings', data: { message: request.payload.message } });
                if (!embeddingsResult || !embeddingsResult.embedding) {
                    let error = new Error('Failed to generate embeddings for query');
                    throw error;
                }

                // Step 2. find matching vectors

                let knnResult = await client.knnSearch({
                    index: `${index}.embeddings`,
                    knn: {
                        field: 'embeddings',

                        query_vector: embeddingsResult.embedding,
                        k: 5,
                        num_candidates: 100
                    },

                    filter: {
                        term: {
                            account: request.params.account
                        }
                    },

                    _source: ['id', 'account', 'chunk', 'messageId', 'chunkNr']
                });

                if (!knnResult?.hits?.hits?.length) {
                    return {
                        success: true,
                        response: null
                    };
                }

                let results = [];
                knnResult.hits.hits
                    .map(entry => {
                        let headerPos = entry._source.chunk.indexOf('\n\n');
                        return {
                            account: entry._source.account,
                            messageId: entry._source.messageId,
                            chunkNr: entry._source.chunkNr,
                            header: entry._source.chunk.substring(0, headerPos),
                            body: entry._source.chunk.substring(headerPos + 2)
                        };
                    })
                    .forEach(entry => {
                        let existing = results.find(elm => elm.messageId === entry.messageId);
                        if (!existing) {
                            results.push({
                                messageId: entry.messageId,
                                header: `${entry.header}\nMessage-ID: ${entry.messageId}`,
                                chunks: [{ chunkNr: entry.chunkNr, body: entry.body }]
                            });
                        } else {
                            existing.chunks.push({ chunkNr: entry.chunkNr, body: entry.body });
                        }
                    });

                let payloadData = results.map((entry, nr) => {
                    entry.chunks.sort((a, b) => a.chunkNr - b.chunkNr);
                    return `- EMAIL #${nr + 1}:\n${entry.header}\n\n${entry.chunks
                        .slice(0, 3) // limit chunks for a single email
                        .map(chunk => chunk.body)
                        .join('\n')}`;
                });

                let responseData = {};

                let queryResponse = await call({
                    cmd: 'embeddingsQuery',
                    data: {
                        question: request.payload.message,
                        contextChunks: payloadData.join('\n\n')
                    },
                    timeout: 3 * 60 * 1000
                });

                if (queryResponse?.answer) {
                    responseData.answer = queryResponse?.answer;
                }

                if (queryResponse?.messageId) {
                    // find the originating message this bounce applies for
                    let searchResult = await client.search({
                        index,
                        size: 20,
                        from: 0,
                        query: {
                            bool: {
                                must: [
                                    {
                                        term: {
                                            account: request.params.account
                                        }
                                    },
                                    {
                                        term: {
                                            messageId: queryResponse.messageId
                                        }
                                    }
                                ]
                            }
                        },
                        sort: { uid: 'desc' },
                        _source_excludes: 'headers,text'
                    });

                    if (searchResult && searchResult.hits && searchResult.hits.hits && searchResult.hits.hits.length) {
                        let message = searchResult.hits.hits
                            .sort((a, b) => {
                                if (a._source.specialUse === '\\Inbox') {
                                    return -1;
                                }
                                if (b._source.specialUse === '\\Inbox') {
                                    return 1;
                                }
                                return new Date(a._source.date || a._source.created) - new Date(b._source.date || b._source.created);
                            })
                            .shift()._source;

                        responseData.message = {};
                        for (let key of ['id', 'path', 'date', 'from', 'to', 'cc', 'bcc', 'subject']) {
                            if (message[key]) {
                                responseData.message[key] = message[key];
                            }
                        }
                    }
                }

                return {
                    success: !!(responseData.answer || responseData.message),
                    ...responseData
                };
            } catch (err) {
                request.logger.error({ msg: 'API request failed', err });
                if (Boom.isBoom(err)) {
                    throw err;
                }
                let error = Boom.boomify(err, { statusCode: err.statusCode || 500 });
                if (err.code) {
                    error.output.payload.code = err.code;
                }
                throw error;
            }
        },

        options: {
            description: 'Chat with emails',
            notes: 'Use OpenAI API and embeddings stored in the Document Store to "chat" with account emails.',
            tags: ['api', 'Chat'],

            plugins: {},

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
                }),

                payload: Joi.object({
                    message: Joi.string()
                        .trim()
                        .max(1024)
                        .example('When did Jason last message me?')
                        .description('Chat message to use')
                        .label('ChatMessage')
                        .required()
                }).label('RequestChat')
            },

            response: {
                schema: Joi.object({
                    response: Joi.string().trim().example('Last tuesday').description('Chat response').label('ChatResponse').required()
                }).label('ReturnChatResponse'),
                failAction: 'log'
            }
        }
    });
}

module.exports = init;
