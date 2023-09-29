'use strict';

const { redis } = require('../db');
const { Account } = require('../account');
const getSecret = require('../get-secret');
const Boom = require('@hapi/boom');
const Joi = require('joi');
const { failAction } = require('../tools');
const settings = require('../settings');

const { accountIdSchema, addressSchema } = require('../schemas');

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

                let documentStoreEnabled = await settings.get('documentStoreEnabled');
                let documentStoreGenerateEmbeddings = (await settings.get('documentStoreGenerateEmbeddings')) || false;
                let hasOpenAiAPIKey = !!(await settings.get('openAiAPIKey'));

                if (!documentStoreEnabled) {
                    let error = Boom.boomify(new Error('Document store is not enabled'), { statusCode: 403 });
                    error.output.payload.code = 'DocumentStoreDisabled';
                    throw error;
                }

                if (!documentStoreGenerateEmbeddings) {
                    let error = Boom.boomify(new Error('Chat is not enabled'), { statusCode: 403 });
                    error.output.payload.code = 'ChatDisabled';
                    throw error;
                }

                if (!hasOpenAiAPIKey) {
                    let error = Boom.boomify(new Error('OpenAI API key not set'), { statusCode: 403 });
                    error.output.payload.code = 'ApiKeyNotSet';
                    throw error;
                }

                const esClient = await h.getESClient(request.logger);
                const { index, client } = esClient;

                // Step 1. Embeddings for the request

                let embeddingsResult = await call({ cmd: 'generateChunkEmbeddings', data: { message: request.payload.question } });

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
                        response: null,
                        description: 'No matching emails found'
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
                        question: request.payload.question,
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
            notes: 'Use OpenAI API and embeddings stored in the Document Store to "chat" with account emails. Requires Document Store indexing and the "Chat with emails" feature to be enabled.',
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
                    question: Joi.string()
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
                    success: Joi.boolean().example(true).description('Was the request successful').label('ReturnChatResponseSuccess'),
                    answer: Joi.string().trim().example('Last tuesday').description('Chat response').label('ChatResponse').required(),
                    message: Joi.object({
                        id: Joi.string().example('AAAAAgAACrI').description('Message ID').label('ChatMessageId'),
                        path: Joi.string().example('INBOX').description('Folder this message was found from').label('ChatMessagePath'),
                        from: addressSchema.example({ name: 'From Me', address: 'sender@example.com' }).description('The From address').label('FromAddress'),

                        to: Joi.array()
                            .items(addressSchema)
                            .single()
                            .description('List of addresses')
                            .example([{ address: 'recipient@example.com' }])
                            .label('AddressList')
                    })
                        .description('Email that best matched the question')
                        .label('ChatResponseMessage')
                }).label('ReturnChatResponse'),
                failAction: 'log'
            }
        }
    });
}

module.exports = init;
