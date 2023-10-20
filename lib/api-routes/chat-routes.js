'use strict';

const { redis } = require('../db');
const { Account } = require('../account');
const getSecret = require('../get-secret');
const Boom = require('@hapi/boom');
const Joi = require('joi');
const { failAction, getBoolean } = require('../tools');
const settings = require('../settings');
const util = require('util');

const LOG_VERBOSE = getBoolean(process.env.EE_OPENAPI_VERBOSE);

const { accountIdSchema, addressSchema } = require('../schemas');

function getDateValue(str) {
    try {
        let date;
        if (/^\d{4}-\d{1,2}-\d{1,2}(\s+\d{1,2}:\d{1,2}(:\d{1,2})?)?$/.test(str)) {
            let parts = str.split(/[^\d]+/).map(v => Number(v));
            parts[1]--;
            date = new Date(Date.UTC(...parts));
        } else {
            date = new Date(str);
        }

        if (date.toString() === 'Invalid Date') {
            return false;
        }
        return date;
    } catch (err) {
        return false;
    }
}

async function init(args) {
    const { server, call, CORS_CONFIG } = args;

    async function processChatRequest(opts) {
        let { account, question, index, client } = opts;

        // throws if account does not exist
        let accountObject = new Account({ redis, account, call, secret: await getSecret() });
        let accountData = await accountObject.loadAccountData();

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

        let processPipeline = [];

        processPipeline.push({
            timestamp: new Date().toISOString(),
            message: 'Received a question',
            question
        });

        // Step 1. define sorting options

        let sortingResponse;
        try {
            sortingResponse = await call({
                cmd: 'questionQuery',
                data: {
                    question,
                    account
                },
                timeout: 3 * 60 * 1000
            });
        } catch (err) {
            err.processPipeline = processPipeline;
            throw err;
        }

        processPipeline.push({
            timestamp: new Date().toISOString(),
            message: 'Retrieved the sorting options',
            ordering: sortingResponse?.ordering,
            startTime: sortingResponse?.start_time,
            endTime: sortingResponse?.end_time,
            model: sortingResponse?.model,
            tokens: sortingResponse.tokens
        });

        // Step 2. Embeddings for the request

        let embeddingsResult;
        try {
            embeddingsResult = await call({
                cmd: 'generateChunkEmbeddings',
                data: {
                    message: `${sortingResponse?.topic || question}`,
                    account
                }
            });
        } catch (err) {
            err.processPipeline = processPipeline;
            throw err;
        }

        if (!embeddingsResult || !embeddingsResult.embedding) {
            let error = new Error('Failed to generate embeddings for query');
            error.processPipeline = processPipeline;
            throw error;
        }

        processPipeline.push({
            timestamp: new Date().toISOString(),
            message: 'Generated embeddings for vector search',
            model: embeddingsResult?.model,
            tokens: embeddingsResult?.usage?.total_tokens
        });

        // Step 3. find matching vectors

        const vectorsFilter = {
            bool: {
                must: [
                    {
                        term: {
                            account
                        }
                    }
                ]
            }
        };

        let startDate, endDate;
        if (sortingResponse?.start_time) {
            startDate = getDateValue(sortingResponse?.start_time);
        }
        if (sortingResponse?.end_time) {
            endDate = getDateValue(sortingResponse?.end_time);
        }
        if (startDate && endDate && startDate.getTime() === endDate.getTime()) {
            // use next day value
            endDate = new Date(endDate.getTime() + 24 * 3600 * 1000);
        }
        let dateMatch = {};
        if (startDate) {
            dateMatch.gte = startDate;
        }
        if (endDate) {
            dateMatch.lte = endDate;
        }
        if (Object.keys(dateMatch).length) {
            vectorsFilter.bool.must.push({
                range: { date: dateMatch }
            });
        }

        let knnResult;
        try {
            knnResult = await client.knnSearch({
                index: `${index}.embeddings`,
                knn: {
                    field: 'embeddings',

                    query_vector: embeddingsResult.embedding,
                    k: 10,
                    num_candidates: 100
                },

                filter: vectorsFilter,

                fields: ['id', 'account', 'chunk', 'messageId', 'chunkNr', 'date', 'created']
            });
        } catch (err) {
            err.processPipeline = processPipeline;
            throw err;
        }

        if (!knnResult?.hits?.hits?.length) {
            processPipeline.push({
                timestamp: new Date().toISOString(),
                message: 'No matching vectors found from the database',
                filter: vectorsFilter?.bool?.must
            });
            return {
                success: true,
                answer: null,
                processPipeline
            };
        }

        processPipeline.push({
            timestamp: new Date().toISOString(),
            message: 'Retrieved matching vectors from the database',
            matches: knnResult?.hits?.hits?.length || 0,
            filter: vectorsFilter?.bool?.must
        });

        let results = [];
        knnResult.hits.hits
            .map(entry => {
                let headerPos = entry._source.chunk.indexOf('\n\n');
                return {
                    account: entry._source.account,
                    messageId: entry._source.messageId,
                    chunkNr: entry._source.chunkNr,
                    header: entry._source.chunk.substring(0, headerPos),
                    body: entry._source.chunk.substring(headerPos + 2),
                    date: entry._source.date,
                    created: entry._source.created
                };
            })
            .forEach(entry => {
                let existing = results.find(elm => elm.messageId === entry.messageId);
                if (!existing) {
                    results.push({
                        messageId: entry.messageId,
                        header: `${entry.header}\nMessage-ID: ${entry.messageId}`,
                        chunks: [{ chunkNr: entry.chunkNr, body: entry.body }],
                        date: new Date(entry.date || entry.created)
                    });
                } else {
                    existing.chunks.push({ chunkNr: entry.chunkNr, body: entry.body });
                }
            });

        // sort and slice
        switch (sortingResponse?.ordering) {
            case 'newer_first':
                results = results.sort((a, b) => b.date - a.date);
                break;
            case 'older_first':
                results = results.sort((a, b) => a.date - b.date);
                break;
        }
        results = results.slice(0, 6);

        let payloadData = results.map((entry, nr) => {
            entry.chunks.sort((a, b) => a.chunkNr - b.chunkNr);
            return `- EMAIL #${nr + 1}:\n${entry.header}\n\n${entry.chunks
                .slice(0, 3) // limit chunks for a single email
                .map(chunk => chunk.body)
                .join('\n')}`;
        });

        // Step 4. Send the question with context emails

        let responseData = {};

        let queryResponse;
        try {
            queryResponse = await call({
                cmd: 'embeddingsQuery',
                data: {
                    question,
                    contextChunks: payloadData.join('\n\n'),
                    account,
                    userData: { name: accountData.name, email: accountData.email }
                },
                timeout: 3 * 60 * 1000
            });
        } catch (err) {
            err.processPipeline = processPipeline;
            throw err;
        }

        processPipeline.push({
            timestamp: new Date().toISOString(),
            message: 'Retrieved the answer',
            messages: queryResponse?.messageId?.length || 0,
            model: queryResponse?.model,
            tokens: queryResponse.tokens
        });

        if (queryResponse?.answer) {
            responseData.answer = queryResponse?.answer;
        }

        if (queryResponse?.messageId) {
            let searchQuery = {
                bool: {
                    must: [
                        {
                            term: {
                                account
                            }
                        },
                        {
                            terms: {
                                messageId: queryResponse.messageId
                            }
                        }
                    ]
                }
            };

            // find the originating message this bounce applies for
            let searchResult;
            try {
                searchResult = await client.search({
                    index,
                    size: 20,
                    from: 0,
                    query: searchQuery,
                    sort: { uid: 'desc' },
                    _source_excludes: 'headers,text'
                });
            } catch (err) {
                err.processPipeline = processPipeline;
                throw err;
            }

            if (LOG_VERBOSE) {
                console.error(util.inspect({ searchQuery, searchResult }, false, 8, true));
            }

            if (searchResult && searchResult.hits && searchResult.hits.hits && searchResult.hits.hits.length) {
                let seenIds = new Set();
                responseData.messages = searchResult.hits.hits
                    .map(message => message._source)
                    .sort((a, b) => {
                        if (a.messageSpecialUse === '\\Inbox') {
                            return -1;
                        }
                        if (b.messageSpecialUse === '\\Inbox') {
                            return 1;
                        }
                        return new Date(a.date || a.created) - new Date(b.date || b.created);
                    })
                    .filter(message => {
                        if (seenIds.has(message.messageId)) {
                            return false;
                        }
                        seenIds.add(message.messageId);
                        return true;
                    })
                    .sort((a, b) => new Date(b.date) - new Date(a.date))
                    .map(message => {
                        let responseData = {};
                        for (let key of ['id', 'path', 'date', 'from', 'to', 'cc', 'bcc', 'subject', 'messageSpecialUse']) {
                            if (message[key]) {
                                responseData[key] = message[key];
                            }
                        }
                        return responseData;
                    });
            }
        }

        return {
            success: !!(responseData.answer || responseData.message),
            ...responseData,
            processPipeline
        };
    }

    server.route({
        method: 'POST',
        path: '/v1/chat/{account}',

        async handler(request, h) {
            try {
                const esClient = await h.getESClient(request.logger);
                const { index, client } = esClient;
                return await processChatRequest({
                    account: request.params.account,
                    question: request.payload.question,
                    index,
                    client
                });
            } catch (err) {
                request.logger.error({ msg: 'API request failed', err });
                if (Boom.isBoom(err)) {
                    throw err;
                }
                let error = Boom.boomify(err, { statusCode: err.statusCode || 500 });
                if (err.code) {
                    error.output.payload.code = err.code;
                }
                if (err.processPipeline) {
                    error.output.payload.processPipeline = err.processPipeline;
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
                    messages: Joi.array()
                        .items(
                            Joi.object({
                                id: Joi.string().example('AAAAAgAACrI').description('Message ID').label('ChatMessageId'),
                                path: Joi.string().example('INBOX').description('Folder this message was found from').label('ChatMessagePath'),
                                date: Joi.date().iso().example('2023-09-29T10:03:49.000Z').description('Date of the email'),
                                from: addressSchema
                                    .example({ name: 'From Me', address: 'sender@example.com' })
                                    .description('The From address')
                                    .label('FromAddress'),

                                to: Joi.array()
                                    .items(addressSchema)
                                    .single()
                                    .description('List of addresses')
                                    .example([{ address: 'recipient@example.com' }])
                                    .label('AddressList'),
                                subject: Joi.string().allow('').example('What a wonderful message').description('Message subject'),
                                messageSpecialUse: Joi.string()
                                    .example('\\Sent')
                                    .valid('\\Drafts', '\\Junk', '\\Sent', '\\Trash', '\\Inbox')
                                    .description('Special use flag of the message')
                            })
                                .description('Email that best matched the question')
                                .label('ChatResponseMessage')
                        )
                        .description('Emails that best matched the question')
                        .label('ChatResponseMessages')
                }).label('ReturnChatResponse'),
                failAction: 'log'
            }
        }
    });

    server.route({
        method: 'POST',
        path: '/admin/config/document-store/chat/test',
        async handler(request, h) {
            try {
                const esClient = await h.getESClient(request.logger);
                const { index, client } = esClient;

                return await processChatRequest({
                    account: request.payload.account,
                    question: request.payload.question,
                    index,
                    client
                });
            } catch (err) {
                request.logger.error({
                    msg: 'Failed posting request',
                    command: 'info',
                    err
                });
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
                    account: accountIdSchema.required(),
                    question: Joi.string()
                        .trim()
                        .max(1024)
                        .example('When did Jason last message me?')
                        .description('Chat message to use')
                        .label('ChatMessage')
                        .required()
                })
            }
        }
    });
}

module.exports = init;
