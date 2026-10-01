'use strict';

const { redis } = require('./db');
const msgpack = require('./msgpack');
const logger = require('./logger');
const { REDIS_PREFIX } = require('./consts');
const settings = require('./settings');
const { SubScript } = require('./sub-script');

// The last OpenAI failure, shown on the AI configuration page until a summary succeeds again
const OPENAI_ERROR_KEY = `${REDIS_PREFIX}:openai:error`;

class LLMPreProcessHandler {
    constructor(options) {
        this.options = options || {};
        this.redis = this.options.redis;

        this.handlerCache = null;
        this.handlerCacheV = 0;
    }

    getPreProcessLogKey() {
        return `${REDIS_PREFIX}llmpp:l`;
    }

    async getHandler() {
        const { generateEmailSummary, openAiAPIKey, openAiPreProcessingFn } = await settings.getMulti(
            'generateEmailSummary',
            'openAiAPIKey',
            'openAiPreProcessingFn'
        );

        if (!generateEmailSummary || !openAiAPIKey) {
            return null;
        }

        let compiledFn;
        try {
            compiledFn = openAiPreProcessingFn ? SubScript.create(`llm-pre-process:filter`, openAiPreProcessingFn) : false;
        } catch (err) {
            await this.storeLog('filter', null, err.stack);

            logger.error({ msg: 'Failed to compile LLM pre-processing script', component: 'llm-pre-process', type: 'filter', err });
            compiledFn = null;
        }

        if (!compiledFn) {
            return null;
        }

        return {
            filterFn: async payload => {
                try {
                    return await compiledFn.exec(payload);
                } catch (err) {
                    await this.storeLog('filter', payload, err.stack);
                    logger.error({ msg: 'Failed to execute LLM pre-processing script', component: 'llm-pre-process', type: 'filter', err });
                    return null;
                }
            }
        };
    }

    async getPreProcessHandler() {
        let v = await this.redis.hget(`${REDIS_PREFIX}settings`, 'openAiSettingsVersion');
        v = Number(v) || 0;
        if (v !== this.handlerCacheV) {
            // changes detected
            this.handlerCache = await this.getHandler();
            // mark the cache as current only after a successful rebuild, so a failure above
            // leaves it stale and the next call retries
            this.handlerCacheV = v;
        }
        return this.handlerCache;
    }

    async storeLog(type, payload, error) {
        const maxLogLines = 20;

        let logRow = msgpack.encode({
            type,
            payload,
            error,
            created: new Date().toISOString()
        });

        try {
            await redis.multi().rpush(this.getPreProcessLogKey(), logRow).ltrim(this.getPreProcessLogKey(), -maxLogLines, -1).exec();
        } catch (err) {
            logger.error({ msg: 'Failed to insert error log entries', component: 'llm-pre-process', err });
        }
    }

    async getErrorLog() {
        let logLines = await redis.lrangeBuffer(this.getPreProcessLogKey(), 0, -1);
        if (!Array.isArray(logLines)) {
            logLines = [].concat(logLines || []);
        }

        let logEntries = [];

        for (let line of logLines) {
            try {
                let entry = msgpack.decode(line);
                logEntries.unshift(entry);
            } catch (err) {
                logger.error({ msg: 'Failed to decode log line', component: 'llm-pre-process', entry: line && line.toString('base64'), err });
            }
        }

        return logEntries;
    }

    /**
     * Decides whether a message goes to the LLM: summaries have to be on, a key has to be set and
     * the operator's filter script has to accept the message. The script sees a copy, so it cannot
     * change what is announced
     * @param {Object} messageData - The message as the webhook would carry it
     * @returns {Promise<boolean>} True when the message should be summarized
     */
    async run(messageData) {
        let preProcessHandler = await this.getPreProcessHandler();
        if (!preProcessHandler) {
            return false;
        }

        return !!(await preProcessHandler.filterFn(structuredClone(messageData)));
    }

    /**
     * Asks the main thread for the OpenAI summary of a message and attaches it to the message in
     * place, with the risk assessment the model returns alongside moved to its own field. A
     * failure is recorded for the AI configuration page and leaves the message unenriched
     * @param {Object} messageData - Formatted message with its text parts, updated in place
     * @param {Object} env - Where the message lives
     * @param {Function} env.call - RPC to the main thread
     * @param {Object} env.redis - The connection's Redis client
     * @param {string} env.account - Account ID
     * @param {Object} env.logger - Account-scoped logger
     */
    async summarize(messageData, { call, redis: client, account, logger: log }) {
        try {
            let summary = await call({
                cmd: 'generateSummary',
                data: {
                    message: {
                        headers: Object.keys(messageData.headers || {}).map(key => ({ key, value: [].concat(messageData.headers[key] || []) })),
                        attachments: messageData.attachments,
                        from: messageData.from,
                        subject: messageData.subject,
                        text: messageData.text.plain,
                        html: messageData.text.html
                    },
                    account
                },
                timeout: 2 * 60 * 1000
            });

            if (summary) {
                for (let key of Object.keys(summary)) {
                    // remove meta keys from output
                    if (key.charAt(0) === '_' || summary[key] === '') {
                        delete summary[key];
                    }
                    if (key === 'riskAssessment') {
                        messageData.riskAssessment = summary.riskAssessment;
                        delete summary.riskAssessment;
                    }
                }
                messageData.summary = summary;

                log.trace({ msg: 'Fetched summary from OpenAI', summary });
            }

            await client.del(OPENAI_ERROR_KEY);
        } catch (err) {
            await client.set(
                OPENAI_ERROR_KEY,
                JSON.stringify({
                    message: err.message,
                    code: err.code,
                    statusCode: err.statusCode,
                    created: Date.now()
                })
            );
            log.error({ msg: 'Failed to fetch summary from OpenAI', err });
        }
    }
}

module.exports.llmPreProcess = new LLMPreProcessHandler({ redis });
