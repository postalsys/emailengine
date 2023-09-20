'use strict';

const { redis } = require('./db');
const msgpack = require('msgpack5')();
const logger = require('./logger');
const { REDIS_PREFIX } = require('./consts');
const settings = require('./settings');
const { SubScript } = require('./sub-script');

let pfStructuredClone = typeof structuredClone === 'function' ? structuredClone : data => JSON.parse(JSON.stringify(data));

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
        let preProcessData = {
            generateEmailSummary: (await settings.get(`generateEmailSummary`)) || false,
            generateEmbeddings: (await settings.get(`openAiGenerateEmbeddings`)) || false,
            apiKey: (await settings.get(`openAiAPIKey`)) || false,
            contentFn: await settings.get(`openAiPreProcessingFn`)
        };

        if ((!preProcessData.generateEmailSummary && !preProcessData.generateEmbeddings) || !preProcessData.apiKey) {
            return null;
        }

        try {
            if (preProcessData.contentFn) {
                preProcessData.compiledFn = SubScript.create(`llm-pre-process:filter`, preProcessData.contentFn);
            } else {
                preProcessData.compiledFn = false;
            }
        } catch (err) {
            await this.storeLog('filter', null, err.stack);

            logger.error({ msg: 'Compilation failed', type: 'filter', err });
            preProcessData.compiledFn = null;
        }

        if (!preProcessData.compiledFn) {
            return null;
        }

        preProcessData.filterFn = async payload => {
            try {
                return await preProcessData.compiledFn.exec(payload);
            } catch (err) {
                await this.storeLog('filter', payload, err.stack);
                logger.error({ msg: 'Exec failed', type: 'filter', err });
                return null;
            }
        };

        return preProcessData;
    }

    async getPreProcessHandler() {
        let v = await this.redis.hget(`${REDIS_PREFIX}settings`, 'openAiSettingsVersion');
        v = Number(v) || 0;
        if (v !== this.handlerCacheV) {
            // changes detected
            this.handlerCache = this.getHandler();
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
            logger.error({ msg: 'Failed to insert error log entries', err });
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
                logger.error({ msg: 'Failed to retrieve log line', entry: line && line.toString('base64') });
            }
        }

        return logEntries;
    }

    async run(originalPayload) {
        let preProcessHandler = await this.getPreProcessHandler();

        if (!preProcessHandler || !preProcessHandler.filterFn) {
            return false;
        }

        let canUse;
        let payload = pfStructuredClone(originalPayload);

        try {
            canUse = await preProcessHandler.filterFn(payload);
        } catch (err) {
            await this.storeLog('filter', payload, err.stack);

            logger.error({ msg: 'Exec failed', type: 'filter', err });
        }

        if (canUse && payload) {
            return {
                generateEmailSummary: preProcessHandler.generateEmailSummary,
                generateEmbeddings: preProcessHandler.generateEmbeddings
            };
        }

        return false;
    }
}

module.exports.llmPreProcess = new LLMPreProcessHandler({ redis });
