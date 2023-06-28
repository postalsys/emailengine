'use strict';

const { redis } = require('./db');
const msgpack = require('msgpack5')();
const logger = require('./logger');
const { REDIS_PREFIX } = require('./consts');
const settings = require('./settings');
const { SubScript } = require('./sub-script');

let pfStructuredClone = typeof structuredClone === 'function' ? structuredClone : data => JSON.parse(JSON.stringify(data));

class PreProcessHandler {
    constructor(options) {
        this.options = options || {};
        this.redis = this.options.redis;

        this.handlerCache = null;
        this.handlerCacheV = 0;
    }

    getPreProcessLogKey() {
        return `${REDIS_PREFIX}dspp:l`;
    }

    async getHandler() {
        let preProcessData = {
            enabled: (await settings.get(`documentStorePreProcessingEnabled`)) || false,
            contentFn: await settings.get(`documentStorePreProcessingFn`),
            contentMap: await settings.get(`documentStorePreProcessingMap`)
        };

        if (!preProcessData.enabled) {
            return null;
        }

        try {
            if (preProcessData.contentFn) {
                preProcessData.compiledFn = SubScript.create(`pre-process:filter`, preProcessData.contentFn);
            } else {
                preProcessData.compiledFn = false;
            }
        } catch (err) {
            await this.storeLog('filter', null, err.stack);

            logger.error({ msg: 'Compilation failed', type: 'filter', err });
            preProcessData.compiledFn = null;
            preProcessData.compiledMap = null;
        }

        if (preProcessData.compiledFn) {
            try {
                if (preProcessData.contentMap) {
                    preProcessData.compiledMap = SubScript.create(`pre-process:map`, preProcessData.contentMap);
                } else {
                    preProcessData.contentMap = false;
                }
            } catch (err) {
                await this.storeLog('map', null, err.stack);

                logger.error({ msg: 'Compilation failed', type: 'map', err });
                preProcessData.compiledFn = null;
                preProcessData.compiledMap = null;
            }
        }

        if (preProcessData.compiledFn) {
            preProcessData.filterFn = async payload => {
                try {
                    return await preProcessData.compiledFn.exec(payload);
                } catch (err) {
                    await this.storeLog('filter', payload, err.stack);
                    logger.error({ msg: 'Exec failed', type: 'filter', err });
                    return null;
                }
            };
        }

        if (preProcessData.compiledMap) {
            preProcessData.mapFn = async payload => {
                try {
                    return preProcessData.compiledMap.exec(payload);
                } catch (err) {
                    await this.storeLog('map', payload, err.stack);
                    logger.error({ msg: 'Exec failed', type: 'map', err });
                    return null;
                }
            };
        }

        return preProcessData;
    }

    async getPreProcessHandler() {
        let v = await this.redis.hget(`${REDIS_PREFIX}settings`, 'documentStoreVersion');
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
        // custom webhoom routes
        let preProcessHandler = await this.getPreProcessHandler();

        if (!preProcessHandler || !preProcessHandler.enabled) {
            return originalPayload;
        }

        if (!preProcessHandler.filterFn) {
            return false;
        }

        let canStore;
        let payload = pfStructuredClone(originalPayload);

        try {
            canStore = await preProcessHandler.filterFn(payload);
        } catch (err) {
            await this.storeLog('filter', payload, err.stack);

            logger.error({ msg: 'Exec failed', type: 'filter', err });
        }

        if (canStore) {
            if (preProcessHandler.mapFn) {
                try {
                    payload = await preProcessHandler.mapFn(payload);
                    if (payload) {
                        if (typeof payload !== 'object') {
                            throw new Error(`Invalid document type. Must be object, got ${typeof payload}`);
                        }
                        // make sure important fields are not touched
                        for (let key of ['id', 'account', 'path', 'uid', 'specialUse', 'messageId']) {
                            if (key in originalPayload && originalPayload[key] !== payload[key]) {
                                payload[key] = originalPayload[key];
                            }
                        }
                    }
                } catch (err) {
                    await this.storeLog('map', payload, err.stack);

                    logger.error({ msg: 'Exec failed', type: 'map', err });
                    canStore = false;
                }
            }
        }

        if (canStore && payload) {
            return payload;
        }

        return false;
    }
}

module.exports.preProcess = new PreProcessHandler({ redis });
