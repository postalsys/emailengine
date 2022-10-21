'use strict';
const { parentPort } = require('worker_threads');

const packageData = require('../package.json');
const config = require('wild-config');
const logger = require('../lib/logger');

const { REDIS_PREFIX } = require('../lib/consts');

const { getDuration, getBoolean, emitChangeEvent, readEnvValue, hasEnvValue } = require('../lib/tools');

const Bugsnag = require('@bugsnag/js');
if (readEnvValue('BUGSNAG_API_KEY')) {
    Bugsnag.start({
        apiKey: readEnvValue('BUGSNAG_API_KEY'),
        appVersion: packageData.version,
        logger: {
            debug(...args) {
                logger.debug({ msg: args.shift(), worker: 'imap', source: 'bugsnag', args: args.length ? args : undefined });
            },
            info(...args) {
                logger.debug({ msg: args.shift(), worker: 'imap', source: 'bugsnag', args: args.length ? args : undefined });
            },
            warn(...args) {
                logger.warn({ msg: args.shift(), worker: 'imap', source: 'bugsnag', args: args.length ? args : undefined });
            },
            error(...args) {
                logger.error({ msg: args.shift(), worker: 'imap', source: 'bugsnag', args: args.length ? args : undefined });
            }
        }
    });
}

const { Connection } = require('../lib/connection');
const { Account } = require('../lib/account');
const { redis, notifyQueue, submitQueue, documentsQueue, getFlowProducer } = require('../lib/db');
const { MessagePortWritable } = require('../lib/message-port-stream');
const { getESClient } = require('../lib/document-store');
const settings = require('../lib/settings');
const msgpack = require('msgpack5')();

const getSecret = require('../lib/get-secret');

const flowProducer = getFlowProducer();

config.service = config.service || {};

config.log = config.log || {
    raw: false
};

const EENGINE_LOG_RAW = hasEnvValue('EENGINE_LOG_RAW') ? getBoolean(readEnvValue('EENGINE_LOG_RAW')) : getBoolean(config.log.raw);
const DEFAULT_EENGINE_TIMEOUT = 10 * 1000;
const EENGINE_TIMEOUT = getDuration(readEnvValue('EENGINE_TIMEOUT') || config.service.commandTimeout) || DEFAULT_EENGINE_TIMEOUT;

const DEFAULT_STATES = {
    init: 0,
    connected: 0,
    connecting: 0,
    authenticationError: 0,
    connectError: 0,
    unset: 0,
    disconnected: 0
};

const NO_ACTIVE_HANDLER_RESP = {
    error: 'No active handler for requested account. Try again later.',
    statusCode: 503
};

class ConnectionHandler {
    constructor() {
        this.callQueue = new Map();
        this.mids = 0;

        this.accounts = new Map();
    }

    async init() {
        // indicate that we are ready to process connections
        parentPort.postMessage({ cmd: 'ready' });
    }

    getLogKey(account) {
        // this format ensures that the key is deleted when user is removed
        return `${REDIS_PREFIX}iam:${account}:g`;
    }

    async getAccountLogger(account) {
        let logKey = this.getLogKey(account);
        let logging = await settings.getLoggingInfo(account);

        return {
            enabled: logging.enabled,
            maxLogLines: logging.maxLogLines,
            log(entry) {
                if (!this.maxLogLines || !this.enabled) {
                    return;
                }

                let logRow = msgpack.encode(entry);
                redis
                    .multi()
                    .rpush(logKey, logRow)
                    .ltrim(logKey, -this.maxLogLines, -1)
                    .exec()
                    .catch(err => this.logger.error({ msg: 'Failed to update log entries', account, err }));
            },
            async reload() {
                logging = await settings.getLoggingInfo(account);
                this.enabled = logging.enabled;
                this.maxLogLines = logging.maxLogLines;
            }
        };
    }

    async assignConnection(account) {
        logger.info({ msg: 'Assigned account to worker', account });

        let accountLogger = await this.getAccountLogger(account);
        let secret = await getSecret();
        let accountObject = new Account({
            redis,
            account,
            secret,
            esClient: await getESClient(logger)
        });

        this.accounts.set(account, accountObject);
        accountObject.connection = new Connection({
            account,
            accountObject,
            redis,
            secret,
            notifyQueue,
            submitQueue,
            documentsQueue,
            flowProducer,
            accountLogger,
            logRaw: EENGINE_LOG_RAW
        });
        accountObject.logger = accountObject.connection.logger;

        let accountData = await accountObject.loadAccountData();

        if (accountData.state) {
            await redis.hSetExists(accountObject.connection.getAccountKey(), 'state', accountData.state);
            await emitChangeEvent(this.logger, account, 'state', accountData.state);
        }

        // do not wait before returning as it may take forever
        accountObject.connection.init().catch(err => {
            logger.error({ account, err });
        });
    }

    async deleteConnection(account) {
        logger.info({ msg: 'Deleting connection', account });
        if (this.accounts.has(account)) {
            let accountObject = this.accounts.get(account);
            if (accountObject.connection) {
                await accountObject.connection.delete();
            }
            this.accounts.delete(account);
        }
    }

    async updateConnection(account) {
        logger.info({ msg: 'Account reconnect requested', account });
        if (this.accounts.has(account)) {
            let accountObject = this.accounts.get(account);
            if (accountObject.connection) {
                accountObject.connection.accountLogger.log({
                    level: 'info',
                    t: Date.now(),
                    cid: accountObject.connection.cid,
                    msg: 'Account reconnect requested'
                });

                let state = 'connecting';
                await redis.hSetExists(accountObject.connection.getAccountKey(), 'state', state);
                accountObject.connection.state = state;
                await emitChangeEvent(this.logger, account, 'state', state);
                await accountObject.connection.reconnect(true);
            }
        }
    }

    async syncConnection(account) {
        logger.info({ msg: 'Account sync requested', account });
        if (this.accounts.has(account)) {
            let accountObject = this.accounts.get(account);
            if (accountObject.connection) {
                accountObject.connection.accountLogger.log({
                    level: 'info',
                    t: Date.now(),
                    cid: accountObject.connection.cid,
                    msg: 'Account sync requested'
                });

                await accountObject.connection.syncMailboxes();

                return true;
            }
        }
    }

    async listMessages(message) {
        if (!this.accounts.has(message.account)) {
            return NO_ACTIVE_HANDLER_RESP;
        }

        let accountData = this.accounts.get(message.account);
        if (!accountData.connection) {
            return NO_ACTIVE_HANDLER_RESP;
        }

        return await accountData.connection.listMessages(message);
    }

    async getText(message) {
        if (!this.accounts.has(message.account)) {
            return NO_ACTIVE_HANDLER_RESP;
        }

        let accountData = this.accounts.get(message.account);
        if (!accountData.connection) {
            return NO_ACTIVE_HANDLER_RESP;
        }

        return await accountData.connection.getText(message.text, message.options);
    }

    async getMessage(message) {
        if (!this.accounts.has(message.account)) {
            return NO_ACTIVE_HANDLER_RESP;
        }

        let accountData = this.accounts.get(message.account);
        if (!accountData.connection) {
            return NO_ACTIVE_HANDLER_RESP;
        }

        return await accountData.connection.getMessage(message.message, message.options);
    }

    async updateMessage(message) {
        if (!this.accounts.has(message.account)) {
            return NO_ACTIVE_HANDLER_RESP;
        }

        let accountData = this.accounts.get(message.account);
        if (!accountData.connection) {
            return NO_ACTIVE_HANDLER_RESP;
        }

        return await accountData.connection.updateMessage(message.message, message.updates);
    }

    async updateMessages(message) {
        if (!this.accounts.has(message.account)) {
            return NO_ACTIVE_HANDLER_RESP;
        }

        let accountData = this.accounts.get(message.account);
        if (!accountData.connection) {
            return NO_ACTIVE_HANDLER_RESP;
        }
        return await accountData.connection.updateMessages(message.path, message.search, message.updates);
    }

    async listMailboxes(message) {
        if (!this.accounts.has(message.account)) {
            return NO_ACTIVE_HANDLER_RESP;
        }

        let accountData = this.accounts.get(message.account);
        if (!accountData.connection) {
            return NO_ACTIVE_HANDLER_RESP;
        }

        return await accountData.connection.listMailboxes(message.options);
    }

    async moveMessage(message) {
        if (!this.accounts.has(message.account)) {
            return NO_ACTIVE_HANDLER_RESP;
        }

        let accountData = this.accounts.get(message.account);
        if (!accountData.connection) {
            return NO_ACTIVE_HANDLER_RESP;
        }

        return await accountData.connection.moveMessage(message.message, message.target);
    }

    async moveMessages(message) {
        if (!this.accounts.has(message.account)) {
            return NO_ACTIVE_HANDLER_RESP;
        }

        let accountData = this.accounts.get(message.account);
        if (!accountData.connection) {
            return NO_ACTIVE_HANDLER_RESP;
        }

        return await accountData.connection.moveMessages(message.source, message.search, message.target);
    }

    async deleteMessage(message) {
        if (!this.accounts.has(message.account)) {
            return NO_ACTIVE_HANDLER_RESP;
        }

        let accountData = this.accounts.get(message.account);
        if (!accountData.connection) {
            return NO_ACTIVE_HANDLER_RESP;
        }

        return await accountData.connection.deleteMessage(message.message, message.force);
    }

    async deleteMessages(message) {
        if (!this.accounts.has(message.account)) {
            return NO_ACTIVE_HANDLER_RESP;
        }

        let accountData = this.accounts.get(message.account);
        if (!accountData.connection) {
            return NO_ACTIVE_HANDLER_RESP;
        }

        return await accountData.connection.deleteMessages(message.path, message.search, message.force);
    }

    async submitMessage(message) {
        if (!this.accounts.has(message.account)) {
            return NO_ACTIVE_HANDLER_RESP;
        }

        let accountData = this.accounts.get(message.account);
        if (!accountData.connection) {
            return NO_ACTIVE_HANDLER_RESP;
        }

        return await accountData.connection.submitMessage(message.data);
    }

    async queueMessage(message) {
        if (!this.accounts.has(message.account)) {
            return NO_ACTIVE_HANDLER_RESP;
        }

        const accountData = this.accounts.get(message.account);
        if (!accountData.connection) {
            return NO_ACTIVE_HANDLER_RESP;
        }

        return await accountData.connection.queueMessage(message.data, message.meta);
    }

    async uploadMessage(message) {
        if (!this.accounts.has(message.account)) {
            return NO_ACTIVE_HANDLER_RESP;
        }

        let accountData = this.accounts.get(message.account);
        if (!accountData.connection) {
            return NO_ACTIVE_HANDLER_RESP;
        }

        return await accountData.connection.uploadMessage(message.data);
    }

    async createMailbox(message) {
        if (!this.accounts.has(message.account)) {
            return NO_ACTIVE_HANDLER_RESP;
        }

        let accountData = this.accounts.get(message.account);
        if (!accountData.connection) {
            return NO_ACTIVE_HANDLER_RESP;
        }

        return await accountData.connection.createMailbox(message.path);
    }

    async deleteMailbox(message) {
        if (!this.accounts.has(message.account)) {
            return NO_ACTIVE_HANDLER_RESP;
        }

        let accountData = this.accounts.get(message.account);
        if (!accountData.connection) {
            return NO_ACTIVE_HANDLER_RESP;
        }
        return await accountData.connection.deleteMailbox(message.path);
    }

    async getRawMessage(message) {
        if (!this.accounts.has(message.account)) {
            return NO_ACTIVE_HANDLER_RESP;
        }

        let accountData = this.accounts.get(message.account);
        if (!accountData.connection) {
            return NO_ACTIVE_HANDLER_RESP;
        }
        let stream = new MessagePortWritable(message.port);

        let source = await accountData.connection.getRawMessage(message.message);
        if (!source) {
            let err = new Error('Requested file not found');
            err.statusCode = 404;
            throw err;
        }

        setImmediate(() => {
            source.pipe(stream);
        });

        return {
            headers: source.headers,
            contentType: source.contentType
        };
    }

    async getAttachment(message) {
        if (!this.accounts.has(message.account)) {
            return NO_ACTIVE_HANDLER_RESP;
        }

        let accountData = this.accounts.get(message.account);
        if (!accountData.connection) {
            return NO_ACTIVE_HANDLER_RESP;
        }

        let stream = new MessagePortWritable(message.port);

        let source = await accountData.connection.getAttachment(message.attachment);
        if (!source) {
            let err = new Error('Requested file not found');
            err.statusCode = 404;
            throw err;
        }

        setImmediate(() => {
            source.pipe(stream);
        });

        return {
            headers: source.headers,
            contentType: source.contentType
        };
    }

    async kill() {
        if (this.killed) {
            return;
        }
        logger.error({ msg: 'Terminating process' });
        this.killed = true;

        this.accounts.forEach(account => {
            if (account.connection) {
                account.connection.close();
            }
        });

        process.exit(0);
    }

    // some general message
    async onMessage(message) {
        /*
        let dataview = new DataView(message);
        dataview.setUint8(Number(threadId), Number(threadId));
        */

        switch (message.cmd) {
            case 'settings':
                if (message.data && message.data.logs) {
                    for (let [account, accountObject] of this.accounts) {
                        // update log handling
                        let logging = await settings.getLoggingInfo(account, message.data.logs);
                        if (accountObject.connection) {
                            accountObject.connection.accountLogger.maxLogLines = logging.maxLogLines;
                            accountObject.connection.accountLogger.enabled = logging.enabled;
                            accountObject.connection.emitLogs = logging.enabled;
                            if (accountObject.connection.imapClient) {
                                accountObject.connection.imapClient.emitLogs = logging.enabled;
                            }
                        }
                        if (!logging.enabled) {
                            await redis.del(this.getLogKey(account));
                        }
                    }
                }
                return;
        }

        logger.debug({ msg: 'Unhandled message', message });
    }

    // message that expects a response
    async onCommand(message) {
        switch (message.cmd) {
            case 'assign':
                return await this.assignConnection(message.account);

            case 'delete':
                return await this.deleteConnection(message.account);

            case 'update':
                return await this.updateConnection(message.account);

            case 'sync':
                return await this.syncConnection(message.account);

            case 'listMessages':
                return await this.listMessages(message);

            case 'getText':
                return await this.getText(message);

            case 'getMessage':
                return await this.getMessage(message);

            case 'updateMessage':
                return await this.updateMessage(message);

            case 'updateMessages':
                return await this.updateMessages(message);

            case 'listMailboxes':
                return await this.listMailboxes(message);

            case 'moveMessage':
                return await this.moveMessage(message);

            case 'moveMessages':
                return await this.moveMessages(message);

            case 'deleteMessage':
                return await this.deleteMessage(message);

            case 'deleteMessages':
                return await this.deleteMessages(message);

            case 'getRawMessage':
                return await this.getRawMessage(message);

            case 'createMailbox':
                return await this.createMailbox(message);

            case 'deleteMailbox':
                return await this.deleteMailbox(message);

            case 'getAttachment':
                return await this.getAttachment(message);

            case 'submitMessage':
                return await this.submitMessage(message);

            case 'queueMessage':
                return await this.queueMessage(message);

            case 'uploadMessage':
                return await this.uploadMessage(message);

            case 'countConnections': {
                let results = Object.assign({}, DEFAULT_STATES);

                let count = status => {
                    if (!results[status]) {
                        results[status] = 0;
                    }
                    results[status] += 1;
                };

                this.accounts.forEach(accountObject => {
                    let state;

                    if (!accountObject || !accountObject.connection) {
                        state = 'unassigned';
                    } else {
                        state = accountObject.connection.currentState();
                    }

                    return count(state);
                });

                return results;
            }

            default:
                return false;
        }
    }

    async call(message) {
        return new Promise((resolve, reject) => {
            let mid = `${Date.now()}:${++this.mids}`;

            let ttl = Math.max(message.timeout || 0, EENGINE_TIMEOUT || 0);
            let timer = setTimeout(() => {
                let err = new Error('Timeout waiting for command response [T3]');
                err.statusCode = 504;
                err.code = 'Timeout';
                err.ttl = ttl;
                reject(err);
            }, ttl);

            this.callQueue.set(mid, { resolve, reject, timer });
            parentPort.postMessage({
                cmd: 'call',
                mid,
                message
            });
        });
    }

    metrics(key, method, ...args) {
        parentPort.postMessage({
            cmd: 'metrics',
            key,
            method,
            args
        });
    }
}

let connectionHandler = new ConnectionHandler();

async function main() {
    logger.info({ msg: 'Started IMAP worker thread', version: packageData.version });
    await connectionHandler.init();
}

parentPort.on('message', message => {
    if (message && message.cmd === 'resp' && message.mid && connectionHandler.callQueue.has(message.mid)) {
        let { resolve, reject, timer } = connectionHandler.callQueue.get(message.mid);
        clearTimeout(timer);
        connectionHandler.callQueue.delete(message.mid);
        if (message.error) {
            let err = new Error(message.error);
            if (message.code) {
                err.code = message.code;
            }
            if (message.statusCode) {
                err.statusCode = message.statusCode;
            }
            return reject(err);
        } else {
            return resolve(message.response);
        }
    }

    if (message && message.cmd === 'call' && message.mid) {
        return connectionHandler
            .onCommand(message.message)
            .then(response => {
                parentPort.postMessage({
                    cmd: 'resp',
                    mid: message.mid,
                    response
                });
            })
            .catch(err => {
                if (message.message && message.message.data && message.message.data.raw) {
                    message.message.data.raw = message.message.data.raw.length;
                }
                logger.error(Object.assign({ msg: 'Command failed' }, message, { err }));
                parentPort.postMessage({
                    cmd: 'resp',
                    mid: message.mid,
                    error: err.message,
                    code: err.code,
                    statusCode: err.statusCode,
                    info: err.info
                });
            });
    }

    connectionHandler.onMessage(message).catch(err => logger.error({ msg: 'Failed to process IPC message', err }));
});

process.on('SIGTERM', () => {
    connectionHandler.kill().catch(err => {
        logger.error({ msg: 'Execution failed', err });
        process.exit(4);
    });
});

process.on('SIGINT', () => {
    connectionHandler.kill().catch(err => {
        logger.error({ msg: 'Execution failed', err });
        process.exit(5);
    });
});

main().catch(err => {
    logger.error({ msg: 'Execution failed', err });
    setImmediate(() => process.exit(6));
});
