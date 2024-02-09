'use strict';
const { parentPort } = require('worker_threads');

const packageData = require('../package.json');
const config = require('wild-config');
const logger = require('../lib/logger');

const { REDIS_PREFIX } = require('../lib/consts');

const { getDuration, getBoolean, emitChangeEvent, readEnvValue, hasEnvValue, threadStats } = require('../lib/tools');

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
    logger.notifyError = Bugsnag.notify.bind(Bugsnag);
}

const { Connection } = require('../lib/connection');
const { GmailClient } = require('../lib/api-client/gmail-client');
const { Account } = require('../lib/account');
const { oauth2Apps } = require('../lib/oauth2-apps');
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
    statusCode: 503,
    code: 'WorkerNotAvailable'
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

                if (entry.err && entry.err.cert) {
                    delete entry.err.cert;
                }

                let logRow;
                try {
                    logRow = msgpack.encode(entry);
                    redis
                        .multi()
                        .rpush(logKey, logRow)
                        .ltrim(logKey, -this.maxLogLines, -1)
                        .exec()
                        .catch(err => this.logger.error({ msg: 'Failed to update log entries', account, err }));
                } catch (err) {
                    this.logger.error({ msg: 'Failed to encode log entry', account, entry, err });
                }
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

        const accountData = await accountObject.loadAccountData();

        if (accountData.oauth2 && accountData.oauth2.auth) {
            const oauth2App = await oauth2Apps.get(accountData.oauth2.provider);
            if (oauth2App.baseScopes === 'api') {
                // Use API instead of IMAP
                accountObject.connection = new GmailClient(account, {
                    redis,
                    accountLogger
                });
                accountData.state = 'connected';
            }
        }

        if (!accountObject.connection) {
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
                call: msg => this.call(msg),
                logRaw: EENGINE_LOG_RAW
            });
            accountObject.logger = accountObject.connection.logger;
        }

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

    async pauseConnection(account) {
        logger.info({ msg: 'Account pause requested', account });
        if (this.accounts.has(account)) {
            let accountObject = this.accounts.get(account);
            if (accountObject.connection) {
                accountObject.connection.accountLogger.log({
                    level: 'info',
                    t: Date.now(),
                    cid: accountObject.connection.cid,
                    msg: 'Account pause requested'
                });

                await accountObject.connection.pause();

                return true;
            }
        }
    }

    async resumeConnection(account) {
        logger.info({ msg: 'Account resume requested', account });
        if (this.accounts.has(account)) {
            let accountObject = this.accounts.get(account);
            if (accountObject.connection) {
                accountObject.connection.accountLogger.log({
                    level: 'info',
                    t: Date.now(),
                    cid: accountObject.connection.cid,
                    msg: 'Account resume requested'
                });

                await accountObject.connection.resume();

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

    async subconnections(message) {
        if (!this.accounts.has(message.account)) {
            return [];
        }

        const accountObject = this.accounts.get(message.account);
        if (!accountObject.connection) {
            return [];
        }

        return accountObject.connection.subconnections.map(subconnection => ({
            path: subconnection.path,
            state: subconnection.state
        }));
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

    async getQuota(message) {
        if (!this.accounts.has(message.account)) {
            return NO_ACTIVE_HANDLER_RESP;
        }

        let accountData = this.accounts.get(message.account);
        if (!accountData.connection) {
            return NO_ACTIVE_HANDLER_RESP;
        }

        return await accountData.connection.getQuota();
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

    async renameMailbox(message) {
        if (!this.accounts.has(message.account)) {
            return NO_ACTIVE_HANDLER_RESP;
        }

        let accountData = this.accounts.get(message.account);
        if (!accountData.connection) {
            return NO_ACTIVE_HANDLER_RESP;
        }

        return await accountData.connection.renameMailbox(message.path, message.newPath);
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
            if (Buffer.isBuffer(source.data)) {
                stream.end(source.data);
            } else {
                source.pipe(stream);
            }
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

        this.accounts.forEach(accountObject => {
            if (accountObject && accountObject.connection) {
                accountObject.connection.close();
            }
        });

        logger.flush(() => process.exit());
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
            case 'resource-usage':
                return threadStats.usage();

            case 'assign':
            case 'delete':
            case 'update':
            case 'sync':
            case 'pause':
            case 'resume':
                return await this[`${message.cmd}Connection`](message.account);

            case 'listMessages':
            case 'getText':
            case 'getMessage':
            case 'updateMessage':
            case 'updateMessages':
            case 'listMailboxes':
            case 'moveMessage':
            case 'moveMessages':
            case 'deleteMessage':
            case 'deleteMessages':
            case 'getRawMessage':
            case 'getQuota':
            case 'createMailbox':
            case 'renameMailbox':
            case 'deleteMailbox':
            case 'getAttachment':
            case 'submitMessage':
            case 'queueMessage':
            case 'uploadMessage':
            case 'subconnections':
                return await this[message.cmd](message);

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
        logger.flush(() => process.exit(4));
    });
});

process.on('SIGINT', () => {
    connectionHandler.kill().catch(err => {
        logger.error({ msg: 'Execution failed', err });
        logger.flush(() => process.exit(5));
    });
});

main().catch(err => {
    logger.fatal({ msg: 'Execution failed', err });
    logger.flush(() => process.exit(6));
});
