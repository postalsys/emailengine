'use strict';

const { parentPort } = require('worker_threads');
const crypto = require('crypto');
const logger = require('../logger');
const { webhooks: Webhooks } = require('../webhooks');
const { getESClient } = require('../document-store');
const { getThread } = require('../threads');
const settings = require('../settings');
const msgpack = require('msgpack5')();
const { templates } = require('../templates');
const { Gateway } = require('../gateway');
const os = require('os');
const punycode = require('punycode.js');
const { inlineHtml, inlineText, htmlToText, textToHtml, mimeHtml } = require('@postalsys/email-text-tools');
const { randomUUID: uuid } = require('crypto');
const { addTrackers } = require('../add-trackers');
const { getRawEmail } = require('../get-raw-email');
const { getTemplate } = require('@postalsys/templates');
const { deepEqual } = require('assert');
const { arfDetect } = require('../arf-detect');
const simpleParser = require('mailparser').simpleParser;
const libmime = require('libmime');
const { bounceDetect } = require('../bounce-detect');
const ical = require('ical.js');
const { llmPreProcess } = require('../llm-pre-process');
const { oauth2Apps } = require('../oauth2-apps');
const { Account } = require('../account');
const util = require('util');
const socks = require('socks');
const nodemailer = require('nodemailer');
const { removeBcc } = require('../get-raw-email');
const { oauth2ProviderData } = require('../oauth2-apps');

const {
    getLocalAddress,
    getSignedFormDataSync,
    getServiceSecret,
    convertDataUrisToAttachments,
    genBaseBoundary,
    getDuration,
    getByteSize,
    readEnvValue,
    emitChangeEvent,
    filterEmptyObjectValues,
    resolveCredentials
} = require('../tools');

const {
    AUTH_ERROR_NOTIFY,
    ACCOUNT_INITIALIZED_NOTIFY,
    REDIS_PREFIX,
    MESSAGE_NEW_NOTIFY,
    MESSAGE_DELETED_NOTIFY,
    MESSAGE_UPDATED_NOTIFY,
    EMAIL_BOUNCE_NOTIFY,
    MAILBOX_DELETED_NOTIFY,
    DEFAULT_DELIVERY_ATTEMPTS,
    MIME_BOUNDARY_PREFIX,
    DEFAULT_DOWNLOAD_CHUNK_SIZE,
    EMAIL_COMPLAINT_NOTIFY,
    MAX_INLINE_ATTACHMENT_SIZE,
    DEFAULT_MAX_IMAP_AUTH_FAILURE_TIME,
    TLS_DEFAULTS,
    EMAIL_DELIVERY_ERROR_NOTIFY,
    EMAIL_SENT_NOTIFY
} = require('../consts');

const DOWNLOAD_CHUNK_SIZE = getByteSize(readEnvValue('EENGINE_CHUNK_SIZE')) || DEFAULT_DOWNLOAD_CHUNK_SIZE;

const MAX_IMAP_AUTH_FAILURE_TIME = getDuration(readEnvValue('EENGINE_MAX_IMAP_AUTH_FAILURE_TIME')) || DEFAULT_MAX_IMAP_AUTH_FAILURE_TIME;

async function metricsMeta(meta, logger, key, method, ...args) {
    try {
        parentPort.postMessage({
            cmd: 'metrics',
            key,
            method,
            args,
            meta: meta || {}
        });
    } catch (err) {
        logger.error({ msg: 'Failed to post metrics to parent', err });
    }
}

class BaseClient {
    constructor(account, options) {
        this.account = account;

        this.options = options || {};

        this.cid = this.getRandomId();

        this.runIndex = this.options.runIndex;

        this.accountObject = this.options.accountObject;
        this.accountLogger = this.options.accountLogger;
        this.redis = this.options.redis;

        this.notifyQueue = this.options.notifyQueue;
        this.submitQueue = this.options.submitQueue;
        this.documentsQueue = this.options.documentsQueue;
        this.flowProducer = this.options.flowProducer;

        this.call = this.options.call;

        this.logger = this.getLogger();

        this.secret = this.options.secret;

        this.subconnections = [];
    }

    // stub methods

    async init() {
        return null;
    }

    close() {
        return null;
    }

    async syncMailboxes() {
        return null;
    }

    async delete() {
        return null;
    }

    async resume() {
        return null;
    }

    async reconnect() {
        return null;
    }

    async subconnections() {
        return [];
    }

    async getQuota() {
        return false;
    }

    getRandomId() {
        let rid = BigInt('0x' + crypto.randomBytes(13).toString('hex')).toString(36);
        if (rid.length < 20) {
            rid = '0'.repeat(20 - rid.length) + rid;
        } else if (rid.length > 20) {
            rid = rid.substring(0, 20);
        }
        return rid;
    }

    getAccountKey() {
        return `${REDIS_PREFIX}iad:${this.account}`;
    }

    getMailboxListKey() {
        return `${REDIS_PREFIX}ial:${this.account}`;
    }

    getMailboxHashKey() {
        return `${REDIS_PREFIX}iah:${this.account}`;
    }

    getSeenMessagesKey() {
        return `${REDIS_PREFIX}iar:s:${this.account}`;
    }

    getLogKey() {
        // this format ensures that the key is deleted when user is removed
        return `${REDIS_PREFIX}iam:${this.account}:g`;
    }

    getLoggedAccountsKey() {
        return `${REDIS_PREFIX}iaz:logged`;
    }

    async currentState() {
        return 'connected';
    }

    getLogger() {
        this.mainLogger =
            this.options.logger ||
            logger.child({
                component: 'connection-client',
                account: this.account,
                cid: this.cid
            });

        let syntheticLogger = {};
        let levels = ['trace', 'debug', 'info', 'warn', 'error', 'fatal'];
        for (let level of levels) {
            syntheticLogger[level] = (...args) => {
                this.mainLogger[level](...args);

                if (this.accountLogger.enabled && args && args[0] && typeof args[0] === 'object') {
                    let entry = Object.assign({ level, t: Date.now(), cid: this.cid }, args[0]);
                    if (entry.err && typeof entry.err === 'object') {
                        let err = entry.err;
                        entry.err = {
                            stack: err.stack
                        };
                        // enumerable error fields
                        Object.keys(err).forEach(key => {
                            entry.err[key] = err[key];
                        });
                    }

                    this.accountLogger.log(entry);
                }
            };
        }

        syntheticLogger.child = opts => this.mainLogger.child(opts);

        return syntheticLogger;
    }

    async setStateVal() {
        let [[e1], [e2], [e3, prevVal], [e4, incrVal], [e5, stateVal]] = await this.redis
            .multi()
            .hSetExists(this.getAccountKey(), 'state', this.state)
            .hSetBigger(this.getAccountKey(), 'runIndex', this.runIndex.toString())
            .hget(this.getAccountKey(), `state:count:${this.state}`)
            .hIncrbyExists(this.getAccountKey(), `state:count:${this.state}`, 1)
            .hget(this.getAccountKey(), 'state')
            .exec();

        if (e1 || e2 || e3 || e4 || e5) {
            throw e1 || e2 || e3 || e4 || e5;
        }

        if (stateVal === 'connected' && incrVal === 1 && prevVal === '0') {
            // first connected event!
            await this.notify(false, ACCOUNT_INITIALIZED_NOTIFY, {
                initialized: true
            });
        }
    }

    async setErrorState(event, data) {
        let prevLastErrorState = await this.redis.hget(this.getAccountKey(), 'lastErrorState');
        if (prevLastErrorState) {
            try {
                prevLastErrorState = JSON.parse(prevLastErrorState);
            } catch (err) {
                // ignore
            }
        }

        this.state = event;
        await this.setStateVal();

        let isFirstOccurrence = true;

        await this.redis.hSetExists(this.getAccountKey(), 'lastErrorState', JSON.stringify(data));
        await emitChangeEvent(this.logger, this.account, 'state', event, { error: data });

        if (data && Object.keys(data).length && prevLastErrorState) {
            // we have an error object, let's see if the error hasn't changed

            if (data.serverResponseCode && data.serverResponseCode === prevLastErrorState.serverResponseCode) {
                // error code did not change, assume it is the same error
                isFirstOccurrence = false;
            } else {
                try {
                    deepEqual(data, prevLastErrorState);
                    // nothing changed
                    isFirstOccurrence = false;
                } catch (err) {
                    // seems different
                }
            }
        }

        if (isFirstOccurrence) {
            await this.redis
                .multi()
                .hSetExists(this.getAccountKey(), 'lastError:errorCount', 1)
                .hSetExists(this.getAccountKey(), 'lastError:first', new Date().toISOString())
                .exec();
        } else {
            let errorCount;
            let firstError;

            let [[err1, ec], [err2, fe]] = await this.redis
                .multi()
                .hIncrbyExists(this.getAccountKey(), `lastError:errorCount`, 1)
                .hget(this.getAccountKey(), 'lastError:first')
                .exec();

            if (!err1 && !err2) {
                errorCount = ec || 0;
                if (fe) {
                    fe = new Date(fe);
                    if (fe.toString() !== 'Invalid Date') {
                        firstError = fe;
                    }
                }
            } else {
                this.logger.error({ msg: 'Redis error while checking error state counters', err1, err2 });
            }

            switch (event) {
                case 'authenticationError':
                    if (errorCount > 0 && firstError && Date.now() - firstError.getTime() > MAX_IMAP_AUTH_FAILURE_TIME) {
                        // disable IMAP
                        let imapData;
                        let imapInfo = await this.redis.hget(this.getAccountKey(), 'imap');
                        if (imapInfo) {
                            try {
                                imapData = JSON.parse(imapInfo);
                            } catch (err) {
                                this.logger.error({ msg: 'Failed parsing IMAP data', err });
                            }
                        }
                        if (imapData && !imapData.disabled) {
                            imapData.disabled = true;

                            await this.redis
                                .multi()
                                .hSetExists(this.getAccountKey(), 'imap', JSON.stringify(imapData))
                                .hdel(this.getAccountKey(), 'lastError:errorCount', 'lastError:first')
                                .hSetExists(
                                    this.getAccountKey(),
                                    'lastErrorState',
                                    JSON.stringify({
                                        description: 'IMAP was disabled for the account due to exceeding the authentication error threshold',
                                        response: data.response
                                    })
                                )
                                .exec();

                            this.logger.info({
                                msg: 'IMAP was disabled for the account due to exceeding the authentication error threshold',
                                errorEvent: event,
                                firstError: firstError.toISOString(),
                                timeThreshold: MAX_IMAP_AUTH_FAILURE_TIME,
                                errorCount
                            });

                            setImmediate(() => {
                                this.close();
                            });
                        }
                    }
                    break;
            }
        }

        return isFirstOccurrence;
    }

    async notify(mailbox, event, data, extraOpts) {
        extraOpts = extraOpts || {};
        const { skipWebhook, canSync = true } = extraOpts;

        metricsMeta({ account: this.account }, this.logger, 'events', 'inc', {
            event
        });

        switch (event) {
            case 'connectError':
            case 'authenticationError': {
                let shouldNotify = await this.setErrorState(event, data);

                if (!shouldNotify) {
                    // do not send a webhook as nothing really changed
                    return;
                }
                break;
            }
        }

        let serviceUrl = (await settings.get('serviceUrl')) || null;

        let payload = {
            serviceUrl,
            account: this.account,
            date: new Date().toISOString()
        };

        let path = (mailbox && mailbox.path) || (data && data.path);
        if (path) {
            payload.path = path;
        }

        if (mailbox && mailbox.listingEntry && mailbox.listingEntry.specialUse) {
            payload.specialUse = mailbox.listingEntry.specialUse;
        }

        if (event) {
            payload.event = event;
        }

        if (data) {
            payload.data = data;
        }

        let queueKeep = (await settings.get('queueKeep')) || true;

        let addDocumentQueueJob =
            canSync &&
            this.documentsQueue &&
            [MESSAGE_NEW_NOTIFY, MESSAGE_DELETED_NOTIFY, MESSAGE_UPDATED_NOTIFY, EMAIL_BOUNCE_NOTIFY, MAILBOX_DELETED_NOTIFY].includes(event) &&
            (await settings.get('documentStoreEnabled'));

        if (addDocumentQueueJob && payload.data && event === MESSAGE_NEW_NOTIFY && !payload.data.threadId) {
            // Generate a thread ID for the email. This is also stored in ElasticSearch.
            const { index, client } = await getESClient(logger);
            try {
                if (client) {
                    let thread = await getThread(client, index, this.account, payload.data, logger);
                    if (thread) {
                        payload.data.threadId = thread;
                        logger.info({
                            msg: 'Provisioned thread ID for a message',
                            account: this.account,
                            message: payload.data.id,
                            threadId: payload.data.threadId
                        });
                    }
                }
            } catch (err) {
                if (logger.notifyError) {
                    logger.notifyError(err, event => {
                        event.setUser(this.account);
                        event.addMetadata('ee', {
                            index
                        });
                    });
                }
                logger.error({ msg: 'Failed to resolve thread', account: this.account, message: payload.data.id, err });
            }
        }

        const defaultJobOptions = {
            removeOnComplete: queueKeep,
            removeOnFail: queueKeep,
            attempts: 10,
            backoff: {
                type: 'exponential',
                delay: 5000
            }
        };

        // use more attempts for ElasticSearch updates
        const documentJobOptions = Object.assign(structuredClone(defaultJobOptions), { attempts: 16 });

        if (!skipWebhook && addDocumentQueueJob) {
            // add both jobs as a Flow

            let notifyPayload = await Webhooks.formatPayload(event, payload);

            const queueFlow = [
                {
                    name: event,
                    data: payload,
                    queueName: 'documents'
                }
            ];

            await Webhooks.pushToQueue(event, notifyPayload, {
                routesOnly: true,
                queueFlow
            });

            await this.flowProducer.add(
                {
                    name: event,
                    data: notifyPayload,
                    queueName: 'notify',
                    children: queueFlow
                },
                {
                    queuesOptions: {
                        notify: {
                            defaultJobOptions
                        },
                        documents: {
                            defaultJobOptions: documentJobOptions
                        }
                    }
                }
            );
        } else {
            // add to queues as normal jobs

            if (!skipWebhook) {
                await Webhooks.pushToQueue(event, await Webhooks.formatPayload(event, payload));
            }

            if (addDocumentQueueJob) {
                await this.documentsQueue.add(event, payload, documentJobOptions);
            }
        }
    }

    async loadOAuth2LoginCredentials(accountObject, accountData, ctx, target) {
        const now = Date.now();
        const oauth2User = accountData.oauth2.auth.delegatedUser || accountData.oauth2.auth.user;
        let accessToken;

        const oauth2App = await oauth2Apps.get(accountData.oauth2.provider);
        if (!oauth2App) {
            let error = new Error('Missing or disabled OAuth2 app');
            error.code = 'AppNotFound';
            throw error;
        }

        if (oauth2App.baseScopes && oauth2App.baseScopes !== 'imap') {
            let error = new Error('Invalid base scopes for references OAuth2 application');
            error.code = 'InvalidBaseScopes';
            throw error;
        }

        if (!accountData.oauth2.accessToken || !accountData.oauth2.expires || accountData.oauth2.expires < new Date(now - 30 * 1000)) {
            // renew access token
            try {
                accountData = await accountObject.renewAccessToken({
                    logger: this.logger,
                    logRaw: this.options.logRaw
                });
                accessToken = accountData.oauth2.accessToken;
            } catch (err) {
                err.authenticationFailed = true;
                let notifyData = {
                    response: err.message,
                    serverResponseCode: 'OauthRenewError'
                };
                if (err.tokenRequest) {
                    notifyData.tokenRequest = err.tokenRequest;
                }
                await ctx.notify(false, AUTH_ERROR_NOTIFY, notifyData);
                ctx.logger.error({
                    account: accountObject.account,
                    err
                });
                ctx.state = 'authenticationError';
                throw err;
            }
        } else {
            this.logger.info({
                msg: 'Using cached OAuth2 access token',
                action: 'ensureAccessToken',
                target,
                error: null,
                user: accountData.oauth2.auth.user,
                expires: accountData.oauth2.expires,
                scopes: accountData.oauth2.scope,
                oauth2App: accountData.oauth2.provider
            });
            accessToken = accountData.oauth2.accessToken;
        }
        return { oauth2User, accessToken, oauth2App };
    }

    async getDelegatedAccount(accountData) {
        let redirect = 0;
        let providerAccountData = accountData;
        let delegatedAccountData;
        let seenAccounts = new Set();
        let hopsAllowed = 20;
        while (redirect++ < hopsAllowed) {
            if (!this.delegatedAccountObject || this.delegatedAccountObject.account !== providerAccountData.oauth2.auth.delegatedAccount) {
                this.delegatedAccountObject = new Account({
                    account: accountData.oauth2.auth.delegatedAccount,
                    redis: this.accountObject.redis,
                    call: this.accountObject.call,
                    secret: this.accountObject.secret,
                    timeout: this.accountObject.timeout
                });
            }
            delegatedAccountData = await this.delegatedAccountObject.loadAccountData();
            if (delegatedAccountData.oauth2.auth.delegatedUser && delegatedAccountData.oauth2.auth.delegatedAccount) {
                if (seenAccounts.has(providerAccountData.account)) {
                    // loop detected
                    let error = new Error('Delegation looping detected');
                    throw error;
                }
                seenAccounts.add(providerAccountData.account);
                providerAccountData = delegatedAccountData;
                continue;
            }
            break;
        }

        if (redirect >= hopsAllowed) {
            let error = new Error('Too many delegation hops');
            throw error;
        }

        return delegatedAccountData;
    }

    async loadOAuth2AccountCredentials(accountData, ctx, target) {
        let oauthCredentials;
        if (accountData.oauth2.auth.delegatedUser && accountData.oauth2.auth.delegatedAccount) {
            const delegatedAccountData = await this.getDelegatedAccount(accountData);
            oauthCredentials = await this.loadOAuth2LoginCredentials(this.delegatedAccountObject, delegatedAccountData, ctx, target);
            if (target !== 'smtp') {
                oauthCredentials.oauth2User = accountData.oauth2.auth.delegatedUser || oauthCredentials.oauth2User;
            }
        } else {
            oauthCredentials = await this.loadOAuth2LoginCredentials(this.accountObject, accountData, ctx, target);
            if (accountData.oauth2.auth.delegatedUser && target === 'smtp') {
                // override SMTP username, do not use the shared user
                oauthCredentials.oauth2User = accountData.oauth2.auth.user;
            }
        }

        return oauthCredentials;
    }

    async queueMessage(data, meta, connectionOptions) {
        let accountData = await this.accountObject.loadAccountData();

        let gatewayData;
        let gatewayObject;
        if (data.gateway) {
            gatewayObject = new Gateway({ gateway: data.gateway, redis: this.redis, secret: this.secret });
            try {
                gatewayData = await gatewayObject.loadGatewayData();
            } catch (err) {
                this.logger.info({ msg: 'Failed to load gateway data', messageId: data.messageId, gateway: data.gateway, err });
            }
        }

        if (!accountData.smtp && !accountData.oauth2 && !gatewayData) {
            // can not make connection
            let err = new Error('SMTP configuration not found');
            err.code = 'SMTPUnavailable';
            err.statusCode = 404;
            throw err;
        }

        let licenseInfo = await this.call({ cmd: 'license' });

        // normal message
        data.disableFileAccess = true;
        data.disableUrlAccess = true;
        data.boundaryPrefix = MIME_BOUNDARY_PREFIX;
        data.baseBoundary = genBaseBoundary();

        // convert data uri images to attachments
        convertDataUrisToAttachments(data);

        if (data.template) {
            let templateData = await templates.get(data.template);
            if (!templateData || (templateData.account && templateData.account !== accountData.account)) {
                let err = new Error(`Requested template was not found [${data.template}]`);
                err.code = 'TemplateNotFound';
                err.statusCode = 404;
                throw err;
            }

            if (templateData.content && templateData.content.html && templateData.format) {
                data.render = data.render || {};
                data.render.format = templateData.format;
            }

            for (let key of Object.keys(templateData.content || {})) {
                data[key] = templateData.content[key];
            }

            delete data.template;
        }

        if (!data.mailMerge || !data.mailMerge.length) {
            return this.queueMessageEntry(data, meta, licenseInfo, connectionOptions);
        }

        let mailMergeList = data.mailMerge;
        delete data.mailMerge;
        delete data.messageId;
        delete data.to;

        let messageProcessors = [];

        for (let mailMergeEntry of mailMergeList) {
            let messageCopy = structuredClone(data);
            if (messageCopy.sendAt) {
                // date values do not survive JSON based copying
                messageCopy.sendAt = new Date(messageCopy.sendAt);
            }

            messageCopy.to = [mailMergeEntry.to];

            for (let key of ['messageId', 'sendAt']) {
                if (mailMergeEntry[key]) {
                    messageCopy[key] = mailMergeEntry[key];
                }
            }

            if (mailMergeEntry.params) {
                messageCopy.render = messageCopy.render || {};
                messageCopy.render.params = mailMergeEntry.params;
            }

            messageProcessors.push(this.queueMessageEntry(messageCopy, meta, licenseInfo, connectionOptions));
        }

        let response = {
            mailMerge: []
        };

        let results = await Promise.allSettled(messageProcessors);
        for (let i = 0; i < mailMergeList.length; i++) {
            let mailMergeEntry = mailMergeList[i];
            let resultEntry = results[i];

            let result = Object.assign(
                {
                    success: resultEntry.status === 'fulfilled',
                    to: mailMergeEntry.to
                },
                resultEntry.status === 'fulfilled'
                    ? resultEntry.value.responseValue || {
                          messageId: resultEntry.value.messageId,
                          queueId: resultEntry.value.queueId,
                          sendAt: resultEntry.value.sendAt
                      }
                    : {
                          error: (resultEntry.reason && resultEntry.reason.message) || resultEntry.status,
                          code: (resultEntry.reason && resultEntry.reason.code) || 'SubmitFail',
                          statusCode: (resultEntry.reason && Number(resultEntry.reason.statusCode)) || null
                      }
            );

            response.mailMerge.push(result);
        }

        return response;
    }

    // placeholder
    async checkIMAPConnection() {
        return true;
    }

    async prepareRawMessage(data, options, connectionOptions) {
        options = options || {};

        data.disableFileAccess = true;
        data.disableUrlAccess = true;
        data.boundaryPrefix = MIME_BOUNDARY_PREFIX;
        data.baseBoundary = genBaseBoundary();

        // convert data uri images to attachments
        convertDataUrisToAttachments(data);

        let accountData = await this.accountObject.loadAccountData();

        if (!data.from && data.reference?.action) {
            data.from = {
                name: accountData.name,
                address: accountData.email
            };
        }

        let inlineOptions = {
            locale: data.locale || accountData.locale || (await settings.get('locale')),
            tz: data.tz || accountData.tz || (await settings.get('timezone'))
        };

        delete data.locale;
        delete data.tz;

        let referencedMessage;
        let documentStoreUsed = false;

        // Resolve reference and update reference/in-reply-to headers
        if (data.reference && data.reference.message) {
            if (data.reference.documentStore && (await settings.get('documentStoreEnabled'))) {
                try {
                    referencedMessage = await this.accountObject.getMessage(data.reference.message, {
                        documentStore: true,
                        textType: '*'
                    });
                } catch (err) {
                    if (err.meta && err.meta.statusCode === 404) {
                        // not found
                    } else {
                        let error = new Error('ElasticSearch request failed');
                        error.info = {
                            response: (err.meta && err.meta.body) || err.message,
                            statusCode: err.meta && err.meta.statusCode
                        };
                        error.code = 'ESRequestError';
                        error.statusCode = (err.meta && err.meta.statusCode) || 500;
                        throw error;
                    }
                }
                documentStoreUsed = true;
            } else {
                let extendedData = data.reference.inline || data.reference.forwardAttachments;
                referencedMessage = await this.getMessage(
                    data.reference.message,
                    {
                        fields: !extendedData
                            ? {
                                  uid: true,
                                  flags: true,
                                  envelope: true,
                                  headers: ['references']
                              }
                            : false,
                        header: extendedData ? true : false,
                        textType: extendedData ? '*' : false
                    },
                    connectionOptions
                );
            }

            if (!referencedMessage && !data.reference.ignoreMissing) {
                let err = new Error('Referenced message was not found');
                err.code = 'MessageNotFound';
                err.statusCode = 404;
                throw err;
            }

            if (referencedMessage) {
                if (data.reference.messageId && data.reference.messageId !== referencedMessage.messageId) {
                    let err = new Error('The referenced message was found, but its Message-ID does not match the expected value');
                    err.code = 'MessageNotFound';
                    err.statusCode = 404;
                    throw err;
                }

                let references = []
                    .concat(referencedMessage.messageId || [])
                    .concat(referencedMessage.inReplyTo || [])
                    .concat((referencedMessage.headers && referencedMessage.headers.references) || [])
                    .flatMap(line => line.split(/\s+/))
                    .map(ref => ref.trim())
                    .filter(ref => ref)
                    .map(ref => {
                        if (!/^</.test(ref)) {
                            ref = '<' + ref;
                        }
                        if (!/>$/.test(ref)) {
                            ref = ref + '>';
                        }
                        return ref;
                    });

                references = Array.from(new Set(references));
                if (references.length) {
                    if (!data.headers) {
                        data.headers = {};
                    }
                    data.headers.references = references.join(' ');
                }

                if (['reply', 'reply-all'].includes(data.reference.action) && referencedMessage.messageId) {
                    data.headers['in-reply-to'] = referencedMessage.messageId;
                }

                if (!data.subject && referencedMessage.subject) {
                    let subject = referencedMessage.subject;
                    let prefix;
                    switch (data.reference.action) {
                        case 'reply':
                        case 'reply-all':
                            if (!/^Re:/i.test(subject)) {
                                prefix = 'Re';
                            }
                            break;
                        case 'forward':
                            if (!/^Fwd:/i.test(subject)) {
                                prefix = 'Fwd';
                            }
                            break;
                    }
                    data.subject = `${prefix ? prefix + ': ' : ''}${subject}`;
                }

                let cidAttachments = [];

                if (data.reference.inline) {
                    let inlineMessageData = {
                        text: referencedMessage.text && referencedMessage.text.plain,
                        html: referencedMessage.text && referencedMessage.text.html
                    };

                    for (let key of ['from', 'to', 'cc', 'bcc', 'date', 'subject']) {
                        inlineMessageData[key] = referencedMessage[key];
                    }

                    if (inlineMessageData.html) {
                        if (referencedMessage.attachments) {
                            // find all attachments that are referenced in the HTML
                            for (let attachment of referencedMessage.attachments) {
                                if (attachment.contentId && inlineMessageData.html.indexOf(`cid:${attachment.contentId.replace(/^<|>$/g, '')}`) >= 0) {
                                    cidAttachments.push(attachment);
                                }
                            }
                        }

                        try {
                            let html = data.html;
                            if (!(html || '').toString().trim() && data.text) {
                                html = textToHtml(data.text); // convert text to html
                            }

                            data.html = inlineHtml(data.reference.action, html, inlineMessageData, inlineOptions);
                        } catch (err) {
                            this.logger.error({ msg: 'Failed to generate inline HTML content', err });
                        }
                    }

                    if (data.text) {
                        try {
                            data.text = inlineText(data.reference.action, data.text, inlineMessageData, inlineOptions);
                        } catch (err) {
                            this.logger.error({ msg: 'Failed to generate inline text content', err });
                        }
                    }
                }

                if (!data.to && data.reference.action === 'reply') {
                    data.to =
                        referencedMessage.replyTo && referencedMessage.replyTo.length
                            ? referencedMessage.replyTo
                            : referencedMessage.from
                            ? referencedMessage.from
                            : false;
                }

                if (data.reference.action === 'reply-all') {
                    let envelope = {
                        to: [].concat(
                            referencedMessage.replyTo && referencedMessage.replyTo.length
                                ? referencedMessage.replyTo
                                : referencedMessage.from
                                ? referencedMessage.from
                                : []
                        ),
                        cc: [],
                        bcc: []
                    };

                    let addressesSeen = new Set([].concat(data.from?.address || []).concat(envelope.to.map(addr => addr.address)));
                    for (let rcpt of ['to', 'cc', 'bcc']) {
                        for (let addr of referencedMessage[rcpt] || []) {
                            if (addressesSeen.has(addr.address)) {
                                continue;
                            }
                            addressesSeen.add(addr.address);
                            envelope[rcpt].push(addr);
                        }

                        for (let addr of data[rcpt] || []) {
                            if (addressesSeen.has(addr.address)) {
                                continue;
                            }
                            addressesSeen.add(addr.address);
                            envelope[rcpt].push(addr);
                        }

                        if (envelope[rcpt].length) {
                            data[rcpt] = envelope[rcpt];
                        }
                    }
                }

                let attachmentsToDownload;

                if (
                    data.reference.action === 'forward' &&
                    data.reference.forwardAttachments &&
                    referencedMessage.attachments &&
                    referencedMessage.attachments.length
                ) {
                    // download all
                    attachmentsToDownload = referencedMessage.attachments;
                } else if (cidAttachments.length) {
                    // download referenced attachments
                    attachmentsToDownload = cidAttachments;
                }

                if (attachmentsToDownload && attachmentsToDownload.length) {
                    this.checkIMAPConnection(connectionOptions);

                    this.logger.info({
                        msg: 'Fetching attachments from the referenced email',
                        attachments: attachmentsToDownload.map(a => ({ id: a.id, hasContent: !!a.content }))
                    });

                    // fetch and add attachments to the message
                    if (!data.attachments) {
                        data.attachments = [];
                    }
                    for (let attachment of attachmentsToDownload) {
                        let content;
                        if (attachment.content) {
                            // use local cache
                            content = Buffer.from(attachment.content, 'base64');
                            this.logger.trace({ msg: 'Using cached email content', attachment: attachment.id, size: content.length });
                        } else {
                            // fetch from IMAP
                            content = await this.getAttachmentContent(
                                attachment.id,
                                {
                                    chunkSize: Math.max(DOWNLOAD_CHUNK_SIZE, 2 * 1024 * 1024),
                                    contentOnly: true
                                },
                                connectionOptions
                            );
                        }
                        if (!content) {
                            // skip missing?
                            continue;
                        }
                        data.attachments.push({
                            filename: attachment.filename,
                            content,
                            contentType: attachment.contentType,
                            contentDisposition: attachment.inline ? 'inline' : 'attachment',
                            cid: attachment.contentId || null
                        });
                    }
                }
            }
        }

        // resolve referenced attachments
        for (let attachment of data.attachments || []) {
            if (attachment.reference && !attachment.content) {
                this.checkIMAPConnection(connectionOptions);

                let content = await this.getAttachmentContent(
                    attachment.reference,
                    {
                        chunkSize: Math.max(DOWNLOAD_CHUNK_SIZE, 2 * 1024 * 1024),
                        contentOnly: true
                    },
                    connectionOptions
                );
                if (!content) {
                    let error = new Error('Referenced attachment was not found');
                    error.code = 'ReferenceNotFound';
                    error.statusCode = 404;
                    throw error;
                }

                attachment.content = content;
            }
        }

        data.disableUrlAccess = true;
        data.disableFileAccess = true;
        data.boundaryPrefix = MIME_BOUNDARY_PREFIX;
        data.baseBoundary = genBaseBoundary();
        data.newline = '\r\n';

        if (data.internalDate && !data.date) {
            // Update Date: header as well
            data.date = new Date(data.internalDate);
        }

        let { raw, emailObject, messageId } = await getRawEmail(data, null, options);

        return { raw, emailObject, messageId, documentStoreUsed, referencedMessage };
    }

    async queueMessageEntry(data, meta, licenseInfo, connectionOptions) {
        let accountData = await this.accountObject.loadAccountData();

        // normal message
        data.disableFileAccess = true;
        data.disableUrlAccess = true;
        data.boundaryPrefix = MIME_BOUNDARY_PREFIX;
        data.baseBoundary = genBaseBoundary();

        let baseUrl = data.baseUrl || (await settings.get('serviceUrl')) || null;

        let context = {
            params: (data.render && data.render.params) || {},
            account: {
                name: accountData.name,
                email: accountData.email
            },
            service: {
                url: baseUrl
            }
        };

        if (!data.from) {
            data.from = {
                name: accountData.name,
                address: accountData.email,
                _default: true
            };
        }

        if (baseUrl && data.listId && data.to && data.to.length === 1 && data.to[0].address) {
            // check if not already blocked

            let blockData;

            try {
                blockData = await this.redis.hget(`${REDIS_PREFIX}lists:unsub:entries:${data.listId}`, data.to[0].address.toLowerCase().trim());
                blockData = JSON.parse(blockData);
            } catch (err) {
                blockData = false;
            }

            if (blockData) {
                return {
                    responseValue: {
                        skipped: {
                            reason: blockData.reason,
                            listId: data.listId
                        }
                    }
                };
            }

            if (!data.headers) {
                data.headers = {};
            }

            let baseDomain;
            try {
                baseDomain = (new URL(baseUrl).hostname || '').toLowerCase().trim();
            } catch (err) {
                // ignore error
            }
            baseDomain = baseDomain || (os.hostname() || '').toLowerCase().trim() || 'localhost';

            if (baseDomain) {
                let unsubscribeUrlObj = new URL('/unsubscribe', baseUrl);

                const serviceSecret = await getServiceSecret();

                let fromDomain = ((data.from && data.from.address) || '').split('@').pop().trim().toLowerCase() || baseDomain;
                try {
                    fromDomain = punycode.toASCII(fromDomain);
                } catch (err) {
                    // ignore
                }

                data.headers['List-ID'] = `<${data.listId}.${baseDomain}>`;

                if (!data.messageId) {
                    data.messageId = `<${uuid()}@${fromDomain}>`;
                }

                let { data: signedData, signature } = getSignedFormDataSync(
                    serviceSecret,
                    {
                        act: 'unsub',
                        acc: accountData.account,
                        list: data.listId,
                        rcpt: data.to[0].address,
                        msg: data.messageId
                    },
                    true
                );

                unsubscribeUrlObj.searchParams.append('data', signedData);
                if (signature) {
                    unsubscribeUrlObj.searchParams.append('sig', signature);
                }

                context.rcpt = Object.assign({}, data.to[0], { unsubscribeUrl: unsubscribeUrlObj.href });

                data.headers['List-Unsubscribe'] = `<${context.rcpt.unsubscribeUrl}>`;
                data.headers['List-Unsubscribe-Post'] = 'List-Unsubscribe=One-Click';
            }
        }

        for (let key of ['subject', 'html', 'text', 'previewText']) {
            if (data.render || data.listId) {
                data[key] = this.render(data[key], context, key, data.render && data.render.format);
            }
        }

        delete data.render;

        let inlineOptions = {
            locale: data.locale || accountData.locale || (await settings.get('locale')),
            tz: data.tz || accountData.tz || (await settings.get('timezone'))
        };

        delete data.locale;
        delete data.tz;

        if (data.html && !data.text) {
            try {
                data.text = htmlToText(data.html);
            } catch (err) {
                this.logger.error({ msg: 'Failed to generate plaintext content from html', err });
            }
        }

        let referencedMessage;
        let documentStoreUsed = false;

        // Resolve reference and update reference/in-reply-to headers
        if (data.reference && data.reference.message) {
            if (data.reference.documentStore && (await settings.get('documentStoreEnabled'))) {
                try {
                    referencedMessage = await this.accountObject.getMessage(data.reference.message, {
                        documentStore: true,
                        textType: '*'
                    });
                } catch (err) {
                    if (err.meta && err.meta.statusCode === 404) {
                        // not found
                    } else {
                        let error = new Error('ElasticSearch request failed');
                        error.info = {
                            response: (err.meta && err.meta.body) || err.message,
                            statusCode: err.meta && err.meta.statusCode
                        };
                        error.code = 'ESRequestError';
                        error.statusCode = (err.meta && err.meta.statusCode) || 500;
                        throw error;
                    }
                }
                documentStoreUsed = true;
            } else {
                this.checkIMAPConnection(connectionOptions);

                let extendedData = data.reference.inline || data.reference.forwardAttachments;
                referencedMessage = await this.getMessage(
                    data.reference.message,
                    {
                        fields: !extendedData
                            ? {
                                  uid: true,
                                  flags: true,
                                  envelope: true,
                                  headers: ['references']
                              }
                            : false,
                        header: extendedData ? true : false,
                        textType: extendedData ? '*' : false
                    },
                    connectionOptions
                );
            }

            if (!referencedMessage && !data.reference.ignoreMissing) {
                let error = new Error('Referenced message was not found');
                error.code = 'ReferenceNotFound';
                error.statusCode = 404;
                throw error;
            }

            if (referencedMessage) {
                if (data.reference.messageId && data.reference.messageId !== referencedMessage.messageId) {
                    let err = new Error('The referenced message was found, but its Message-ID does not match the expected value');
                    err.code = 'MessageNotFound';
                    err.statusCode = 404;
                    throw err;
                }

                let references = []
                    .concat(referencedMessage.messageId || [])
                    .concat(referencedMessage.inReplyTo || [])
                    .concat((referencedMessage.headers && referencedMessage.headers.references) || [])
                    .flatMap(line => line.split(/\s+/))
                    .map(ref => ref.trim())
                    .filter(ref => ref)
                    .map(ref => {
                        if (!/^</.test(ref)) {
                            ref = '<' + ref;
                        }
                        if (!/>$/.test(ref)) {
                            ref = ref + '>';
                        }
                        return ref;
                    });

                references = Array.from(new Set(references));
                if (references.length) {
                    if (!data.headers) {
                        data.headers = {};
                    }
                    data.headers.references = references.join(' ');
                }

                if (['reply', 'reply-all'].includes(data.reference.action) && referencedMessage.messageId) {
                    data.headers['in-reply-to'] = referencedMessage.messageId;
                }

                let referenceFlags = ['\\Answered'].concat(data.reference.action === 'forward' ? '$Forwarded' : []);
                if (!referencedMessage.flags || !referencedMessage.flags.length || !referenceFlags.some(flag => referencedMessage.flags.includes(flag))) {
                    data.reference.update = true;
                }

                if (referencedMessage.threadId) {
                    data.reference.threadId = referencedMessage.threadId;
                }

                if (!data.subject && referencedMessage.subject) {
                    let subject = referencedMessage.subject;
                    let prefix;
                    switch (data.reference.action) {
                        case 'reply':
                        case 'reply-all':
                            if (!/^Re:/i.test(subject)) {
                                prefix = 'Re';
                            }
                            break;
                        case 'forward':
                            if (!/^Fwd:/i.test(subject)) {
                                prefix = 'Fwd';
                            }
                            break;
                    }
                    data.subject = `${prefix ? prefix + ': ' : ''}${subject}`;
                }

                let cidAttachments = [];

                if (data.reference.inline) {
                    let inlineMessageData = {
                        text: referencedMessage.text && referencedMessage.text.plain,
                        html: referencedMessage.text && referencedMessage.text.html
                    };

                    for (let key of ['from', 'to', 'cc', 'bcc', 'date', 'subject']) {
                        inlineMessageData[key] = referencedMessage[key];
                    }

                    if (inlineMessageData.html) {
                        if (referencedMessage.attachments) {
                            // find all attachments that are referenced in the HTML
                            for (let attachment of referencedMessage.attachments) {
                                if (attachment.contentId && inlineMessageData.html.indexOf(`cid:${attachment.contentId.replace(/^<|>$/g, '')}`) >= 0) {
                                    cidAttachments.push(attachment);
                                }
                            }
                        }

                        try {
                            let html = data.html;
                            if (!(html || '').toString().trim() && data.text) {
                                html = textToHtml(data.text); // convert text to html
                            }

                            data.html = inlineHtml(data.reference.action, html, inlineMessageData, inlineOptions);
                        } catch (err) {
                            this.logger.error({ msg: 'Failed to generate inline HTML content', err });
                        }
                    }

                    if (data.text) {
                        try {
                            data.text = inlineText(data.reference.action, data.text, inlineMessageData, inlineOptions);
                        } catch (err) {
                            this.logger.error({ msg: 'Failed to generate inline text content', err });
                        }
                    }
                }

                if (!data.to && data.reference.action === 'reply') {
                    data.to =
                        referencedMessage.replyTo && referencedMessage.replyTo.length
                            ? referencedMessage.replyTo
                            : referencedMessage.from
                            ? referencedMessage.from
                            : false;
                }

                if (data.reference.action === 'reply-all') {
                    let envelope = {
                        to: [].concat(
                            referencedMessage.replyTo && referencedMessage.replyTo.length
                                ? referencedMessage.replyTo
                                : referencedMessage.from
                                ? referencedMessage.from
                                : []
                        ),
                        cc: [],
                        bcc: []
                    };

                    let addressesSeen = new Set([].concat(data.from?.address || []).concat(envelope.to.map(addr => addr.address)));
                    for (let rcpt of ['to', 'cc', 'bcc']) {
                        for (let addr of referencedMessage[rcpt] || []) {
                            if (addressesSeen.has(addr.address)) {
                                continue;
                            }
                            addressesSeen.add(addr.address);
                            envelope[rcpt].push(addr);
                        }

                        for (let addr of data[rcpt] || []) {
                            if (addressesSeen.has(addr.address)) {
                                continue;
                            }
                            addressesSeen.add(addr.address);
                            envelope[rcpt].push(addr);
                        }

                        if (envelope[rcpt].length) {
                            data[rcpt] = envelope[rcpt];
                        }
                    }
                }

                let attachmentsToDownload;

                if (
                    data.reference.action === 'forward' &&
                    data.reference.forwardAttachments &&
                    referencedMessage.attachments &&
                    referencedMessage.attachments.length
                ) {
                    // download all
                    attachmentsToDownload = referencedMessage.attachments;
                } else if (cidAttachments.length) {
                    // download referenced attachments
                    attachmentsToDownload = cidAttachments;
                }

                if (attachmentsToDownload && attachmentsToDownload.length) {
                    this.checkIMAPConnection(connectionOptions);

                    this.logger.info({
                        msg: 'Fetching attachments from the referenced email',
                        attachments: attachmentsToDownload.map(a => ({ id: a.id, hasContent: !!a.content }))
                    });

                    // fetch and add attachments to the message
                    if (!data.attachments) {
                        data.attachments = [];
                    }
                    for (let attachment of attachmentsToDownload) {
                        let content;
                        if (attachment.content) {
                            // use local cache
                            content = Buffer.from(attachment.content, 'base64');
                            this.logger.trace({ msg: 'Using cached email content', attachment: attachment.id, size: content.length });
                        } else {
                            // fetch from IMAP
                            content = await this.getAttachmentContent(
                                attachment.id,
                                {
                                    chunkSize: Math.max(DOWNLOAD_CHUNK_SIZE, 2 * 1024 * 1024),
                                    contentOnly: true
                                },
                                connectionOptions
                            );
                        }
                        if (!content) {
                            // skip missing?
                            continue;
                        }
                        data.attachments.push({
                            filename: attachment.filename,
                            content,
                            contentType: attachment.contentType,
                            contentDisposition: attachment.inline ? 'inline' : 'attachment',
                            cid: attachment.contentId || null
                        });
                    }
                }
            }
        }

        // resolve referenced attachments
        for (let attachment of data.attachments || []) {
            if (attachment.reference && !attachment.content) {
                this.checkIMAPConnection(connectionOptions);

                let content = await this.getAttachmentContent(
                    attachment.reference,
                    {
                        chunkSize: Math.max(DOWNLOAD_CHUNK_SIZE, 2 * 1024 * 1024),
                        contentOnly: true
                    },
                    connectionOptions
                );

                if (!content) {
                    let error = new Error('Referenced attachment was not found');
                    error.code = 'ReferenceNotFound';
                    error.statusCode = 404;
                    throw error;
                }

                attachment.content = content;
            }
        }

        let { raw, hasBcc, envelope, subject, messageId, sendAt, deliveryAttempts, trackClicks, trackOpens, trackingEnabled, gateway } = await getRawEmail(
            data,
            licenseInfo
        );

        if (data.dryRun) {
            let response = {
                response: 'Dry run',
                messageId
            };

            if (data.reference && data.reference.message) {
                response.reference = {
                    message: data.reference.message,
                    documentStore: documentStoreUsed,
                    success: referencedMessage ? true : false
                };

                if (!referencedMessage) {
                    response.reference.error = 'Referenced message was not found';
                }
            }

            response.preview = raw.toString('base64');

            return response;
        }

        let gatewayData;
        if (gateway) {
            let gatewayObject = new Gateway({ gateway, redis: this.redis, secret: this.secret });
            try {
                gatewayData = await gatewayObject.loadGatewayData();
            } catch (err) {
                this.logger.info({ msg: 'Failed to load gateway data', envelope, messageId, gateway, err });
            }
        }

        if (!accountData.smtp && !accountData.oauth2 && !gatewayData) {
            // can not make connection
            let err = new Error('SMTP configuration not found');
            err.code = 'SMTPUnavailable';
            err.statusCode = 404;
            throw err;
        }

        if (typeof trackingEnabled !== 'boolean') {
            trackingEnabled = (await settings.get('trackSentMessages')) || false;
        }

        if (typeof trackClicks !== 'boolean') {
            trackClicks = await settings.get('trackClicks');
            if (typeof trackClicks !== 'boolean') {
                trackClicks = trackingEnabled;
            }
        }

        if (typeof trackOpens !== 'boolean') {
            trackOpens = await settings.get('trackOpens');
            if (typeof trackOpens !== 'boolean') {
                trackOpens = trackingEnabled;
            }
        }

        if (raw && (trackClicks || trackOpens) && baseUrl) {
            // add open and click tracking
            raw = await addTrackers(raw, accountData.account, messageId, baseUrl, {
                trackClicks,
                trackOpens
            });
        }

        let now = new Date();

        //queue for later

        // Use timestamp in the ID to make sure that jobs are ordered by send time
        let timeBuf = Buffer.allocUnsafe(8);

        timeBuf.writeBigInt64BE(BigInt((sendAt && sendAt.getTime()) || Date.now()), 0);

        let queueId = Buffer.concat([timeBuf.subarray(2), crypto.randomBytes(4)])
            .toString('hex')
            .substring(1); // first char is always 0

        let msgEntry = msgpack.encode({
            queueId,
            gateway: gatewayData && gatewayData.gateway,
            hasBcc,
            envelope,
            messageId,
            reference: data.reference || {},
            sendAt: (sendAt && sendAt.getTime()) || false,
            created: now.getTime(),
            copy: data.copy,
            sentMailPath: data.sentMailPath,
            feedbackKey: data.feedbackKey || null,
            dsn: data.dsn || null,
            proxy: data.proxy || null,
            localAddress: data.localAddress || null,
            raw
        });

        await this.redis.hsetBuffer(`${REDIS_PREFIX}iaq:${this.account}`, queueId, msgEntry);

        let queueKeep = (await settings.get('queueKeep')) || true;

        let defaultDeliveryAttempts = await settings.get('deliveryAttempts');
        if (typeof defaultDeliveryAttempts !== 'number') {
            defaultDeliveryAttempts = DEFAULT_DELIVERY_ATTEMPTS;
        }

        let jobData = Object.assign({}, meta || {}, {
            account: this.account,
            queueId,
            gateway: (gatewayData && gatewayData.gateway) || null,
            messageId,
            envelope,
            subject,
            proxy: data.proxy,
            localAddress: data.localAddress,
            created: now.getTime()
        });

        let queueName = 'queued';
        let jobOpts = {
            jobId: queueId,
            removeOnComplete: queueKeep,
            removeOnFail: queueKeep,
            attempts: typeof deliveryAttempts === 'number' ? deliveryAttempts : defaultDeliveryAttempts,
            backoff: {
                type: 'exponential',
                delay: 5000
            }
        };

        if (sendAt && sendAt > now) {
            queueName = 'delayed';
            jobOpts.delay = sendAt.getTime() - now.getTime();
        }

        let job = await this.submitQueue.add(queueName, jobData, jobOpts);

        try {
            await job.updateProgress({
                status: 'queued'
            });
        } catch (err) {
            // ignore
        }

        this.logger.info({ msg: 'Message queued for delivery', envelope, messageId, sendAt: (sendAt || now).toISOString(), queueId, job: job.id });

        let response = {
            response: 'Queued for delivery',
            messageId,
            sendAt: (sendAt || now).toISOString(),
            queueId
        };

        if (data.reference && data.reference.message) {
            response.reference = {
                message: data.reference.message,
                documentStore: documentStoreUsed,
                success: referencedMessage ? true : false
            };

            if (!referencedMessage) {
                response.reference.error = 'Referenced message was not found';
            }
        }

        return response;
    }

    render(template, data, key, renderFormat) {
        let format;

        switch (key) {
            case 'subject':
            case 'text': {
                format = 'plain';
                break;
            }

            case 'html': {
                format = renderFormat ? renderFormat : 'html';
                break;
            }

            case 'previewText':
            default: {
                format = 'html';
                break;
            }
        }

        try {
            const compiledTemplate = getTemplate({
                format,
                template
            });

            return compiledTemplate(data);
        } catch (err) {
            logger.error({ msg: `Failed rendering ${key} template`, err });
            let error = new Error(`Failed rendering ${key} template`);
            error.code = err.code || 'SubmitFail';
            error.statusCode = 422;
            throw error;
        }
    }

    isAutoreply(messageData) {
        if (/^(auto:|Out of Office|OOF:|OOO:)/i.test(messageData.subject) && messageData.inReplyTo) {
            return true;
        }

        if (!messageData.headers) {
            return false;
        }

        if (messageData.headers.precedence && messageData.headers.precedence.some(e => /auto[_-]?reply/.test(e))) {
            return true;
        }

        if (messageData.headers['auto-submitted'] && messageData.headers['auto-submitted'].some(e => /auto[_-]?replied/.test(e))) {
            return true;
        }

        for (let headerKey of ['x-autoresponder', 'x-autorespond', 'x-autoreply']) {
            if (messageData.headers[headerKey] && messageData.headers[headerKey].length) {
                return true;
            }
        }

        return false;
    }

    async getMessageFetchOptions() {
        let messageFetchOptions = {};

        let notifyText = await settings.get('notifyText');
        if (notifyText) {
            messageFetchOptions.textType = '*';
            let notifyTextSize = await settings.get('notifyTextSize');

            if (notifyTextSize) {
                messageFetchOptions.maxBytes = notifyTextSize;
            }
        }

        let notifyHeaders = (await settings.get('notifyHeaders')) || [];
        if (notifyHeaders.length) {
            messageFetchOptions.headers = notifyHeaders.includes('*') ? true : notifyHeaders.length ? notifyHeaders : false;
        }

        // also request autoresponse headers
        if (messageFetchOptions.headers !== true) {
            let fetchHeaders = new Set(messageFetchOptions.headers || []);

            fetchHeaders.add('x-autoreply');
            fetchHeaders.add('x-autorespond');
            fetchHeaders.add('auto-submitted');
            fetchHeaders.add('precedence');

            fetchHeaders.add('in-reply-to');
            fetchHeaders.add('references');

            fetchHeaders.add('content-type');

            messageFetchOptions.fetchHeaders = Array.from(fetchHeaders);
        }

        return messageFetchOptions;
    }

    async processNew(messageData, options) {
        let requestedHeaders = options.headers;

        let bounceNotifyInfo;
        let complaintNotifyInfo;
        let content;

        if (this.mightBeAComplaint(messageData)) {
            try {
                for (let attachment of messageData.attachments) {
                    if (!['message/feedback-report', 'message/rfc822-headers', 'message/rfc822'].includes(attachment.contentType)) {
                        continue;
                    }

                    Object.defineProperty(attachment, 'content', {
                        value: (await this.getAttachment(attachment.id))?.data?.toString(),
                        enumerable: false
                    });
                }

                const report = await arfDetect(messageData);

                if (report && report.arf && report.arf['original-rcpt-to'] && report.arf['original-rcpt-to'].length) {
                    // can send report
                    let complaint = {};
                    for (let subKey of ['arf', 'headers']) {
                        for (let key of Object.keys(report[subKey])) {
                            if (!complaint[subKey]) {
                                complaint[subKey] = {};
                            }
                            complaint[subKey][key.replace(/-(.)/g, (o, c) => c.toUpperCase())] = report[subKey][key];
                        }
                    }

                    complaintNotifyInfo = Object.assign({ complaintMessage: messageData.id }, complaint);

                    messageData.isComplaint = true;

                    if (complaint.headers && complaint.headers.messageId) {
                        messageData.relatedMessageId = complaint.headers.messageId;
                    }
                }
            } catch (err) {
                this.logger.error({
                    msg: 'Failed to process ARF',
                    id: messageData.id,
                    uid: messageData.uid,
                    messageId: messageData.messageId,
                    err
                });
            }
        }

        if (this.mightBeDSNResponse(messageData)) {
            try {
                let raw = await this.getRawMessage(messageData.id);

                let parsed = await simpleParser(raw, { keepDeliveryStatus: true });
                if (parsed) {
                    content = { parsed };

                    let deliveryStatus = parsed.attachments.find(attachment => attachment.contentType === 'message/delivery-status');
                    if (deliveryStatus) {
                        let deliveryEntries = libmime.decodeHeaders((deliveryStatus.content || '').toString().trim());
                        let structured = {};
                        for (let key of Object.keys(deliveryEntries)) {
                            if (!key) {
                                continue;
                            }
                            let displayKey = key.replace(/-(.)/g, (m, c) => c.toUpperCase());
                            let value = deliveryEntries[key].at(-1);
                            if (typeof value === 'string') {
                                let m = value.match(/^([^\s;]+);/);
                                if (m) {
                                    value = {
                                        label: m[1],
                                        value: value.substring(m[0].length).trim()
                                    };
                                } else {
                                    switch (key) {
                                        case 'arrival-date': {
                                            value.trim();
                                            let date = new Date(value);
                                            if (date.toString() !== 'Invalid Date') {
                                                value = date.toISOString();
                                            }
                                            structured[displayKey] = value;
                                            break;
                                        }
                                        default:
                                            structured[displayKey] = value.trim();
                                    }
                                }
                            } else {
                                // ???
                                structured[displayKey] = value;
                            }
                        }

                        if (/^delivered|^delayed/i.test(structured.action)) {
                            this.logger.debug({
                                msg: 'Detected delivery report',
                                id: messageData.id,
                                uid: messageData.uid,
                                messageId: messageData.messageId,
                                report: structured
                            });

                            messageData.deliveryReport = structured;
                        }
                    }
                }
            } catch (err) {
                this.logger.error({
                    msg: 'Failed to process DSN',
                    id: messageData.id,
                    uid: messageData.uid,
                    messageId: messageData.messageId,
                    err
                });
            }
        }

        // Check if this could be a bounce
        if (this.mightBeABounce(messageData)) {
            // parse for bounce
            try {
                if (!content) {
                    content = await this.getRawMessage(messageData.id);
                }

                if (content) {
                    let bounce = await bounceDetect(content);

                    let stored = 0;
                    if (bounce.action && bounce.recipient && bounce.messageId) {
                        bounceNotifyInfo = Object.assign({ bounceMessage: messageData.id }, bounce);

                        messageData.isBounce = true;
                        messageData.relatedMessageId = bounce.messageId;
                    }

                    this.logger.debug({
                        msg: 'Detected bounce message',
                        id: messageData.id,
                        uid: messageData.uid,
                        messageId: messageData.messageId,
                        bounce,
                        stored
                    });
                }
            } catch (err) {
                this.logger.error({
                    msg: 'Failed to process potential bounce',
                    id: messageData.id,
                    uid: messageData.uid,
                    messageId: messageData.messageId,
                    err
                });
            }
        }

        let notifyAttachments = await settings.get('notifyAttachments');
        let notifyAttachmentSize = await settings.get('notifyAttachmentSize');
        if (notifyAttachments && messageData.attachments?.length) {
            for (let attachment of messageData.attachments || []) {
                if (notifyAttachmentSize && attachment.encodedSize && attachment.encodedSize > notifyAttachmentSize) {
                    // skip large attachments
                    continue;
                }
                if (!attachment.content) {
                    try {
                        attachment.content = (await this.getAttachment(attachment.id))?.data?.toString('base64');
                    } catch (err) {
                        this.logger.error({ msg: 'Failed to load attachment content', attachment, err });
                    }
                }
            }
        }

        if (messageData.attachments && messageData.attachments.length && messageData.text && messageData.text.html) {
            // fetch inline attachments
            for (let attachment of messageData.attachments) {
                if (attachment.encodedSize && attachment.encodedSize > MAX_INLINE_ATTACHMENT_SIZE) {
                    // skip large attachments
                    continue;
                }

                if (!attachment.content && attachment.contentId && messageData.text.html.indexOf(`cid:${attachment.contentId.replace(/^<|>$/g, '')}`) >= 0) {
                    try {
                        attachment.content = (await this.getAttachment(attachment.id))?.data?.toString('base64');
                    } catch (err) {
                        this.logger.error({ msg: 'Failed to load attachment content', attachment, err });
                    }
                }
            }
        }

        // Fetch and process calendar events if needed
        let notifyCalendarEvents = await settings.get('notifyCalendarEvents');
        if (notifyCalendarEvents && messageData.attachments && messageData.attachments.length) {
            let calendarEventMap = new Map();

            // when iterating the attachment array, process text/calendar before application/ics
            let sortCalendarAttachments = (a, b) => {
                if (a.contentType !== b.contentType) {
                    if (a.contentType === 'text/calendar') {
                        return -1;
                    }
                    if (b.contentType === 'text/calendar') {
                        return 1;
                    }
                }
                return a.contentType.localeCompare(b.contentType);
            };

            for (let attachment of [...messageData.attachments].sort(sortCalendarAttachments)) {
                if (['text/calendar', 'application/ics'].includes(attachment.contentType)) {
                    if (!attachment.content) {
                        try {
                            let calendarBuf = (await this.getAttachment(attachment.id))?.data;
                            attachment.content = calendarBuf.toString('base64');
                        } catch (err) {
                            this.logger.error({ msg: 'Failed to load attachment content', attachment, err });
                        }
                    }
                    if (attachment.content) {
                        let contentBuf = Buffer.from(attachment.content, 'base64');
                        try {
                            const jcalData = ical.parse(contentBuf.toString());

                            const comp = new ical.Component(jcalData);
                            if (!comp) {
                                continue;
                            }

                            const vevent = comp.getFirstSubcomponent('vevent');
                            if (!vevent) {
                                continue;
                            }

                            let eventMethodProp = comp.getFirstProperty('method');
                            let eventMethodValue = eventMethodProp ? eventMethodProp.getFirstValue() : null;

                            const event = new ical.Event(vevent);

                            if (!event || !event.uid) {
                                continue;
                            }

                            if (calendarEventMap.has(event.uid)) {
                                if (attachment.filename) {
                                    let existingEntry = calendarEventMap.get(event.uid);
                                    if (!existingEntry.filename) {
                                        // inject filename
                                        existingEntry.filename = attachment.filename;
                                    }
                                }
                                continue;
                            }

                            let timezone;
                            const vtz = comp.getFirstSubcomponent('vtimezone');
                            if (vtz) {
                                const tz = new ical.Timezone(vtz);
                                timezone = tz && tz.tzid;
                            }

                            let startDate = event.startDate && event.startDate.toJSDate();
                            let endDate = event.endDate && event.endDate.toJSDate();

                            calendarEventMap.set(
                                event.uid,
                                filterEmptyObjectValues({
                                    eventId: event.uid,
                                    attachment: attachment.id,
                                    method: attachment.method || eventMethodValue || null,

                                    summary: event.summary || null,
                                    description: event.description || null,
                                    timezone: timezone || null,
                                    startDate: startDate ? startDate.toISOString() : null,
                                    endDate: endDate ? endDate.toISOString() : null,
                                    organizer: event.organizer && typeof event.organizer === 'string' ? event.organizer : null,

                                    filename: attachment.filename,
                                    contentType: attachment.contentType,
                                    encoding: 'base64',
                                    content: attachment.content
                                })
                            );
                        } catch (err) {
                            this.logger.error({
                                msg: 'Failed to parse calendar event',
                                attachment: Object.assign({}, attachment, { content: `${contentBuf.length} bytes` }),
                                err
                            });
                        }
                    }
                }
            }

            if (calendarEventMap && calendarEventMap.size) {
                messageData.calendarEvents = Array.from(calendarEventMap.values()).map(calendarEvent => {
                    if (!calendarEvent.filename) {
                        switch (calendarEvent.method && calendarEvent.method.toUpperCase()) {
                            case 'CANCEL':
                            case 'REQUEST':
                                calendarEvent.filename = 'invite.ics';
                                break;
                            default:
                                calendarEvent.filename = 'event.ics';
                                break;
                        }
                    }
                    return calendarEvent;
                });
            }
        }

        if (messageData.messageSpecialUse === '\\Inbox') {
            let llmMessageData = Object.assign({ account: this.account }, messageData);

            let canUseLLM = await llmPreProcess.run(llmMessageData);

            if (canUseLLM && (messageData.text.plain || messageData.text.html)) {
                if (canUseLLM.generateEmailSummary) {
                    try {
                        messageData.summary = await this.call({
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
                                account: this.account
                            },
                            timeout: 2 * 60 * 1000
                        });

                        if (messageData.summary) {
                            for (let key of Object.keys(messageData.summary)) {
                                // remove meta keys from output
                                if (key.charAt(0) === '_' || messageData.summary[key] === '') {
                                    delete messageData.summary[key];
                                }
                                if (key === 'riskAssessment') {
                                    messageData.riskAssessment = messageData.summary.riskAssessment;
                                    delete messageData.summary.riskAssessment;
                                }
                            }

                            this.logger.trace({ msg: 'Fetched summary from OpenAI', summary: messageData.summary });
                        }

                        await this.redis.del(`${REDIS_PREFIX}:openai:error`);
                    } catch (err) {
                        await this.redis.set(
                            `${REDIS_PREFIX}:openai:error`,
                            JSON.stringify({
                                message: err.message,
                                code: err.code,
                                statusCode: err.statusCode,
                                created: Date.now()
                            })
                        );
                        this.logger.error({ msg: 'Failed to fetch summary from OpenAI', err });
                    }
                }

                if (canUseLLM.generateEmbeddings) {
                    try {
                        messageData.embeddings = await this.call({
                            cmd: 'generateEmbeddings',
                            data: {
                                message: {
                                    headers: Object.keys(messageData.headers || {}).map(key => ({ key, value: [].concat(messageData.headers[key] || []) })),
                                    attachments: messageData.attachments,
                                    from: messageData.from,
                                    subject: messageData.subject,
                                    text: messageData.text.plain,
                                    html: messageData.text.html
                                },
                                account: this.account
                            },
                            timeout: 2 * 60 * 1000
                        });
                    } catch (err) {
                        await this.redis.set(
                            `${REDIS_PREFIX}:openai:error`,
                            JSON.stringify({
                                message: err.message,
                                code: err.code,
                                statusCode: err.statusCode,
                                time: Date.now()
                            })
                        );
                        this.logger.error({ msg: 'Failed to fetch embeddings OpenAI', err });
                    }
                }
            }
        }

        // Convert message HTML to web safe HTML
        let notifyWebSafeHtml = await settings.get('notifyWebSafeHtml');
        if (notifyWebSafeHtml && messageData.text && (messageData.text.html || messageData.text.plain)) {
            // convert to web safe

            if (messageData.text.html && messageData.attachments) {
                let attachmentList = new Map();

                for (let attachment of messageData.attachments) {
                    let contentId = attachment.contentId && attachment.contentId.replace(/^<|>$/g, '');
                    if (contentId && messageData.text.html.indexOf(contentId) >= 0) {
                        if (attachment.content) {
                            // already downloaded in a previous step
                            continue;
                        } else {
                            attachment.content = (await this.getAttachment(attachment.id))?.data?.toString('base64');
                        }

                        attachmentList.set(contentId, {
                            attachment,
                            content: attachment.content || null
                        });
                    }
                }

                if (attachmentList.size) {
                    messageData.text.html = messageData.text.html.replace(/\bcid:([^"'\s>]+)/g, (fullMatch, cidMatch) => {
                        if (attachmentList.has(cidMatch)) {
                            let { attachment, content } = attachmentList.get(cidMatch);
                            if (content) {
                                return `data:${attachment.contentType || 'application/octet-stream'};base64,${content}`;
                            }
                        }
                        return fullMatch;
                    });
                }
            }

            messageData.text._generatedHtml = mimeHtml({
                html: messageData.text.html,
                text: messageData.text.plain
            });

            messageData.text.webSafe = true;
        }

        // we might have fetched more headers than was asked for, so filter out all the unneeded ones
        if (options.headers && Array.isArray(requestedHeaders)) {
            let filteredHeaders = {};
            for (let key of Object.keys(messageData.headers || {})) {
                if (requestedHeaders.includes(key)) {
                    filteredHeaders[key] = messageData.headers[key];
                }
            }
            messageData.headers = filteredHeaders;
        } else if (options.headers && requestedHeaders === false) {
            delete messageData.headers;
        }

        let path = messageData.path || this.path;
        let specialUse = messageData.path ? messageData.messageSpecialUse : this.listingEntry.specialUse;

        if (messageData.path) {
            // unset path from the message level
            messageData.path = undefined;
        }

        await this.notify(
            {
                path,
                specialUse
            },
            MESSAGE_NEW_NOTIFY,
            messageData
        );

        if (bounceNotifyInfo) {
            // send bounce notification _after_ bounce email notification
            await this.notify(false, EMAIL_BOUNCE_NOTIFY, bounceNotifyInfo);
        }

        if (complaintNotifyInfo) {
            // send complaint notification _after_ complaint email notification
            await this.notify(false, EMAIL_COMPLAINT_NOTIFY, complaintNotifyInfo);
        }
    }

    mightBeAComplaint(messageData) {
        if (messageData.messageSpecialUse !== '\\Inbox') {
            return false;
        }

        let hasEmbeddedMessage = false;
        for (let attachment of messageData.attachments || []) {
            if (attachment.contentType === 'message/feedback-report') {
                return true;
            }

            if (['message/rfc822', 'message/rfc822-headers'].includes(attachment.contentType)) {
                hasEmbeddedMessage = true;
            }
        }

        let fromAddress = (messageData.from && messageData.from.address) || '';

        if (hasEmbeddedMessage && fromAddress === 'staff@hotmail.com' && /complaint/i.test(messageData.subject)) {
            return true;
        }

        return false;
    }

    mightBeDSNResponse(messageData) {
        if (messageData.messageSpecialUse !== '\\Inbox') {
            return false;
        }

        if (messageData.headers && messageData.headers['content-type'] && messageData.headers['content-type'].length) {
            let parsedContentType = libmime.parseHeaderValue(messageData.headers['content-type'].at(-1));
            if (
                parsedContentType &&
                parsedContentType.value &&
                parsedContentType.value.toLowerCase().trim() === 'multipart/report' &&
                parsedContentType.params['report-type'] === 'delivery-status'
            ) {
                return true;
            }
        }

        return false;
    }

    mightBeABounce(messageData) {
        if (messageData.messageSpecialUse !== '\\Inbox') {
            return false;
        }

        if (messageData.deliveryReport) {
            // already processed
            return false;
        }

        let name = (messageData.from && messageData.from.name) || '';
        let address = (messageData.from && messageData.from.address) || '';

        if (/Mail Delivery System|Mail Delivery Subsystem|Internet Mail Delivery/i.test(name)) {
            return true;
        }

        if (/mailer-daemon@|postmaster@/i.test(address)) {
            return true;
        }

        let hasDeliveryStatus = false;
        for (let attachment of messageData.attachments || []) {
            if (attachment.contentType === 'message/delivery-status') {
                hasDeliveryStatus = true;
            }
        }

        if (hasDeliveryStatus && /Undeliverable/i.test(messageData.subject)) {
            return true;
        }

        return false;
    }

    async submitMessage(data) {
        let accountData = await this.accountObject.loadAccountData();
        if (!accountData.smtp && !accountData.oauth2 && !data.gateway) {
            // can not make connection
            let err = new Error('SMTP configuration not found');
            err.code = 'SMTPUnavailable';
            err.statusCode = 404;
            throw err;
        }

        let gatewayData;
        let gatewayObject;
        if (data.gateway) {
            gatewayObject = new Gateway({ gateway: data.gateway, redis: this.redis, secret: this.secret });
            try {
                gatewayData = await gatewayObject.loadGatewayData();
            } catch (err) {
                this.logger.info({ msg: 'Failed to load gateway data', messageId: data.messageId, gateway: data.gateway, err });
            }
        }

        let smtpConnectionConfig;

        if (gatewayData) {
            smtpConnectionConfig = {
                host: gatewayData.host,
                port: gatewayData.port,
                secure: gatewayData.secure
            };
            if (gatewayData.user || gatewayData.pass) {
                smtpConnectionConfig.auth = {
                    user: gatewayData.user || '',
                    pass: gatewayData.pass || ''
                };
            }
        } else if (accountData.oauth2 && accountData.oauth2.auth) {
            // load OAuth2 tokens
            const { oauth2User, accessToken, oauth2App } = await this.loadOAuth2AccountCredentials(accountData, this, 'smtp');
            const providerData = oauth2ProviderData(oauth2App.provider);

            smtpConnectionConfig = Object.assign(
                {
                    auth: {
                        user: oauth2User,
                        accessToken
                    },
                    resyncDelay: 900
                },
                providerData.smtp || {}
            );
        } else {
            // deep copy of imap settings
            smtpConnectionConfig = JSON.parse(JSON.stringify(accountData.smtp));
        }

        let { raw, hasBcc, envelope, messageId, queueId, reference, job: jobData } = data;

        let smtpAuth = smtpConnectionConfig.auth;
        // If authentication server is set then it overrides authentication data
        if (smtpConnectionConfig.useAuthServer) {
            try {
                smtpAuth = await resolveCredentials(this.account, 'smtp');
            } catch (err) {
                err.authenticationFailed = true;
                this.logger.error({
                    account: this.account,
                    err
                });
                throw err;
            }
        }

        let { localAddress: address, name, addressSelector: selector } = await getLocalAddress(this.redis, 'smtp', this.account, data.localAddress);
        this.logger.info({
            msg: 'Selected local address',
            account: this.account,
            proto: 'SMTP',
            address,
            name,
            selector,
            requestedLocalAddress: data.localAddress
        });

        let smtpLogger = {};
        let smtpSettings = Object.assign(
            {
                name,
                localAddress: address,
                transactionLog: true,
                logger: smtpLogger
            },
            smtpConnectionConfig
        );

        if (smtpAuth) {
            smtpSettings.auth = {
                user: smtpAuth.user
            };

            if (smtpAuth.accessToken) {
                smtpSettings.auth.type = 'OAuth2';
                smtpSettings.auth.accessToken = smtpAuth.accessToken;
            } else {
                smtpSettings.auth.pass = smtpAuth.pass;
            }
        }

        if (!smtpSettings.tls) {
            smtpSettings.tls = {};
        }
        for (let key of Object.keys(TLS_DEFAULTS)) {
            if (!(key in smtpSettings.tls)) {
                smtpSettings.tls[key] = TLS_DEFAULTS[key];
            }
        }

        for (let level of ['trace', 'debug', 'info', 'warn', 'error', 'fatal']) {
            smtpLogger[level] = (data, message, ...args) => {
                if (args && args.length) {
                    message = util.format(message, ...args);
                }
                data.msg = message;
                data.sub = 'nodemailer';
                if (typeof this.logger[level] === 'function') {
                    this.logger[level](data);
                } else {
                    this.logger.debug(data);
                }
            };
        }

        // set up proxy if needed
        if (data.proxy) {
            smtpSettings.proxy = data.proxy;
        } else if (accountData.proxy) {
            smtpSettings.proxy = accountData.proxy;
        } else {
            let proxyUrl = await settings.get('proxyUrl');
            let proxyEnabled = await settings.get('proxyEnabled');
            if (proxyEnabled && proxyUrl && !smtpSettings.proxy) {
                smtpSettings.proxy = proxyUrl;
            }
        }

        if (accountData.smtpEhloName) {
            smtpSettings.name = accountData.smtpEhloName;
        }

        const submitJobEntry = await this.submitQueue.getJob(jobData.id);
        if (!submitJobEntry) {
            // already failed?
            this.logger.error({
                msg: 'Submit job was not found',
                job: jobData.id
            });
            return false;
        }

        const ignoreMailCertErrors = await settings.get('ignoreMailCertErrors');
        if (ignoreMailCertErrors && smtpSettings?.tls?.rejectUnauthorized !== false) {
            smtpSettings.tls = smtpSettings.tls || {};
            smtpSettings.tls.rejectUnauthorized = false;
        }

        const networkRouting = smtpSettings.localAddress || smtpSettings.proxy ? {} : null;

        if (networkRouting && smtpSettings.localAddress) {
            networkRouting.localAddress = smtpSettings.localAddress;
        }

        if (networkRouting && smtpSettings.proxy) {
            networkRouting.proxy = smtpSettings.proxy;
        }

        if (networkRouting && smtpSettings.name) {
            networkRouting.name = smtpSettings.name;
        }

        if (networkRouting && data.localAddress && data.localAddress !== networkRouting.localAddress) {
            networkRouting.requestedLocalAddress = data.localAddress;
        }

        const transporter = nodemailer.createTransport(smtpSettings);
        transporter.set('proxy_socks_module', socks);
        try {
            try {
                // try to update
                await submitJobEntry.updateProgress({
                    status: 'smtp-starting'
                });
            } catch (err) {
                // ignore
            }

            const info = await transporter.sendMail({
                envelope,
                messageId,
                // make sure that Bcc line is removed from the version sent to SMTP
                raw: !hasBcc ? raw : await removeBcc(raw),
                dsn: data.dsn || null
            });

            if (info.ehlo) {
                await this.redis.hSetExists(this.getAccountKey(), 'smtpServerEhlo', JSON.stringify(info.ehlo));
            }

            // special rules for MTA servers

            let originalMessageId;

            // Hotmail
            let hotmailMessageIdMatch = (info.response || '').toString().match(/^250 2.0.0 OK (<[^>]+\.prod\.outlook\.com>)/);
            if (hotmailMessageIdMatch && hotmailMessageIdMatch[1] !== info.messageId) {
                // MessageId was overridden
                originalMessageId = info.messageId;
                info.messageId = hotmailMessageIdMatch[1];
            }

            // done

            try {
                // try to update
                await submitJobEntry.updateProgress({
                    status: 'smtp-completed',

                    response: info.response,
                    messageId: info.messageId,
                    originalMessageId
                });
            } catch (err) {
                // ignore
            }

            await this.notify(false, EMAIL_SENT_NOTIFY, {
                messageId: info.messageId,
                originalMessageId,
                response: info.response,
                queueId,
                envelope,
                networkRouting
            });

            // clean up possible cached SMTP error
            try {
                await this.redis.hset(
                    this.getAccountKey(),
                    'smtpStatus',
                    JSON.stringify({
                        created: Date.now(),
                        status: 'ok',
                        response: info.response
                    })
                );
            } catch (err) {
                // ignore?
            }

            // The default is to copy message to Sent Mail folder
            let shouldCopy = !Object.prototype.hasOwnProperty.call(accountData, 'copy');

            // Account specific setting
            if (typeof accountData.copy === 'boolean') {
                shouldCopy = accountData.copy;
            }

            // Suppress uploads for Gmail and Outlook
            // Unfortunately, previous default schema for all added accounts was copy=true, so can't prefer account specific setting here

            // Emails for delegated accounts will be uploaded as the sender is different.
            // SMTP is disabled for shared mailboxes, so we need to send using the main account.
            let skipIfOutlook = this.isOutlook && (!accountData.oauth2 || !accountData.oauth2.auth || !accountData.oauth2.auth.delegatedUser);

            if ((this.isGmail || skipIfOutlook) && !gatewayData) {
                shouldCopy = false;
            }

            // Message specific setting, overrides all other settings
            if (typeof data.copy === 'boolean') {
                shouldCopy = data.copy;
            }

            if ((!accountData.imap && !accountData.oauth2) || (accountData.imap && accountData.imap.disabled)) {
                // IMAP is disabled for this account
                shouldCopy = false;
            }

            let connectionOptions = { allowSecondary: true };

            if (shouldCopy) {
                // NB! IMAP only
                // Upload the message to Sent Mail folder

                try {
                    this.checkIMAPConnection(connectionOptions);

                    let sentMailbox =
                        data.sentMailPath && typeof data.sentMailPath === 'string'
                            ? {
                                  path: data.sentMailPath
                              }
                            : await this.getSpecialUseMailbox('\\Sent');

                    if (sentMailbox) {
                        if (raw.buffer) {
                            // convert from a Uint8Array to a Buffer
                            raw = Buffer.from(raw);
                        }

                        const connectionClient = await this.getImapConnection(connectionOptions, 'submitMessage');

                        await connectionClient.append(sentMailbox.path, raw, ['\\Seen']);

                        if (connectionClient === this.imapClient && this.imapClient.mailbox && !this.imapClient.idling) {
                            // force back to IDLE
                            this.imapClient.idle().catch(err => {
                                this.logger.error({ msg: 'IDLE error', err });
                            });
                        }
                    }
                } catch (err) {
                    this.logger.error({ msg: 'Failed to upload Sent mail', queueId, messageId, err });
                }
            }

            // Add \Answered flag to referenced message if needed
            if (reference && reference.update) {
                try {
                    this.checkIMAPConnection(connectionOptions);
                    await this.updateMessage(
                        reference.message,
                        {
                            flags: {
                                add: ['\\Answered'].concat(reference.action === 'forward' ? '$Forwarded' : [])
                            }
                        },
                        connectionOptions
                    );
                } catch (err) {
                    this.logger.error({ msg: 'Failed to update reference flags', queueId, messageId, reference, err });
                }
            }

            if (data.feedbackKey) {
                await this.redis
                    .multi()
                    .hset(data.feedbackKey, 'success', 'true')
                    .expire(1 * 60 * 60);
            }

            if (gatewayData) {
                try {
                    await gatewayObject.update({
                        lastError: null,
                        lastUse: new Date(),
                        deliveries: { inc: 1 }
                    });
                } catch (err) {
                    this.logger.error({ msg: 'Failed to update gateway', queueId, messageId, reference, gateway: gatewayData.gateway, err });
                }
            }

            return {
                response: info.response,
                messageId: info.messageId
            };
        } catch (err) {
            if (err.responseCode >= 500 && jobData.opts?.attempts <= jobData.attemptsMade) {
                jobData.nextAttempt = false;
            }

            let smtpStatus = false;
            switch (err.code) {
                case 'ESOCKET':
                    if (err.cert && err.reason) {
                        smtpStatus = {
                            description: `Certificate check for ${smtpSettings.host}:${smtpSettings.port} failed. ${err.reason}`
                        };
                    }
                    break;
                case 'EMESSAGE':
                case 'ESTREAM':
                case 'EENVELOPE':
                    // Ignore. Too generic or message related
                    break;
                case 'ETIMEDOUT':
                    // firewall?
                    smtpStatus = {
                        description: `Request timed out. Possibly a firewall issue or a wrong hostname/port (${smtpSettings.host}:${smtpSettings.port}).`
                    };
                    break;
                case 'ETLS':
                    smtpStatus = {
                        description: `EmailEngine failed to set up TLS session with ${smtpSettings.host}:${smtpSettings.port}`
                    };
                    break;
                case 'EDNS':
                    smtpStatus = {
                        description: `EmailEngine failed to resolve DNS record for ${smtpSettings.host}`
                    };
                    break;
                case 'ECONNECTION':
                    smtpStatus = {
                        description: `EmailEngine failed to establish TCP connection against ${smtpSettings.host}`
                    };
                    break;
                case 'EPROTOCOL':
                    smtpStatus = {
                        description: `Unexpected response from ${smtpSettings.host}`
                    };
                    break;
                case 'EAUTH':
                    smtpStatus = {
                        description: `Authentication failed`
                    };
                    break;
            }

            if (smtpStatus) {
                let lastError = Object.assign(
                    {
                        created: Date.now(),
                        status: 'error',
                        response: err.response,
                        responseCode: err.responseCode,
                        code: err.code,
                        command: err.command,
                        networkRouting
                    },
                    smtpStatus
                );

                // store SMTP error for the account
                try {
                    await this.redis.hset(this.getAccountKey(), 'smtpStatus', JSON.stringify(lastError));
                } catch (err) {
                    // ignore?
                }

                if (gatewayData) {
                    try {
                        await gatewayObject.update({
                            lastError,
                            lastUse: new Date()
                        });
                    } catch (err) {
                        // ignore?
                    }
                }
            }

            if (data.feedbackKey && !jobData.nextAttempt) {
                await this.redis
                    .multi()
                    .hset(data.feedbackKey, 'success', 'false')
                    .hset(data.feedbackKey, 'error', ((smtpStatus && smtpStatus.description) || '').toString() || 'Failed to send email')
                    .expire(data.feedbackKey, 1 * 60 * 60)
                    .exec();
            }

            await this.notify(false, EMAIL_DELIVERY_ERROR_NOTIFY, {
                queueId,
                envelope,

                messageId: data.messageId,

                error: err.message,
                errorCode: err.code,

                smtpResponse: err.response,
                smtpResponseCode: err.responseCode,
                smtpCommand: err.command,

                networkRouting,

                job: jobData
            });

            err.code = err.code || 'SubmitFail';
            err.statusCode = Number(err.responseCode) || null;

            err.info = { networkRouting };

            throw err;
        }
    }

    // stub
    async listSignatures() {
        return { signatures: [], signaturesSupported: false };
    }
}

module.exports = { BaseClient };
